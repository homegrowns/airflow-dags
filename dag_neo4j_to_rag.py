"""
dag_neo4j_to_rag.py
실시간 추론 DAG — session_gold parquet (S3) → whitelist → Neo4j enrichment → Groq RAG

- 트리거 방식:
· unified_events_to_gold._s3_write_parquet() 이 생성한 _SUCCESS 마커 감지
· 15초 폴링으로 즉시성 확보
- resolve_session_gold_prefix task 추가
· 최신 _SUCCESS 경로에서 prefix / partition 파싱
· load_session_gold 가 해당 배치만 읽도록 보장
- 입력 소스: silver parquet → session_gold parquet
- inference_datetime 컬럼 추가 (KST)
- 모든 ts → KST 변환

Pipeline:
  [wait_for_session_gold]       ← S3KeySensor: _SUCCESS 감지 (15초 폴링)
          ↓
  [resolve_session_gold_prefix] ← 최신 _SUCCESS → prefix / partition 파싱
          ↓
  [load_session_gold]           ← 해당 배치 parquet만 읽기
          ↓
  [filter_whitelist]            ← whitelist + suspicion_score 필터
          ↓
  [build_subgraphs]             ← Neo4j 1-hop enrichment
          ↓
  [run_rag_analysis]            ← Groq LLM 위협 분석
          ↓
  [save_rag_results]            ← S3 저장 (gold partition 기반 경로)
          ↓
  [report_rag_stats]            ← 통계 로그
"""

from __future__ import annotations

import io
import json
import logging
import re
import time
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import boto3
from airflow import DAG
from airflow.models import Variable
from airflow.operators.python import PythonOperator
from airflow.providers.amazon.aws.sensors.s3 import S3KeySensor

logger = logging.getLogger(__name__)

KST = ZoneInfo("Asia/Seoul")

S3_BUCKET              = "malware-project-bucket"
S3_SESSION_GOLD_PREFIX = "gold/session_gold/"
S3_RAG_PREFIX          = "rag_result"
AWS_REGION             = "ap-northeast-2"

NEO4J_BATCH_SIZE   = 50
GROQ_RPM_SLEEP     = 2.0
MAX_SESSIONS       = 200
GROQ_MODEL_DEFAULT = "llama-3.3-70b-versatile"


# ══════════════════════════════════════════════════════════════════════════════
# 공통 헬퍼
# ══════════════════════════════════════════════════════════════════════════════

def _s3_client():
    return boto3.client("s3", region_name=AWS_REGION)


def _neo4j_driver():
    from neo4j import GraphDatabase
    uri  = Variable.get("NEO4J_URI")
    user = Variable.get("NEO4J_USER")
    pw   = Variable.get("NEO4J_PASSWORD")
    return GraphDatabase.driver(uri, auth=(user, pw))


def _groq_client():
    from groq import Groq
    return Groq(api_key=Variable.get("GROQ_API_KEY"), max_retries=2, timeout=30.0)


def _groq_model() -> str:
    try:
        return Variable.get("GROQ_MODEL")
    except Exception:
        return GROQ_MODEL_DEFAULT


def _make_session_id(community_id: str | None, idx: int) -> str:
    if community_id:
        return f"s_{hashlib.sha1(community_id.encode()).hexdigest()[:8]}"
    return f"s_orphan_{idx:04d}"


def _now_kst_iso() -> str:
    return datetime.now(tz=KST).isoformat()


def _ms_to_kst_iso(ms: Any) -> str | None:
    if ms is None:
        return None
    if isinstance(ms, str):
        try:
            s = ms.replace(" ", "T")
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(KST).isoformat()
        except Exception:
            return ms
    try:
        return datetime.fromtimestamp(int(ms) / 1000.0, tz=timezone.utc).astimezone(KST).isoformat()
    except Exception:
        return str(ms)


# ── session_gold S3 경로 헬퍼 ─────────────────────────────────────────────────

def _list_session_gold_keys(prefix: str) -> list[str]:
    s3        = _s3_client()
    paginator = s3.get_paginator("list_objects_v2")
    keys: list[str] = []
    for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith(".parquet") and "_SUCCESS" not in key:
                keys.append(key)
    return keys


def _parse_gold_partition(prefix: str) -> dict[str, str]:
    """
    gold/session_gold/dt=2026-03-28/hour=14/minute_10=10/
    → {"dt": "2026-03-28", "hour": "14", "minute": "10"}
    """
    dt_m     = re.search(r"dt=([^/]+)",            prefix)
    hour_m   = re.search(r"hour=(\d+)",             prefix)
    minute_m = re.search(r"minute(?:_10)?=(\d+)",   prefix)

    if dt_m and hour_m and minute_m:
        return {
            "dt":     dt_m.group(1),
            "hour":   hour_m.group(1),
            "minute": minute_m.group(1),
        }

    now = datetime.now(tz=KST)
    logger.warning("_parse_gold_partition: 파싱 실패 — KST 현재값 fallback")
    return {
        "dt":     now.strftime("%Y-%m-%d"),
        "hour":   str(now.hour),
        "minute": str((now.minute // 10) * 10),
    }


def _build_rag_s3_key(partition: dict[str, str]) -> str:
    """
    → rag_result/dt=2026-03-28_hour=14_minute=10_rag_results.jsonl
    """
    dt     = partition["dt"]
    hour   = int(partition["hour"])
    minute = int(partition["minute"])
    return (
        f"{S3_RAG_PREFIX}/"
        f"dt={dt}_hour={hour:02d}_minute={minute:02d}_rag_results.jsonl"
    )


# ══════════════════════════════════════════════════════════════════════════════
# whitelist 로직
# ══════════════════════════════════════════════════════════════════════════════

WHITELIST_IPS: set[str] = {
    "10.0.0.1", "10.0.0.2", "192.168.0.1", "192.168.0.10",
}
WHITELIST_CIDRS: list[str] = ["10.0.2.0/24"]
SUSPICION_THRESHOLD = 30

_CATEGORY_TO_CLASSTYPE: dict[str, str] = {
    "Web Application Attack":                        "web-application-attack",
    "A Network Trojan was detected":                 "trojan-activity",
    "Misc Attack":                                   "misc-attack",
    "Potentially Bad Traffic":                       "bad-unknown",
    "Detection of a Network Scan":                   "network-scan",
    "Not Suspicious Traffic":                        "not-suspicious",
    "Attempted Administrator Privilege Gain":        "misc-attack",
    "Attempted User Privilege Gain":                 "misc-attack",
    "Generic Protocol Command Decode":               "bad-unknown",
    "Unknown Traffic":                               "unknown",
    "Malware Command and Control Activity Detected": "command-and-control",
}
_CLASSTYPE_RANK: dict[str, int] = {
    "web-application-attack": 3, "trojan-activity": 3,
    "command-and-control": 3,   "misc-attack": 3,
    "bad-unknown": 2,           "network-scan": 2,
    "not-suspicious": 1,        "unknown": 1,
}


def _in_whitelist(ip: str | None) -> bool:
    if not ip: return False
    if ip in WHITELIST_IPS: return True
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(c, strict=False) for c in WHITELIST_CIDRS)
    except ValueError:
        return False


def _is_whitelisted_session(session: dict) -> bool:
    if session.get("src_ip") is not None:
        return _in_whitelist(session["src_ip"])
    for ev in session.get("timeline", []):
        if ev.get("source") == "zeek_conn":  return _in_whitelist(ev.get("orig_h"))
        if ev.get("source") == "suricata":   return _in_whitelist(ev.get("src_ip"))
    return False


def _get_session_src_ip(session: dict) -> str | None:
    if session.get("src_ip") is not None: return session["src_ip"]
    for ev in session.get("timeline", []):
        if ev.get("source") == "zeek_conn" and ev.get("orig_h"): return ev["orig_h"]
    for ev in session.get("timeline", []):
        if ev.get("source") == "suricata"  and ev.get("src_ip"): return ev["src_ip"]
    return None


def _get_session_flow_start(session: dict) -> float | None:
    ts = session.get("flow_start")
    if not ts: return None
    if isinstance(ts, (int, float)):
        v = float(ts)
        return v / 1000.0 if v > 1e10 else v
    try:
        s = str(ts).replace(" ", "T")
        if s.endswith("Z"): s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None: dt = dt.replace(tzinfo=KST)
        return dt.astimezone(timezone.utc).timestamp()
    except Exception:
        return None


REPEAT_WINDOW_SEC = 10


def _build_repeat_count_map(sessions: list[dict]) -> dict[str, int]:
    from collections import defaultdict
    ip_ts:     dict[str, list[float]] = defaultdict(list)
    cid_to_ip: dict[str, str]         = {}

    for sess in sessions:
        src_ip = _get_session_src_ip(sess)
        ts     = _get_session_flow_start(sess)
        cid    = str(sess.get("community_id") or id(sess))
        if src_ip and ts is not None:
            ip_ts[src_ip].append(ts)
            cid_to_ip[cid] = src_ip

    ip_max_count: dict[str, int] = {}
    for ip, ts_list in ip_ts.items():
        ts_list.sort()
        max_count, left = 1, 0
        for right in range(len(ts_list)):
            while ts_list[right] - ts_list[left] > REPEAT_WINDOW_SEC:
                left += 1
            max_count = max(max_count, right - left + 1)
        ip_max_count[ip] = max_count

    result: dict[str, int] = {}
    for sess in sessions:
        cid    = str(sess.get("community_id") or id(sess))
        src_ip = cid_to_ip.get(cid)
        result[cid] = ip_max_count.get(src_ip, 1) if src_ip else 1
    return result


def _calc_suspicion_score(session: dict, repeat_count: int = 1) -> int:
    classtypes: list[str] = []
    severities: list[int] = []
    for ev in session.get("timeline", []):
        if ev.get("source") != "suricata" or not ev.get("signature"): continue
        ct = _CATEGORY_TO_CLASSTYPE.get(ev.get("category", ""), "unknown")
        classtypes.append(ct)
        sev = ev.get("severity")
        if sev is not None:
            try: severities.append(int(sev))
            except (ValueError, TypeError): pass

    highest_ct  = max(classtypes, key=lambda c: _CLASSTYPE_RANK.get(c, 0), default="unknown")
    highest_sev = min(severities) if severities else 4

    def _ct_score(ct: str) -> int:
        if ct in {"web-application-attack","trojan-activity","command-and-control","misc-attack"}: return 30
        if ct in {"bad-unknown","network-scan"}:  return 20
        if ct in {"not-suspicious","unknown"}:    return 10
        return 0

    def _sev_score(s: int) -> int:
        return {1: 30, 2: 20, 3: 10}.get(s, 0)

    def _repeat_score(cnt: int) -> int:
        if cnt >= 5: return 20
        if cnt >= 3: return 10
        return 0

    return _ct_score(highest_ct) + _sev_score(highest_sev) + _repeat_score(repeat_count)


# ══════════════════════════════════════════════════════════════════════════════
# Task 0-a : resolve_session_gold_prefix
# ══════════════════════════════════════════════════════════════════════════════

def resolve_session_gold_prefix(**ctx) -> None:
    """
    S3에서 가장 최근 _SUCCESS 파일을 찾아 해당 배치의 prefix / partition 파싱.
    wait_for_session_gold Sensor 통과 직후 실행.
    """
    s3        = _s3_client()
    paginator = s3.get_paginator("list_objects_v2")

    success_keys: list[tuple[datetime, str]] = []
    for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=S3_SESSION_GOLD_PREFIX):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/_SUCCESS"):
                success_keys.append((obj["LastModified"], key))

    if not success_keys:
        raise ValueError("resolve_session_gold_prefix: _SUCCESS 파일 없음")

    _, latest_success = max(success_keys, key=lambda x: x[0])
    prefix    = latest_success.rsplit("/", 1)[0] + "/"
    partition = _parse_gold_partition(prefix)

    logger.info("resolve_session_gold_prefix: prefix    = %s", prefix)
    logger.info("resolve_session_gold_prefix: partition = %s", partition)

    ctx["ti"].xcom_push(key="session_gold_prefix", value=prefix)
    ctx["ti"].xcom_push(key="gold_partition",       value=partition)


# ══════════════════════════════════════════════════════════════════════════════
# Task 1 : load_session_gold
# ══════════════════════════════════════════════════════════════════════════════

def load_session_gold(**ctx) -> None:
    import pandas as pd

    prefix: str = ctx["ti"].xcom_pull(
        task_ids="resolve_session_gold_prefix", key="session_gold_prefix",
    ) or S3_SESSION_GOLD_PREFIX

    partition = ctx["ti"].xcom_pull(
        task_ids="resolve_session_gold_prefix", key="gold_partition",
    ) or _parse_gold_partition(prefix)

    # partition은 resolve에서 이미 파싱 완료 — 그대로 전달
    ctx["ti"].xcom_push(key="gold_partition", value=partition)
    logger.info("load_session_gold: prefix = %s, partition = %s", prefix, partition)

    keys = _list_session_gold_keys(prefix)
    if not keys:
        raise ValueError(f"session_gold parquet 파일 없음 — prefix: {prefix}")

    s3 = _s3_client()
    frames: list[Any] = []
    for key in keys:
        try:
            obj = s3.get_object(Bucket=S3_BUCKET, Key=key)
            frames.append(pd.read_parquet(io.BytesIO(obj["Body"].read())))
        except Exception as e:
            logger.warning("parquet 읽기 실패 — %s: %s", key, e)

    if not frames:
        raise ValueError("읽을 수 있는 session_gold parquet 파일 없음")

    df = pd.concat(frames, ignore_index=True)
    logger.info("load_session_gold: %d 행 로드", len(df))
    df = df.drop(columns=[c for c in ("dt", "hour", "minute_10") if c in df.columns])

    def _cvt(v: Any) -> Any:
        if isinstance(v, float) and v != v: return None
        if isinstance(v, bool):             return v
        if isinstance(v, (int, str)):       return v
        if hasattr(v, "item"):              return v.item()
        if isinstance(v, list):             return v
        return v

    NUMERIC_FIELDS = (
        "uid", "flow_id", "src_ip", "src_port", "dest_ip", "dest_port",
        "proto", "service", "is_threat", "alert_count", "threat_level",
    )

    merged:     dict[str, dict] = {}
    orphan_idx: int = 0

    for _, row in df.iterrows():
        rec: dict[str, Any] = {k: _cvt(v) for k, v in row.to_dict().items()}
        rec["flow_start"] = _ms_to_kst_iso(rec.get("flow_start"))
        rec["flow_end"]   = _ms_to_kst_iso(rec.get("flow_end"))

        tl_raw = rec.get("timeline", [])
        if isinstance(tl_raw, str):
            try:
                tl_parsed = json.loads(tl_raw)
                if not isinstance(tl_parsed, list): tl_parsed = []
            except json.JSONDecodeError:
                tl_parsed = []
        elif isinstance(tl_raw, list):
            tl_parsed = tl_raw
        else:
            tl_parsed = []
        rec["timeline"] = tl_parsed

        cid = rec.get("community_id")
        if not cid:
            merged[f"_orphan_{orphan_idx}"] = rec
            orphan_idx += 1
            continue

        if cid not in merged:
            merged[cid] = rec
        else:
            ex = merged[cid]
            ex["timeline"] = ex.get("timeline", []) + tl_parsed
            for f in NUMERIC_FIELDS:
                if rec.get(f) is not None: ex[f] = rec[f]
            fs_old, fs_new = ex.get("flow_start"), rec.get("flow_start")
            if fs_old and fs_new: ex["flow_start"] = min(fs_old, fs_new)
            elif fs_new:          ex["flow_start"] = fs_new
            fe_old, fe_new = ex.get("flow_end"), rec.get("flow_end")
            if fe_old and fe_new: ex["flow_end"] = max(fe_old, fe_new)
            elif fe_new:          ex["flow_end"] = fe_new

    raw_sessions = list(merged.values())
    logger.info("load_session_gold 완료 — %d 세션", len(raw_sessions))
    ctx["ti"].xcom_push(key="raw_sessions", value=raw_sessions)
    ctx["ti"].xcom_push(key="total_loaded", value=len(raw_sessions))


# ══════════════════════════════════════════════════════════════════════════════
# Task 2 : filter_whitelist
# ══════════════════════════════════════════════════════════════════════════════

def filter_whitelist(**ctx) -> None:
    raw_sessions: list[dict] = ctx["ti"].xcom_pull(
        task_ids="load_session_gold", key="raw_sessions"
    ) or []

    repeat_map = _build_repeat_count_map(raw_sessions)
    passed:   list[dict]     = []
    filtered: dict[str, int] = {"whitelist_ip": 0, "low_score": 0}

    for sess in raw_sessions:
        if _is_whitelisted_session(sess):
            filtered["whitelist_ip"] += 1
            continue
        cid          = str(sess.get("community_id") or id(sess))
        repeat_count = repeat_map.get(cid, 1)
        score        = _calc_suspicion_score(sess, repeat_count=repeat_count)
        if score < SUSPICION_THRESHOLD:
            filtered["low_score"] += 1
            continue
        sess["suspicion_score"] = score
        passed.append(sess)

    logger.info(
        "filter_whitelist: 전체 %d → 통과 %d (화이트리스트 %d, 저점수 %d)",
        len(raw_sessions), len(passed),
        filtered["whitelist_ip"], filtered["low_score"],
    )
    ctx["ti"].xcom_push(key="filtered_sessions", value=passed)
    ctx["ti"].xcom_push(key="filter_stats",       value=filtered)


# ══════════════════════════════════════════════════════════════════════════════
# Task 3 : build_subgraphs
# ══════════════════════════════════════════════════════════════════════════════

def build_subgraphs(**ctx) -> None:
    sessions: list[dict] = ctx["ti"].xcom_pull(
        task_ids="filter_whitelist", key="filtered_sessions"
    ) or []

    if not sessions:
        logger.warning("build_subgraphs: 처리할 세션 없음")
        ctx["ti"].xcom_push(key="subgraphs", value=[])
        return

    for idx, sess in enumerate(sessions):
        if not sess.get("session_id"):
            sess["session_id"] = _make_session_id(sess.get("community_id"), idx)

    sess_index  = {s["session_id"]: s for s in sessions}
    session_ids = list(sess_index.keys())
    neighbor_map: dict[str, list[dict]] = {sid: [] for sid in session_ids}

    batch_query = """
    UNWIND $session_ids AS sid
    MATCH (s:Session {session_id: sid})-[r]->(n)
    RETURN
        sid                       AS session_id,
        type(r)                   AS rel_type,
        labels(n)                 AS node_labels,
        n.value                   AS node_value,
        n.signature               AS signature,
        n.category                AS category,
        n.first_seen              AS first_seen,
        n.last_seen               AS last_seen,
        n.related_session_count   AS related_session_count,
        n.total_orig_bytes        AS total_orig_bytes,
        n.total_resp_bytes        AS total_resp_bytes
    """

    total_edges = 0
    driver = _neo4j_driver()
    with driver.session() as neo_sess:
        for i in range(0, len(session_ids), NEO4J_BATCH_SIZE):
            batch  = session_ids[i : i + NEO4J_BATCH_SIZE]
            result = neo_sess.run(batch_query, session_ids=batch)
            for record in result:
                sid = record["session_id"]
                neighbor_map[sid].append({
                    "rel_type":              record["rel_type"],
                    "node_labels":           record["node_labels"],
                    "node_value":            record["node_value"],
                    "signature":             record["signature"],
                    "category":             record["category"],
                    "first_seen":            str(record["first_seen"]) if record["first_seen"] else None,
                    "last_seen":             str(record["last_seen"])  if record["last_seen"]  else None,
                    "related_session_count": record["related_session_count"],
                    "total_orig_bytes":      record["total_orig_bytes"],
                    "total_resp_bytes":      record["total_resp_bytes"],
                })
                total_edges += 1
    driver.close()

    subgraphs = [{"session": sess_index[sid], "neighbors": neighbor_map[sid]}
                 for sid in session_ids]
    neo4j_hit = sum(1 for sid in session_ids if neighbor_map[sid])
    logger.info(
        "build_subgraphs 완료 — 세션 %d개 | Neo4j 매칭 %d개 (%d 엣지) | 신규 %d개",
        len(subgraphs), neo4j_hit, total_edges, len(subgraphs) - neo4j_hit,
    )
    ctx["ti"].xcom_push(key="subgraphs", value=subgraphs)


# ══════════════════════════════════════════════════════════════════════════════
# Task 4 : run_rag_analysis
# ══════════════════════════════════════════════════════════════════════════════

def _subgraph_to_text(subgraph: dict) -> str:
    s = subgraph["session"]
    lines = [
        "[현재 세션 정보]",
        f"  session_id   : {s.get('session_id')}",
        f"  src_ip       : {s.get('src_ip')}  →  dest_ip : {s.get('dest_ip')}",
        f"  proto        : {s.get('proto')}       port    : {s.get('dest_port')}",
        f"  alert_count  : {s.get('alert_count')}   max_severity : {s.get('max_severity')}",
        f"  conn_state   : {s.get('conn_state') or 'N/A'}",
        f"  tls_sni      : {s.get('tls_sni') or 'N/A'}",
        f"  http_host    : {s.get('http_host') or 'N/A'}",
        f"  http_uri     : {s.get('http_uri') or 'N/A'}",
        f"  http_version : {s.get('http_version') or 'N/A'}",
        f"  dns_query    : {s.get('dns_query') or 'N/A'}",
        f"  flow_start   : {s.get('flow_start')}",
        "",
    ]
    neighbors = subgraph.get("neighbors", [])
    if neighbors:
        lines.append("[Neo4j 과거 행위 (1-hop)]")
        for nb in neighbors:
            label = (nb.get("node_labels") or ["?"])[0]
            value = nb.get("node_value", "")
            rel   = nb.get("rel_type", "")
            extra = (f"  signature={nb['signature']}  category={nb.get('category')}"
                     if nb.get("signature") else "")
            lines.append(f"  -[{rel}]→ :{label} '{value}'{extra}")
    else:
        lines.append("[Neo4j 과거 행위] 없음 (신규 세션 또는 미수집)")
    return "\n".join(lines)


_SYSTEM_PROMPT = """\
You are a professional cybersecurity analyst specializing in network threat detection.
You will be given:
1. Current session attributes (from real-time network logs)
2. Past behavior context from Neo4j graph (may be empty for brand-new sessions)

When writing the summary, you MUST analyze and reference ALL of the following fields if present:
- community_id         : 동일 community_id의 반복 등장 여부 (세션 군집 이상 여부)
- src_ip / dest_ip     : 출발지·목적지 IP (내부망 여부, 알려진 악성 IP 패턴)
- dest_port / proto    : 포트·프로토콜 이상 여부 (비표준 포트, 불필요한 프로토콜)
- alert_count          : 알림 발생 횟수 (높을수록 반복 공격 가능성)
- max_severity         : 최고 위험도 (1=최고, 4=낮음)
- signature / category : 탐지된 Suricata 시그니처명과 분류 (판단의 핵심 근거)
- tls_sni / tls_version / tls_cipher : TLS SNI 도메인 이상 여부, 취약 버전·암호화 스위트 사용 여부
- http_host / http_uri / http_method / http_version : 비정상 URI 패턴, 웹 공격 흔적
- dns_query            : DGA 도메인 의심 여부, 비정상 쿼리
- conn_state           : 연결 완료 여부 (S0=연결 시도만, SF=정상 완료, REJ=포트닫힘, RSTO/RSTR=강제종료, OTH=터널링의심 등)
- Neo4j 과거 행위      : 동일 세션의 과거 관계(엣지 타입, 연결 노드)에서 반복·지속 패턴 여부

Analyze and respond ONLY in this JSON format (no markdown, no explanation):
{
  "threat_type": "<Web Application Attack | A Network Trojan was detected | Misc Attack | Potentially Bad Traffic | Detection of a Network Scan | Not Suspicious Traffic | Attempted Administrator Privilege Gain | Attempted User Privilege Gain | Generic Protocol Command Decode | Malware Command and Control Activity Detected | Unknown Traffic>",
  "summary": "<2~3문장 한국어 위협 요약. 위 필드 중 실제로 존재하는 값을 구체적으로 인용하여 판단 근거를 서술할 것. N/A이거나 없는 필드는 언급하지 말 것>",
  "recommended_action": "<한 줄 대응 권고>"
}
"""


def run_rag_analysis(**ctx) -> None:
    from groq import RateLimitError

    subgraphs: list[dict] = ctx["ti"].xcom_pull(
        task_ids="build_subgraphs", key="subgraphs"
    ) or []

    if not subgraphs:
        logger.warning("run_rag_analysis: 처리할 서브그래프 없음")
        ctx["ti"].xcom_push(key="rag_results", value=[])
        return

    groq         = _groq_client()
    model        = _groq_model()
    results:     list[dict] = []
    use_fallback = False
    inference_dt = _now_kst_iso()   # DAG 실행 시각 KST

    def _parse_response(raw: str) -> dict:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            cleaned = raw.replace("```json", "").replace("```", "").strip()
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError:
                return {"raw_response": raw, "parse_error": True}

    def _append_result(response, session_id: str, sg: dict) -> None:
        raw      = response.choices[0].message.content.strip()
        analysis = _parse_response(raw)
        results.append({
            "session_id":         session_id,
            "uid":                sg["session"].get("uid"),
            "inference_datetime": inference_dt,
            "session":            sg["session"],
            "analysis": {
                **analysis,
                "threat_score": sg["session"].get("suspicion_score", 0),
            },
            "neighbors": sg.get("neighbors", []),
        })

    for i, sg in enumerate(subgraphs):
        session_id    = sg["session"].get("session_id", f"unknown_{i}")
        user_text     = _subgraph_to_text(sg)
        current_model = "openai/gpt-oss-120b" if use_fallback else model

        try:
            response = groq.chat.completions.create(
                model=current_model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": user_text},
                ],
                temperature=0.1,
                max_tokens=1024,
            )
            _append_result(response, session_id, sg)

        except RateLimitError:
            if not use_fallback:
                logger.warning(
                    "run_rag_analysis: session_id=%s Rate Limit — 60초 대기 후 fallback 전환",
                    session_id,
                )
                use_fallback = True
                time.sleep(60)
            else:
                logger.warning(
                    "run_rag_analysis: session_id=%s fallback도 Rate Limit — 2초 대기", session_id,
                )
                time.sleep(2)
            try:
                response = groq.chat.completions.create(
                    model="llama-3.1-8b-instant",
                    messages=[
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user",   "content": user_text},
                    ],
                    temperature=0.1,
                    max_tokens=1024,
                )
                _append_result(response, session_id, sg)
            except Exception as e2:
                logger.error("run_rag_analysis: session_id=%s fallback 실패 — %s", session_id, e2)
                results.append({
                    "session_id":         session_id,
                    "uid":                sg["session"].get("uid"),
                    "inference_datetime": inference_dt,
                    "session":            sg["session"],
                    "analysis":           {"error": str(e2)},
                    "neighbors":          sg.get("neighbors", []),
                })

        except Exception as e:
            logger.error("run_rag_analysis: session_id=%s 오류 — %s", session_id, e)
            results.append({
                "session_id":         session_id,
                "uid":                sg["session"].get("uid"),
                "inference_datetime": inference_dt,
                "session":            sg["session"],
                "analysis":           {"error": str(e)},
                "neighbors":          sg.get("neighbors", []),
            })

        time.sleep(GROQ_RPM_SLEEP)

    logger.info(
        "run_rag_analysis: %d 건 분석 완료 (inference_datetime: %s, fallback: %s)",
        len(results), inference_dt, use_fallback,
    )
    ctx["ti"].xcom_push(key="rag_results",       value=results)
    ctx["ti"].xcom_push(key="inference_datetime", value=inference_dt)


# ══════════════════════════════════════════════════════════════════════════════
# Task 5 : save_rag_results
# ══════════════════════════════════════════════════════════════════════════════

def save_rag_results(**ctx) -> None:
    results: list[dict] = ctx["ti"].xcom_pull(
        task_ids="run_rag_analysis", key="rag_results"
    ) or []

    if not results:
        logger.warning("save_rag_results: 저장할 결과 없음")
        return

    partition = ctx["ti"].xcom_pull(
        task_ids="load_session_gold", key="gold_partition"
    ) or {}
    s3_key = _build_rag_s3_key(partition)

    body = "\n".join(json.dumps(r, ensure_ascii=False) for r in results)
    _s3_client().put_object(
        Bucket=S3_BUCKET, Key=s3_key,
        Body=body.encode("utf-8"), ContentType="application/jsonl",
    )
    logger.info("save_rag_results: s3://%s/%s 에 %d 건 저장", S3_BUCKET, s3_key, len(results))
    ctx["ti"].xcom_push(key="saved_count", value=len(results))
    ctx["ti"].xcom_push(key="saved_s3_key", value=s3_key)


# ══════════════════════════════════════════════════════════════════════════════
# Task 6 : report_rag_stats
# ══════════════════════════════════════════════════════════════════════════════

def report_rag_stats(**ctx) -> None:
    ti           = ctx["ti"]
    total_loaded = ti.xcom_pull(task_ids="load_session_gold", key="total_loaded")    or 0
    filter_stats = ti.xcom_pull(task_ids="filter_whitelist",  key="filter_stats")    or {}
    results      = ti.xcom_pull(task_ids="run_rag_analysis",  key="rag_results")     or []
    saved_count  = ti.xcom_pull(task_ids="save_rag_results",  key="saved_count")     or 0
    saved_key    = ti.xcom_pull(task_ids="save_rag_results",  key="saved_s3_key")    or "-"
    inference_dt = ti.xcom_pull(task_ids="run_rag_analysis",  key="inference_datetime") or "-"

    threat_dist: dict[str, int] = {}
    error_count = 0
    for r in results:
        a = r.get("analysis", {})
        if a.get("error") or a.get("parse_error"):
            error_count += 1
            continue
        tt = a.get("threat_type", "Unknown")
        threat_dist[tt] = threat_dist.get(tt, 0) + 1

    logger.info("=" * 70)
    logger.info("▶ neo4j_to_rag 추론 파이프라인 완료 요약 (v6 — S3KeySensor 즉시 트리거)")
    logger.info("=" * 70)
    logger.info("  [입력]  session_gold 로드      : %d 세션", total_loaded)
    logger.info("  [필터]  화이트리스트 제외       : %d", filter_stats.get("whitelist_ip", 0))
    logger.info("  [필터]  저점수 제외             : %d", filter_stats.get("low_score", 0))
    logger.info("  [분석]  RAG 분석 세션           : %d", len(results))
    logger.info("  [추론]  inference_datetime      : %s (KST)", inference_dt)
    logger.info("  [저장]  S3 저장 건수            : %d", saved_count)
    logger.info("  [저장]  S3 경로                 : s3://%s/%s", S3_BUCKET, saved_key)
    logger.info("  [오류]  분석 실패               : %d", error_count)
    logger.info("  [위협 유형 분포]")
    for tt, cnt in sorted(threat_dist.items(), key=lambda x: -x[1]):
        logger.info("    %-45s %d", tt, cnt)
    logger.info("=" * 70)


# ══════════════════════════════════════════════════════════════════════════════
# DAG 정의
# ══════════════════════════════════════════════════════════════════════════════

default_args = {
    "owner":            "linda",
    "depends_on_past":  False,
    "retries":          1,
    "retry_delay":      timedelta(minutes=3),
    "email_on_failure": False,
}

with DAG(
    dag_id="neo4j_to_rag",
    description="추론 DAG — session_gold parquet → whitelist → Neo4j enrichment → Groq RAG (v6)",
    default_args=default_args,
    start_date=datetime(2026, 1, 1),
    schedule="*/10 * * * *",   # unified_events_to_gold 와 동일 주기
    catchup=False,
    max_active_runs=1,
    tags=["cti", "graph-rag", "groq"],
) as dag:

    # _SUCCESS 감지 → 즉시 트리거 (15초 폴링)
    t_sensor = S3KeySensor(
        task_id="wait_for_session_gold",
        bucket_name=S3_BUCKET,
        bucket_key=S3_SESSION_GOLD_PREFIX + "*/_SUCCESS",
        wildcard_match=True,
        aws_conn_id="aws_default",
        poke_interval=15,
        timeout=1800,
        mode="poke",
    )

    t_resolve  = PythonOperator(task_id="resolve_session_gold_prefix", python_callable=resolve_session_gold_prefix)
    t_load     = PythonOperator(task_id="load_session_gold",           python_callable=load_session_gold)
    t_filter   = PythonOperator(task_id="filter_whitelist",            python_callable=filter_whitelist)
    t_subgraph = PythonOperator(task_id="build_subgraphs",             python_callable=build_subgraphs)
    t_rag      = PythonOperator(task_id="run_rag_analysis",            python_callable=run_rag_analysis)
    t_save     = PythonOperator(task_id="save_rag_results",            python_callable=save_rag_results)
    t_report   = PythonOperator(task_id="report_rag_stats",            python_callable=report_rag_stats)

    t_sensor >> t_resolve >> t_load >> t_filter >> t_subgraph >> t_rag >> t_save >> t_report
