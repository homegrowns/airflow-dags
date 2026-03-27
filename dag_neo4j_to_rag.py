"""
dag_neo4j_to_rag.py
실시간 추론 DAG — S3 silver parquet → whitelist → session_gold → Neo4j enrichment → Groq RAG


  1. 입력 경로( 3/25 추가 수정)
       Before : S3_PARQUET_KEY = "unified_events.parquet"  (단일 파일)
       After  : S3_SILVER_PREFIX = "silver/common_records/"  (dt/hour/batch_seq 파티션)

  2. load_parquet task 전면 재작성
       · _list_silver_parquet_keys() — prefix 내 .parquet 전체 열거
       · pd.concat 후 파티션 컬럼(dt/hour/batch_seq) 제거
       · flow_start/flow_end Unix ms int → ISO UTC 문자열 변환 (_ms_to_iso)
       · community_id 기준 배치 통합 (timeline 누적, 수치 필드 최신값)

  3. _extract_conn 변경 (인라인)
       · top-level src_ip/dest_ip 1순위 (Spark coalesce 확정값)
       · zeek_conn: uid + conn 세부 필드 보완
       · suricata: IP 최후 fallback (src_ip/dest_ip 직접 사용)

  4. _extract_suricata_stats 변경 (인라인)
       · top-level alert_count / threat_level 1순위
       · flow_*: event_type=="flow" 이벤트에서 추출
       · max_severity fallback: event_type=="alert" 이벤트에서 재집계

  5. _get_session_flow_start
       · load_parquet 에서 _ms_to_iso 변환 후 ISO string 으로 저장되므로
         str 파싱 경로로 정상 처리됨 (int ms epoch 직접 입력 방어 코드도 유지)

  6. _to_session_gold
       · top-level uid/src_ip/dest_ip 우선 사용 반영

Pipeline:
  [load_parquet]          ← S3 silver/common_records/ parquet 읽기 → community_id 통합
          ↓
  [filter_whitelist]      ← whitelist 로직 적용 (IP + suspicion_score)
          ↓
  [build_session_gold]    ← session_gold 구조 생성
          ↓
  [build_subgraphs]       ← Neo4j 1-hop enrichment
          ↓
  [run_rag_analysis]      ← Groq LLM 위협 분석
          ↓
  [save_rag_results]      ← S3 저장
          ↓
  [report_rag_stats]      ← 통계 로그

Author : Linda
"""

from __future__ import annotations

import io
import json
import logging
import time
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any

import boto3
from airflow import DAG
from airflow.models import Variable
from airflow.operators.python import PythonOperator

logger = logging.getLogger(__name__)

# ── S3 설정 ───────────────────────────────────────────────────────────────────
S3_BUCKET        = "malware-project-bucket"
S3_SILVER_PREFIX = "silver/common_records/"   #   3/25 추가 Spark silver 파티션 parquet prefix
S3_RAG_KEY       = "rag_result/rag_results.jsonl"
AWS_REGION       = "ap-northeast-2"

# ── 배치 / 요청 설정 ──────────────────────────────────────────────────────────
NEO4J_BATCH_SIZE = 50
GROQ_RPM_SLEEP   = 2.0
MAX_SESSIONS     = 200

# ── Groq 모델 ─────────────────────────────────────────────────────────────────
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
    return Groq(api_key=Variable.get("GROQ_API_KEY"))


def _groq_model() -> str:
    try:
        return Variable.get("GROQ_MODEL")
    except Exception:
        return GROQ_MODEL_DEFAULT


def _make_session_id(community_id: str | None, idx: int) -> str:
    if community_id:
        h = hashlib.sha1(community_id.encode()).hexdigest()[:8]
        return f"s_{h}"
    return f"s_orphan_{idx:04d}"


def _is_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


# ──   3/25 추가 silver prefix 헬퍼 ───────────────────────────────────────────────────

def _list_silver_parquet_keys() -> list[str]:
    """silver/common_records/ prefix 아래 모든 .parquet 파일 키 반환."""
    s3        = _s3_client()
    paginator = s3.get_paginator("list_objects_v2")
    keys: list[str] = []
    for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=S3_SILVER_PREFIX):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith(".parquet") and not key.endswith("_SUCCESS"):
                keys.append(key)
    return keys


def _ms_to_iso(ms: Any) -> str | None:
    """
    Spark flow_start/flow_end 는 Unix milliseconds (int) 로 저장됨.
    ISO UTC 문자열로 변환. 이미 문자열이면 그대로 반환.
    """
    if ms is None:
        return None
    if isinstance(ms, str):
        return ms
    try:
        return datetime.fromtimestamp(int(ms) / 1000.0, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError):
        return str(ms)


# ══════════════════════════════════════════════════════════════════════════════
# whitelist.py 로직 인라인
# ══════════════════════════════════════════════════════════════════════════════

WHITELIST_IPS: set[str] = {
    "10.0.0.1",
    "10.0.0.2",
    "192.168.0.1",
    "192.168.0.10",
}

WHITELIST_CIDRS: list[str] = [
    "10.0.2.0/24",
]

SUSPICION_THRESHOLD = 30

_CATEGORY_TO_CLASSTYPE: dict[str, str] = {
    "Web Application Attack":                 "web-application-attack",
    "A Network Trojan was detected":          "trojan-activity",
    "Misc Attack":                            "misc-attack",
    "Potentially Bad Traffic":                "bad-unknown",
    "Detection of a Network Scan":            "network-scan",
    "Not Suspicious Traffic":                 "not-suspicious",
    "Attempted Administrator Privilege Gain": "misc-attack",
    "Attempted User Privilege Gain":          "misc-attack",
    "Generic Protocol Command Decode":        "bad-unknown",
    "Unknown Traffic":                               "unknown",
    "Malware Command and Control Activity Detected": "command-and-control",
}

_CLASSTYPE_RANK: dict[str, int] = {
    "web-application-attack": 3,
    "trojan-activity":        3,
    "command-and-control":    3,
    "misc-attack":            3,
    "bad-unknown":            2,
    "network-scan":           2,
    "not-suspicious":         1,
    "unknown":                1,
}


def _in_whitelist(ip: str | None) -> bool:
    if not ip:
        return False
    if ip in WHITELIST_IPS:
        return True
    if WHITELIST_CIDRS:
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in ipaddress.ip_network(cidr, strict=False)
                       for cidr in WHITELIST_CIDRS)
        except ValueError:
            return False
    return False


def _is_whitelisted_session(session: dict) -> bool:
    """top-level src_ip 1순위 (v4: Spark coalesce 확정값)."""
    if session.get("src_ip") is not None:
        return _in_whitelist(session["src_ip"])
    for ev in session.get("timeline", []):
        if ev.get("source") == "zeek_conn":
            return _in_whitelist(ev.get("orig_h"))
        if ev.get("source") == "suricata":
            return _in_whitelist(ev.get("src_ip"))
    return False


def _get_session_src_ip(session: dict) -> str | None:
    """top-level src_ip 1순위."""
    if session.get("src_ip") is not None:
        return session["src_ip"]
    for ev in session.get("timeline", []):
        if ev.get("source") == "zeek_conn" and ev.get("orig_h"):
            return ev["orig_h"]
    for ev in session.get("timeline", []):
        if ev.get("source") == "suricata" and ev.get("src_ip"):
            return ev["src_ip"]
    return None


def _get_session_flow_start(session: dict) -> float | None:
    """
    세션 flow_start → epoch seconds (float).
      3/25 추가 load_parquet 에서 _ms_to_iso 변환 후 ISO string 으로 저장되므로
         str 파싱 경로로 처리됨.
         만약 int ms epoch 가 직접 들어오는 경우를 방어하기 위해
         int 값이 > 1e10 이면 ms로 판단해 1000으로 나눔.
    """
    ts = session.get("flow_start")
    if not ts:
        return None
    if isinstance(ts, (int, float)):
        v = float(ts)
        # Unix ms epoch 방어 (> 1e10 이면 ms 단위로 판단)
        return v / 1000.0 if v > 1e10 else v
    try:
        ts_str = str(ts).replace(" ", "T")
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        return datetime.fromisoformat(ts_str).astimezone(timezone.utc).timestamp()
    except Exception:
        return None


REPEAT_WINDOW_SEC = 10


def _build_repeat_count_map(sessions: list[dict]) -> dict[str, int]:
    from collections import defaultdict

    ip_ts: dict[str, list[float]] = defaultdict(list)
    cid_to_ip: dict[str, str] = {}

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
        if ev.get("source") != "suricata" or not ev.get("signature"):
            continue
        ct = _CATEGORY_TO_CLASSTYPE.get(ev.get("category", ""), "unknown")
        classtypes.append(ct)
        sev = ev.get("severity")
        if sev is not None:
            try:
                severities.append(int(sev))
            except (ValueError, TypeError):
                pass

    highest_ct  = max(classtypes, key=lambda c: _CLASSTYPE_RANK.get(c, 0), default="unknown")
    highest_sev = min(severities) if severities else 4

    def _ct_score(ct: str) -> int:
        if ct in {"web-application-attack", "trojan-activity", "command-and-control", "misc-attack"}:
            return 30
        if ct in {"bad-unknown", "network-scan"}:
            return 20
        if ct in {"not-suspicious", "unknown"}:
            return 10
        return 0

    def _sev_score(s: int) -> int:
        return {1: 30, 2: 20, 3: 10}.get(s, 0)

    def _repeat_score(cnt: int) -> int:
        if cnt >= 5: return 20
        if cnt >= 3: return 10
        return 0

    return _ct_score(highest_ct) + _sev_score(highest_sev) + _repeat_score(repeat_count)


# ══════════════════════════════════════════════════════════════════════════════
# extract_sessions 인라인 헬퍼 (unified_to_gold v7 동일 로직)
# ══════════════════════════════════════════════════════════════════════════════

def _extract_conn(row: dict, timeline: list[dict]) -> dict:
    """
      3/25 추가 conn 정보 추출 우선순위:
      1. top-level src_ip/dest_ip (Spark coalesce 확정값)
      2. zeek_conn: uid + conn 세부 필드 보완 (orig_h/resp_h → IP fallback)
      3. suricata: src_ip/dest_ip 직접 사용 (orig_h/resp_h 없음)
    """
    base = {
        "uid":          row.get("uid"),
        "src_ip":       row.get("src_ip"),
        "src_port":     row.get("src_port"),
        "dest_ip":      row.get("dest_ip"),
        "dest_port":    row.get("dest_port"),
        "proto":        row.get("proto"),
        "service":      row.get("service"),
        "duration":     None,
        "orig_bytes":   None,
        "resp_bytes":   None,
        "conn_state":   None,
        "missed_bytes": None,
        "history":      None,
        "orig_pkts":    None,
        "resp_pkts":    None,
    }

    for ev in timeline:
        if ev.get("source") != "zeek_conn":
            continue
        if not base["uid"]:      base["uid"]      = ev.get("uid")
        if not base["src_ip"]:   base["src_ip"]   = ev.get("orig_h")
        if not base["dest_ip"]:  base["dest_ip"]  = ev.get("resp_h")
        if not base["src_port"]: base["src_port"] = ev.get("orig_p")
        if not base["dest_port"]:base["dest_port"]= ev.get("resp_p")
        base["duration"]     = ev.get("duration")
        base["orig_bytes"]   = ev.get("orig_bytes")
        base["resp_bytes"]   = ev.get("resp_bytes")
        base["conn_state"]   = ev.get("conn_state")
        base["missed_bytes"] = ev.get("missed_bytes")
        base["history"]      = ev.get("history")
        base["orig_pkts"]    = ev.get("orig_pkts")
        base["resp_pkts"]    = ev.get("resp_pkts")
        break

    # suricata fallback
    if not base["src_ip"] or not base["dest_ip"]:
        for ev in timeline:
            if ev.get("source") != "suricata":
                continue
            if not base["src_ip"]:    base["src_ip"]   = ev.get("src_ip")
            if not base["dest_ip"]:   base["dest_ip"]  = ev.get("dest_ip")
            if not base["src_port"]:  base["src_port"] = ev.get("src_port")
            if not base["dest_port"]: base["dest_port"]= ev.get("dest_port")
            if not base["proto"] and ev.get("proto"):
                base["proto"] = ev["proto"].lower()
            break

    return base


def _extract_http(timeline: list[dict]) -> dict:
    _null = {k: None for k in [
        "http_method", "http_host", "http_uri", "http_user_agent",
        "http_request_body_len", "http_response_body_len",
        "http_status_code", "http_status_msg",
        "http_version",   #   3/25 추가 zeek_http version 필드
    ]}
    for ev in timeline:
        if ev.get("source") != "zeek_http":
            continue
        host = ev.get("host")
        if host and ":" in host:
            host = host.rsplit(":", 1)[0]
        return {
            "http_method":            ev.get("method"),
            "http_host":              host,
            "http_uri":               ev.get("uri"),
            "http_user_agent":        ev.get("user_agent"),
            "http_request_body_len":  ev.get("request_body_len"),
            "http_response_body_len": ev.get("response_body_len"),
            "http_status_code":       ev.get("status_code"),
            "http_status_msg":        ev.get("status_msg"),
            "http_version":           ev.get("version"),
        }
    return _null


def _extract_dns(timeline: list[dict]) -> dict:
    _null = {k: None for k in [
        "dns_query", "dns_qtype_name", "dns_rcode_name", "dns_answers", "dns_rtt",
    ]}
    for ev in timeline:
        if ev.get("source") == "zeek_dns":
            return {
                "dns_query":      ev.get("query"),
                "dns_qtype_name": ev.get("qtype_name"),
                "dns_rcode_name": ev.get("rcode_name"),
                "dns_answers":    ev.get("answers"),
                "dns_rtt":        ev.get("rtt"),
            }
    return _null


def _extract_ssl(timeline: list[dict]) -> dict:
    _null = {k: None for k in [
        "tls_version", "tls_cipher", "tls_curve", "tls_sni",
        "tls_ssl_history", "tls_established", "tls_resumed",
    ]}
    for ev in timeline:
        if ev.get("source") == "zeek_ssl":
            return {
                "tls_version":     ev.get("version"),
                "tls_cipher":      ev.get("cipher"),
                "tls_curve":       ev.get("curve"),
                "tls_sni":         ev.get("server_name"),
                "tls_ssl_history": ev.get("ssl_history"),
                "tls_established": ev.get("established"),
                "tls_resumed":     ev.get("resumed"),
            }
    return _null


def _extract_suricata_stats(row: dict, timeline: list[dict]) -> dict:
    """
      3/25 추가
    · alert_count / threat_level: top-level 값 1순위 (Spark 집계 확정값)
    · flow_*: event_type=="flow" 이벤트에서 추출
    · max_severity fallback: event_type=="alert" 이벤트에서 재집계
    """
    alert_count  = row.get("alert_count") or 0
    max_severity = row.get("threat_level")

    flow_ev: dict = {}
    for ev in timeline:
        if ev.get("source") == "suricata" and ev.get("event_type") == "flow":
            flow_ev = ev
            break

    if max_severity is None:
        severities = [
            int(ev["severity"])
            for ev in timeline
            if ev.get("source") == "suricata"
            and ev.get("event_type") == "alert"
            and ev.get("severity") is not None
        ]
        max_severity = min(severities) if severities else None

    return {
        "alert_count":    alert_count,
        "max_severity":   max_severity,
        "flow_state":     flow_ev.get("flow_state"),
        "flow_reason":    flow_ev.get("flow_reason"),
        "pkts_toserver":  flow_ev.get("pkts_toserver"),
        "pkts_toclient":  flow_ev.get("pkts_toclient"),
        "bytes_toserver": flow_ev.get("bytes_toserver"),
        "bytes_toclient": flow_ev.get("bytes_toclient"),
    }


def _to_session_gold(raw_session: dict, session_id: str) -> dict:
    """raw unified 세션 → session_gold 레코드"""
    tl   = raw_session.get("timeline", [])
    conn = _extract_conn(raw_session, tl)   #   3/25 추가 row 전달
    http = _extract_http(tl)
    dns  = _extract_dns(tl)
    ssl  = _extract_ssl(tl)
    suri = _extract_suricata_stats(raw_session, tl)  #   3/25 추가 row 전달
    return {
        "session_id":     session_id,
        "community_id":   raw_session.get("community_id"),
        **conn,
        "uid":            conn.get("uid") or raw_session.get("uid"),
        "ts":             raw_session.get("flow_start"),  #   3/25 추가 ISO UTC 변환 완료 상태
        **http,
        **dns,
        **ssl,
        "alert_count":    suri["alert_count"],
        "max_severity":   suri["max_severity"],
        "is_threat":      raw_session.get("is_threat", False),
        "flow_state":     suri["flow_state"],
        "flow_reason":    suri["flow_reason"],
        "pkts_toserver":  suri["pkts_toserver"],
        "pkts_toclient":  suri["pkts_toclient"],
        "bytes_toserver": suri["bytes_toserver"],
        "bytes_toclient": suri["bytes_toclient"],
        "flow_start":     raw_session.get("flow_start"),
        "flow_end":       raw_session.get("flow_end"),
        "suspicion_score": raw_session.get("suspicion_score", 0),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Task 1 : load_parquet
# ══════════════════════════════════════════════════════════════════════════════

def load_parquet(**ctx) -> None:
    """
      3/25 추가 S3 silver/common_records/ 파티션 parquet 전체 읽기
         → community_id 기준 통합 → raw 세션 목록 XCom 전달.

    unified_to_gold v7 _load_silver_records() 동일 로직.
    """
    import pandas as pd

    keys = _list_silver_parquet_keys()
    if not keys:
        raise ValueError("silver prefix 에 parquet 파일이 없습니다.")

    s3 = _s3_client()
    frames: list[pd.DataFrame] = []
    for key in keys:
        try:
            obj = s3.get_object(Bucket=S3_BUCKET, Key=key)
            frames.append(pd.read_parquet(io.BytesIO(obj["Body"].read())))
        except Exception as e:
            logger.warning("parquet 읽기 실패 — %s: %s", key, e)

    if not frames:
        raise ValueError("읽을 수 있는 parquet 파일이 없습니다.")

    df = pd.concat(frames, ignore_index=True)
    logger.info("load_parquet: %d 행 로드 (컬럼: %s)", len(df), list(df.columns))

    # 파티션 컬럼 제거
    df = df.drop(columns=[c for c in ("dt", "hour", "batch_seq") if c in df.columns])

    # flow_start 기준 정렬 (배치 통합 시 최신값을 나중에 덮어씀)
    if "flow_start" in df.columns:
        df = df.sort_values("flow_start", na_position="last")

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

    merged: dict[str, dict] = {}
    orphan_idx = 0

    for _, row in df.iterrows():
        rec: dict[str, Any] = {k: _cvt(v) for k, v in row.to_dict().items()}

        # flow_start / flow_end Unix ms → ISO UTC
        rec["flow_start"] = _ms_to_iso(rec.get("flow_start"))
        rec["flow_end"]   = _ms_to_iso(rec.get("flow_end"))

        # timeline JSON string → list
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
                if rec.get(f) is not None:
                    ex[f] = rec[f]
            fs_old, fs_new = ex.get("flow_start"), rec.get("flow_start")
            if fs_old and fs_new: ex["flow_start"] = min(fs_old, fs_new)
            elif fs_new:          ex["flow_start"] = fs_new
            fe_old, fe_new = ex.get("flow_end"), rec.get("flow_end")
            if fe_old and fe_new: ex["flow_end"] = max(fe_old, fe_new)
            elif fe_new:          ex["flow_end"] = fe_new

    raw_sessions = list(merged.values())
    logger.info("load_parquet 완료 — community_id 기준 %d 세션", len(raw_sessions))
    ctx["ti"].xcom_push(key="raw_sessions",  value=raw_sessions)
    ctx["ti"].xcom_push(key="total_loaded",  value=len(raw_sessions))


# ══════════════════════════════════════════════════════════════════════════════
# Task 2 : filter_whitelist
# ══════════════════════════════════════════════════════════════════════════════

def filter_whitelist(**ctx) -> None:
    raw_sessions: list[dict] = ctx["ti"].xcom_pull(
        task_ids="load_parquet", key="raw_sessions"
    ) or []

    repeat_map = _build_repeat_count_map(raw_sessions)
    logger.info("filter_whitelist: repeat_count_map 계산 완료 (%d src_ip)", len(repeat_map))

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
# Task 3 : build_session_gold
# ══════════════════════════════════════════════════════════════════════════════

def build_session_gold(**ctx) -> None:
    filtered: list[dict] = ctx["ti"].xcom_pull(
        task_ids="filter_whitelist", key="filtered_sessions"
    ) or []

    if not filtered:
        logger.warning("build_session_gold: 처리할 세션 없음")
        ctx["ti"].xcom_push(key="session_gold", value=[])
        return

    seen_cids:  dict[str, str] = {}
    orphan_idx: int = 0
    gold: list[dict] = []

    for sess in filtered:
        cid = sess.get("community_id")
        if cid and cid in seen_cids:
            sid = seen_cids[cid]
        elif cid:
            sid = _make_session_id(cid, 0)
            seen_cids[cid] = sid
        else:
            sid = _make_session_id(None, orphan_idx)
            orphan_idx += 1
        gold.append(_to_session_gold(sess, sid))

    gold.sort(key=lambda s: (s.get("max_severity") or 99, -(s.get("alert_count") or 0)))
    gold = gold[:MAX_SESSIONS]

    logger.info(
        "build_session_gold 완료 — %d 건 (is_threat: %d)",
        len(gold), sum(1 for s in gold if s.get("is_threat")),
    )
    ctx["ti"].xcom_push(key="session_gold", value=gold)


# ══════════════════════════════════════════════════════════════════════════════
# Task 4 : build_subgraphs
# ══════════════════════════════════════════════════════════════════════════════

def build_subgraphs(**ctx) -> None:
    sessions: list[dict] = ctx["ti"].xcom_pull(
        task_ids="build_session_gold", key="session_gold"
    ) or []

    if not sessions:
        logger.warning("build_subgraphs: 처리할 세션 없음")
        ctx["ti"].xcom_push(key="subgraphs", value=[])
        return

    sess_index   = {s["session_id"]: s for s in sessions}
    session_ids  = list(sess_index.keys())
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
                    "category":              record["category"],
                    "first_seen":            str(record["first_seen"])  if record["first_seen"]  else None,
                    "last_seen":             str(record["last_seen"])   if record["last_seen"]   else None,
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
        "build_subgraphs 완료 — 세션 %d개 | Neo4j 매칭 %d개 (%d 엣지) | "
        "신규(미보유) %d개 → 현재 세션만으로 분석",
        len(subgraphs), neo4j_hit, total_edges, len(subgraphs) - neo4j_hit,
    )
    ctx["ti"].xcom_push(key="subgraphs", value=subgraphs)


# ══════════════════════════════════════════════════════════════════════════════
# Task 5 : run_rag_analysis
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
        f"  http_version : {s.get('http_version') or 'N/A'}",   #   3/25 추가 추가
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
- http_host / http_uri / http_method / http_version  : 비정상 URI 패턴, 웹 공격 흔적
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

    groq    = _groq_client()
    model   = _groq_model()
    results: list[dict] = []

    for i, sg in enumerate(subgraphs):
        session_id = sg["session"].get("session_id", f"unknown_{i}")
        user_text  = _subgraph_to_text(sg)

        def _parse_response(raw: str) -> dict:
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                cleaned = raw.replace("```json", "").replace("```", "").strip()
                try:
                    return json.loads(cleaned)
                except json.JSONDecodeError:
                    return {"raw_response": raw, "parse_error": True}

        def _append_result(response) -> None:
            raw      = response.choices[0].message.content.strip()
            analysis = _parse_response(raw)
            results.append({
                "session_id": session_id,
                "uid":        sg["session"].get("uid"),
                "session":    sg["session"],
                "analysis":   {
                    **analysis,
                    "threat_score": sg["session"].get("suspicion_score", 0),
                },
                "neighbors": sg.get("neighbors", []),
            })

        try:
            response = groq.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": user_text},
                ],
                temperature=0.1,
                max_tokens=1024,
            )
            _append_result(response)

        except RateLimitError as e:
            logger.warning(
                "run_rag_analysis: session_id=%s Rate Limit — 60초 대기 후 8b로 재시도", session_id
            )
            time.sleep(60)
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
                _append_result(response)
            except Exception as e2:
                logger.error(
                    "run_rag_analysis: session_id=%s fallback 실패 — %s", session_id, e2
                )
                results.append({
                    "session_id": session_id,
                    "uid":        sg["session"].get("uid"),
                    "session":    sg["session"],
                    "analysis":   {"error": str(e2)},
                    "neighbors":  sg.get("neighbors", []),
                })

        except Exception as e:
            logger.error("run_rag_analysis: session_id=%s 오류 — %s", session_id, e)
            results.append({
                "session_id": session_id,
                "uid":        sg["session"].get("uid"),
                "session":    sg["session"],
                "analysis":   {"error": str(e)},
                "neighbors":  sg.get("neighbors", []),
            })

        time.sleep(GROQ_RPM_SLEEP)

    logger.info("run_rag_analysis: %d 건 분석 완료", len(results))
    ctx["ti"].xcom_push(key="rag_results", value=results)
    
# ══════════════════════════════════════════════════════════════════════════════
# Task 6 : save_rag_results
# ══════════════════════════════════════════════════════════════════════════════

def save_rag_results(**ctx) -> None:
    results: list[dict] = ctx["ti"].xcom_pull(
        task_ids="run_rag_analysis", key="rag_results"
    ) or []

    if not results:
        logger.warning("save_rag_results: 저장할 결과 없음")
        return

    body = "\n".join(json.dumps(r, ensure_ascii=False) for r in results)
    _s3_client().put_object(
        Bucket=S3_BUCKET, Key=S3_RAG_KEY,
        Body=body.encode("utf-8"), ContentType="application/jsonl",
    )
    logger.info("save_rag_results: s3://%s/%s 에 %d 건 저장",
                S3_BUCKET, S3_RAG_KEY, len(results))
    ctx["ti"].xcom_push(key="saved_count", value=len(results))


# ══════════════════════════════════════════════════════════════════════════════
# Task 7 : report_rag_stats
# ══════════════════════════════════════════════════════════════════════════════

def report_rag_stats(**ctx) -> None:
    ti           = ctx["ti"]
    total_loaded = ti.xcom_pull(task_ids="load_parquet",     key="total_loaded")   or 0
    filter_stats = ti.xcom_pull(task_ids="filter_whitelist", key="filter_stats")   or {}
    results      = ti.xcom_pull(task_ids="run_rag_analysis", key="rag_results")    or []
    saved_count  = ti.xcom_pull(task_ids="save_rag_results", key="saved_count")    or 0

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
    logger.info("▶ neo4j_to_rag 추론 파이프라인 완료 요약 (Spark silver 대응)")
    logger.info("=" * 70)
    logger.info("  [입력]  silver parquet 로드    : %d 세션", total_loaded)
    logger.info("  [필터]  화이트리스트 제외       : %d", filter_stats.get("whitelist_ip", 0))
    logger.info("  [필터]  저점수 제외             : %d", filter_stats.get("low_score", 0))
    logger.info("  [분석]  RAG 분석 세션           : %d", len(results))
    logger.info("  [저장]  S3 저장 건수            : %d", saved_count)
    logger.info("  [오류]  분석 실패               : %d", error_count)
    logger.info("  [위협 유형 분포]")
    for tt, cnt in sorted(threat_dist.items(), key=lambda x: -x[1]):
        logger.info("    %-30s %d", tt, cnt)
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
    description="실시간 추론 DAG — Spark silver parquet → whitelist → session_gold → Neo4j enrichment → Groq RAG",
    default_args=default_args,
    start_date=datetime(2026, 1, 1),
    schedule="*/10 * * * *",
    catchup=False,
    max_active_runs=1,
    tags=["cti", "graph-rag", "groq"],
) as dag:

    t_load     = PythonOperator(task_id="load_parquet",       python_callable=load_parquet)
    t_filter   = PythonOperator(task_id="filter_whitelist",   python_callable=filter_whitelist)
    t_sessions = PythonOperator(task_id="build_session_gold", python_callable=build_session_gold)
    t_subgraph = PythonOperator(task_id="build_subgraphs",    python_callable=build_subgraphs)
    t_rag      = PythonOperator(task_id="run_rag_analysis",   python_callable=run_rag_analysis)
    t_save     = PythonOperator(task_id="save_rag_results",   python_callable=save_rag_results)
    t_report   = PythonOperator(task_id="report_rag_stats",   python_callable=report_rag_stats)

    t_load >> t_filter >> t_sessions >> t_subgraph >> t_rag >> t_save >> t_report