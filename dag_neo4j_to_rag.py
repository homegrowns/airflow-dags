"""
dag_neo4j_to_rag.py
실시간 추론 DAG — S3 parquet → whitelist → session_gold → Neo4j enrichment → Groq RAG  (v3)

Pipeline:
  [load_parquet]          ← S3 unified_events.parquet 읽기 → raw 세션 목록 생성
          ↓
  [filter_whitelist]      ← whitelist.py 로직 적용 (IP 화이트리스트 + suspicion_score 필터)
          ↓
  [build_session_gold]    ← unified_to_gold의 extract_sessions 로직 재사용 → session_gold 구조 생성
          ↓
  [build_subgraphs]       ← session_id 배치로 Neo4j 1-hop enrichment (과거 행위 보강)
          ↓
  [run_rag_analysis]      ← Groq LLM 위협 분석 (현재 세션 속성 + 과거 그래프 컨텍스트)
          ↓
  [save_rag_results]      ← 분석 결과 S3 저장 (rag_result/rag_results.jsonl)
          ↓
  [report_rag_stats]      ← 처리 건수 / 필터 현황 / 분류 분포 로그 출력

설계 원칙:
  - Spark가 S3에 올린 unified_events.parquet 소비
  - whitelist.py의 is_whitelisted_session() + should_include() 로직 인라인 사용
  - unified_to_gold의 extract_sessions 전처리 로직 인라인 사용
  - Neo4j는 과거 행위 enrichment 전용 (세션 속성의 단일 소스는 parquet)
  - Neo4j에 해당 session_id 없으면 neighbors=[] 로 처리 → 현재 세션만으로 RAG 실행

Author : Linda
"""

from __future__ import annotations

import io
import json
import logging
import time
import hashlib
from datetime import datetime, timedelta
from typing import Any

import boto3
from airflow import DAG
from airflow.models import Variable
from airflow.operators.python import PythonOperator

logger = logging.getLogger(__name__)

# ── S3 설정 ───────────────────────────────────────────────────────────────────
S3_BUCKET      = "malware-project-bucket"
S3_PARQUET_KEY = "unified_events.parquet"        # Spark 출력 경로
S3_RAG_KEY     = "rag_result/rag_results.jsonl"
AWS_REGION     = "ap-northeast-2"

# ── 배치 / 요청 설정 ──────────────────────────────────────────────────────────
NEO4J_BATCH_SIZE = 50     # Neo4j UNWIND 배치 크기
GROQ_RPM_SLEEP   = 2.0    # Groq rate limit 방지 sleep (초)
MAX_SESSIONS     = 200    # 1회 실행 최대 처리 세션 수

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


# ══════════════════════════════════════════════════════════════════════════════
# whitelist.py 로직 인라인
# (외부 파일 import 대신 인라인으로 유지 — DAG 파서가 dags/ 외부 모듈을 못 찾는 환경 대비)
# whitelist.py 수정 시 아래 상수도 같이 업데이트 필요
# ══════════════════════════════════════════════════════════════════════════════

WHITELIST_IPS: set[str] = {
    "10.0.0.1",       # 게이트웨이
    "10.0.0.2",       # DNS 서버
    "192.168.0.1",    # 내부 라우터
    "192.168.0.10",   # 모니터링 서버
}

WHITELIST_CIDRS: list[str] = [
    "10.0.2.0/24",
]

SUSPICION_THRESHOLD = 30

_CATEGORY_TO_CLASSTYPE: dict[str, str] = {
    # SQLi / XSS / LFI / RFI / WebShell 등 웹 취약점 직접 공격
    "Web Application Attack":                 "web-application-attack",
    # RAT, 백도어, 봇넷 에이전트 등 악성코드가 이미 감염된 호스트에서 통신
    "A Network Trojan was detected":          "trojan-activity",
    # 위 범주에 안 들어가는 기타 공격 (Exploit 시도, 프로토콜 남용 등)
    "Misc Attack":                            "misc-attack",
    # 악성으로 확정하기 어렵지만 의심스러운 트래픽 (C2 후보, DGA 도메인 등)
    "Potentially Bad Traffic":                "bad-unknown",
     # Nmap, Masscan 등 포트/서비스 스캐닝 행위
    "Detection of a Network Scan":            "network-scan",
    # Suricata가 정상으로 판단한 트래픽 (오탐 가능성 있음)
    "Not Suspicious Traffic":                 "not-suspicious",
    # sudo 탈취, SUID 악용 등 관리자 권한 획득 시도 (수평이동/권한상승)
    "Attempted Administrator Privilege Gain": "misc-attack",
    # 일반 사용자 권한 획득 시도 (웹쉘 → 로컬 사용자 전환 등)
    "Attempted User Privilege Gain":          "misc-attack",
    # HTTP/DNS/SMB 등 프로토콜 구조 자체를 디코딩하다 이상 패턴 감지
    # → C2 터널링, 비표준 인코딩 등에서 자주 발생하지만 오탐도 많음
    "Generic Protocol Command Decode":        "bad-unknown",
    # 룰 매칭은 됐지만 카테고리 분류 불가 (커스텀 룰 또는 구버전 룰셋)
    "Unknown Traffic":                        "unknown",
}

_CLASSTYPE_RANK: dict[str, int] = {
    "web-application-attack": 3, "trojan-activity": 3, "command-and-control": 3, "misc-attack": 3,
    "bad-unknown": 2,            "network-scan": 2,
    "not-suspicious": 1,         "unknown": 1,          
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
    for ev in session.get("timeline", []):
        if ev.get("source") == "zeek_conn":
            if _in_whitelist(ev.get("orig_h")):
                return True
        elif ev.get("source") == "suricata":
            if _in_whitelist(ev.get("src_ip")):
                return True
    return False


def _calc_suspicion_score(session: dict) -> int:
    """whitelist.py calc_suspicion_score() + extract_score_inputs() 통합."""
    classtypes: list[str] = []
    severities: list[int] = []
    alert_count = 0

    for ev in session.get("timeline", []):
        if ev.get("source") != "suricata" or not ev.get("signature"):
            continue
        alert_count += 1
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

    return _ct_score(highest_ct) + _sev_score(highest_sev) + _repeat_score(alert_count)


# ══════════════════════════════════════════════════════════════════════════════
# unified_to_gold extract_sessions 로직 인라인
# ══════════════════════════════════════════════════════════════════════════════

def _extract_conn(timeline: list[dict]) -> dict:
    for ev in timeline:
        if ev.get("source") == "zeek_conn":
            return {
                "src_ip":       ev.get("orig_h"),
                "src_port":     ev.get("orig_p"),
                "dst_ip":       ev.get("resp_h"),
                "dst_port":     ev.get("resp_p"),
                "proto":        ev.get("proto"),
                "service":      ev.get("service"),
                "duration":     ev.get("duration"),
                "orig_bytes":   ev.get("orig_bytes"),
                "resp_bytes":   ev.get("resp_bytes"),
                "conn_state":   ev.get("conn_state"),
                "missed_bytes": ev.get("missed_bytes"),
                "history":      ev.get("history"),
                "orig_pkts":    ev.get("orig_pkts"),
                "resp_pkts":    ev.get("resp_pkts"),
            }
    # fallback: suricata
    for ev in timeline:
        if ev.get("source") == "suricata":
            return {
                "src_ip":       ev.get("src_ip"),
                "src_port":     str(ev.get("src_port", "")),
                "dst_ip":       ev.get("dest_ip"),
                "dst_port":     str(ev.get("dest_port", "")),
                "proto":        ev.get("proto", "").lower(),
                **{k: None for k in ["service", "duration", "orig_bytes", "resp_bytes",
                                     "conn_state", "missed_bytes", "history",
                                     "orig_pkts", "resp_pkts"]},
            }
    return {}


def _extract_http(timeline: list[dict]) -> dict:
    _null = {k: None for k in ["http_method", "http_host", "http_uri", "http_user_agent",
                                "http_request_body_len", "http_response_body_len",
                                "http_status_code", "http_status_msg"]}
    for ev in timeline:
        if ev.get("source") == "zeek_http":
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
            }
    return _null


def _extract_dns(timeline: list[dict]) -> dict:
    _null = {k: None for k in ["dns_query", "dns_qtype_name", "dns_rcode_name",
                                "dns_answers", "dns_rtt"]}
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
    _null = {k: None for k in ["tls_version", "tls_cipher", "tls_curve", "tls_sni",
                                "tls_ssl_history", "tls_established", "tls_resumed"]}
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


def _extract_suricata_stats(timeline: list[dict]) -> dict:
    alerts    = [ev for ev in timeline
                 if ev.get("source") == "suricata" and ev.get("signature")]
    alert_cnt = len(alerts)
    max_sev   = min((int(a["severity"]) for a in alerts
                     if a.get("severity") is not None), default=None)
    flow: dict = {}
    for ev in timeline:
        if ev.get("source") == "suricata":
            flow = ev
            break
    return {
        "alert_count":    alert_cnt,
        "max_severity":   max_sev,
        "flow_state":     flow.get("flow_state"),
        "flow_reason":    flow.get("flow_reason"),
        "pkts_toserver":  flow.get("pkts_toserver"),
        "pkts_toclient":  flow.get("pkts_toclient"),
        "bytes_toserver": flow.get("bytes_toserver"),
        "bytes_toclient": flow.get("bytes_toclient"),
    }


def _to_session_gold(raw_session: dict, session_id: str) -> dict:
    """raw unified 세션 → session_gold 레코드 (unified_to_gold extract_sessions 동일 구조)."""
    tl   = raw_session.get("timeline", [])
    conn = _extract_conn(tl)
    http = _extract_http(tl)
    dns  = _extract_dns(tl)
    ssl  = _extract_ssl(tl)
    suri = _extract_suricata_stats(tl)
    return {
        "session_id":     session_id,
        "community_id":   raw_session.get("community_id"),
        **conn,
        **http,
        **dns,
        **ssl,
        "alert_count":    raw_session.get("alert_count", suri["alert_count"]),
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
    }


# ══════════════════════════════════════════════════════════════════════════════
# Task 1 : load_parquet
# ══════════════════════════════════════════════════════════════════════════════

def load_parquet(**ctx) -> None:
    """
    S3에서 unified_events.parquet 직접 읽기 → raw 세션 목록 XCom 전달.
    timeline 컬럼이 JSON 문자열로 저장된 경우 파싱.
    """
    import numpy as np
    import pandas as pd

    s3  = _s3_client()
    obj = s3.get_object(Bucket=S3_BUCKET, Key=S3_PARQUET_KEY)
    df  = pd.read_parquet(io.BytesIO(obj["Body"].read()))
    logger.info("load_parquet: %d 행 로드 (컬럼: %s)", len(df), list(df.columns))

    def _cvt(v: Any) -> Any:
        if isinstance(v, float) and v != v:  return None
        if isinstance(v, np.integer):        return int(v)
        if isinstance(v, np.floating):       return None if v != v else float(v)
        if isinstance(v, np.ndarray):        return v.tolist()
        if isinstance(v, np.bool_):          return bool(v)
        return v

    raw_sessions: list[dict] = []
    for _, row in df.iterrows():
        rec = {k: _cvt(v) for k, v in row.to_dict().items()}
        if isinstance(rec.get("timeline"), str):
            try:
                rec["timeline"] = json.loads(rec["timeline"])
            except json.JSONDecodeError:
                rec["timeline"] = []
        raw_sessions.append(rec)

    logger.info("load_parquet 완료 — %d 세션", len(raw_sessions))
    ctx["ti"].xcom_push(key="raw_sessions", value=raw_sessions)
    ctx["ti"].xcom_push(key="total_loaded", value=len(raw_sessions))


# ══════════════════════════════════════════════════════════════════════════════
# Task 2 : filter_whitelist
# ══════════════════════════════════════════════════════════════════════════════

def filter_whitelist(**ctx) -> None:
    """
    whitelist.py should_include() 동일 로직:
      1. src_ip 화이트리스트(IP/CIDR) 해당 시 제외
      2. suspicion_score < SUSPICION_THRESHOLD 시 제외
    """
    raw_sessions: list[dict] = ctx["ti"].xcom_pull(
        task_ids="load_parquet", key="raw_sessions"
    ) or []

    passed:   list[dict]     = []
    filtered: dict[str, int] = {"whitelist_ip": 0, "low_score": 0}

    for sess in raw_sessions:
        if _is_whitelisted_session(sess):
            filtered["whitelist_ip"] += 1
            continue
        if _calc_suspicion_score(sess) < SUSPICION_THRESHOLD:
            filtered["low_score"] += 1
            continue
        passed.append(sess)

    logger.info(
        "filter_whitelist: 전체 %d → 통과 %d (화이트리스트 제외 %d, 저점수 제외 %d)",
        len(raw_sessions), len(passed),
        filtered["whitelist_ip"], filtered["low_score"],
    )
    ctx["ti"].xcom_push(key="filtered_sessions", value=passed)
    ctx["ti"].xcom_push(key="filter_stats",       value=filtered)


# ══════════════════════════════════════════════════════════════════════════════
# Task 3 : build_session_gold
# ══════════════════════════════════════════════════════════════════════════════

def build_session_gold(**ctx) -> None:
    """
    필터링된 raw 세션 → session_gold 구조 변환.
    unified_to_gold의 extract_sessions와 동일한 필드/로직 사용.
    위험도 높은 순 정렬 후 MAX_SESSIONS 제한.
    """
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

    # 위험도 높은 순 (severity 낮을수록 위험, alert_count 높을수록 우선)
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
    """
    session_gold의 session_id로 Neo4j 1-hop enrichment (과거 행위).
    UNWIND 배치 쿼리로 왕복 최소화.
    Neo4j에 없는 session_id → neighbors=[] → 현재 세션만으로 RAG 계속 진행.
    """
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
        sid          AS session_id,
        type(r)      AS rel_type,
        labels(n)    AS node_labels,
        n.value      AS node_value,
        n.signature  AS signature,
        n.category   AS category
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
                    "rel_type":    record["rel_type"],
                    "node_labels": record["node_labels"],
                    "node_value":  record["node_value"],
                    "signature":   record["signature"],
                    "category":    record["category"],
                })
                total_edges += 1
    driver.close()

    subgraphs    = [{"session": sess_index[sid], "neighbors": neighbor_map[sid]}
                    for sid in session_ids]
    neo4j_hit    = sum(1 for sid in session_ids if neighbor_map[sid])

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
    """서브그래프 dict → LLM 프롬프트 텍스트."""
    s = subgraph["session"]
    lines = [
        "[현재 세션 정보]",
        f"  session_id   : {s.get('session_id')}",
        f"  src_ip       : {s.get('src_ip')}  →  dst_ip : {s.get('dst_ip')}",
        f"  proto        : {s.get('proto')}       port   : {s.get('dst_port')}",
        f"  alert_count  : {s.get('alert_count')}   max_severity : {s.get('max_severity')}",
        f"  conn_state   : {s.get('conn_state') or 'N/A'}",
        f"  tls_sni      : {s.get('tls_sni') or 'N/A'}",
        f"  http_host    : {s.get('http_host') or 'N/A'}",
        f"  http_uri     : {s.get('http_uri') or 'N/A'}",
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
You are a cybersecurity analyst specializing in network threat detection.
You will be given:
1. Current session attributes (from real-time network logs)
2. Past behavior context from Neo4j graph (may be empty for brand-new sessions)

Analyze and respond ONLY in this JSON format (no markdown, no explanation):
{
  "threat_type": CATEGORY,
  "summary": "<1~2문장 한국어 위협 요약>",
  "recommended_action": "<한 줄 대응 권고>"
}
"""


def run_rag_analysis(**ctx) -> None:
    """서브그래프 텍스트 → Groq LLM 호출 → 분석 결과 수집."""
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

        try:
            response = groq.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": user_text},
                ],
                temperature=0.1,   # 구조화 JSON 출력 → 낮은 temperature 유지
                max_tokens=1024,
            )
            raw = response.choices[0].message.content.strip()
            try:
                analysis = json.loads(raw)
            except json.JSONDecodeError:
                cleaned = raw.replace("```json", "").replace("```", "").strip()
                try:
                    analysis = json.loads(cleaned)
                except json.JSONDecodeError:
                    analysis = {"raw_response": raw, "parse_error": True}

            results.append({"session_id": session_id, "session": sg["session"],
                             "analysis": analysis})

        except Exception as e:
            logger.error("run_rag_analysis: session_id=%s 오류 — %s", session_id, e)
            results.append({"session_id": session_id, "session": sg["session"],
                             "analysis": {"error": str(e)}})

        time.sleep(GROQ_RPM_SLEEP)

    logger.info("run_rag_analysis: %d 건 분석 완료", len(results))
    ctx["ti"].xcom_push(key="rag_results", value=results)


# ══════════════════════════════════════════════════════════════════════════════
# Task 6 : save_rag_results
# ══════════════════════════════════════════════════════════════════════════════

def save_rag_results(**ctx) -> None:
    """분석 결과 → S3 rag_result/rag_results_{datetime}.jsonl 저장 ."""
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
    ti = ctx["ti"]
    total_loaded = ti.xcom_pull(task_ids="load_parquet",     key="total_loaded")   or 0
    filter_stats = ti.xcom_pull(task_ids="filter_whitelist", key="filter_stats")   or {}
    results      = ti.xcom_pull(task_ids="run_rag_analysis", key="rag_results")    or []
    saved_count  = ti.xcom_pull(task_ids="save_rag_results", key="saved_count")    or 0

    threat_dist:     dict[str, int] = {}
    # confidence_dist: dict[str, int] = {}
    error_count = 0

    for r in results:
        a = r.get("analysis", {})
        if a.get("error") or a.get("parse_error"):
            error_count += 1
            continue
        tt = a.get("threat_type", "Unknown")
        # cf = a.get("confidence",  "unknown")
        threat_dist[tt]     = threat_dist.get(tt, 0) + 1
        # confidence_dist[cf] = confidence_dist.get(cf, 0) + 1

    logger.info("=" * 70)
    logger.info("  [입력]  parquet 로드         : %d 세션", total_loaded)
    logger.info("  [필터]  화이트리스트 제외     : %d", filter_stats.get("whitelist_ip", 0))
    logger.info("  [필터]  저점수 제외           : %d", filter_stats.get("low_score", 0))
    logger.info("  [분석]  RAG 분석 세션         : %d", len(results))
    logger.info("  [저장]  S3 저장 건수          : %d", saved_count)
    logger.info("  [오류]  분석 실패             : %d", error_count)
    logger.info("  [위협 유형 분포]")
    for tt, cnt in sorted(threat_dist.items(), key=lambda x: -x[1]):
        logger.info("    %-30s %d", tt, cnt)
    # logger.info("  [신뢰도 분포]")
    # for cf, cnt in sorted(confidence_dist.items(), key=lambda x: -x[1]):
    #     logger.info("    %-10s %d", cf, cnt)
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
    description="실시간 추론 DAG — S3 parquet → whitelist → session_gold → Neo4j enrichment → Groq RAG (v3)",
    default_args=default_args,
    start_date=datetime(2026, 1, 1),
    schedule="*/5 * * * *",   # unified_to_gold와 동일 주기, 완전 독립 실행
    catchup=False,
    max_active_runs=1,
    tags=["graph-rag", "groq"],
) as dag:

    t_load     = PythonOperator(task_id="load_parquet",       python_callable=load_parquet)
    t_filter   = PythonOperator(task_id="filter_whitelist",   python_callable=filter_whitelist)
    t_sessions = PythonOperator(task_id="build_session_gold", python_callable=build_session_gold)
    t_subgraph = PythonOperator(task_id="build_subgraphs",    python_callable=build_subgraphs)
    t_rag      = PythonOperator(task_id="run_rag_analysis",   python_callable=run_rag_analysis)
    t_save     = PythonOperator(task_id="save_rag_results",   python_callable=save_rag_results)
    t_report   = PythonOperator(task_id="report_rag_stats",   python_callable=report_rag_stats)

    t_load >> t_filter >> t_sessions >> t_subgraph >> t_rag >> t_save >> t_report