"""
dag_unified_to_gold.py
S3 unified_events.parquet → session_gold / entity_gold / relation_gold 전처리 DAG

Pipeline:
  [fetch_from_s3]      ← S3 ETag 체크 → skip XCom 전달 (다운로드 없음)
       ↓
  [parquet_to_jsonl]   ← S3 parquet 직접 읽기 → JSONL 변환 → S3 업로드
       ↓
  [validate_input]     ← S3에서 JSONL 다운로드 → 행 수 검증
       ↓
  [extract_sessions]   ← S3에서 JSONL 읽기 → session_gold → S3 업로드
       ↓
  [extract_entities]   ← S3에서 session_gold + JSONL 읽기 → entity_gold → S3 업로드
       ↓
  [extract_relations]  ← S3에서 session_gold + JSONL 읽기 → relation_gold → S3 업로드
       ↓
  [report_stats]       ← S3에서 3개 gold 파일 읽기 → 요약 통계 로그

스키마 (v4 — SSL 포함 전 필드):

  session_gold:
    # 세션 식별
    session_id, community_id
    # conn.log 지정 필드
    src_ip, src_port, dst_ip, dst_port,
    proto, service, duration, orig_bytes, resp_bytes, conn_state,
    missed_bytes, history, orig_pkts, resp_pkts
    # http.log 지정 필드
    http_method, http_host, http_uri, http_user_agent,
    http_request_body_len, http_response_body_len,
    http_status_code, http_status_msg
    # dns.log 지정 필드
    dns_query, dns_qtype_name, dns_rcode_name, dns_answers, dns_rtt
    # ssl.log 지정 필드
    tls_version, tls_cipher, tls_curve, tls_sni,
    tls_ssl_history, tls_established, tls_resumed
    # suricata 전용 (zeek와 비겹치)
    alert_count, max_severity, is_threat,
    flow_state, flow_reason, pkts_toserver, pkts_toclient,
    bytes_toserver, bytes_toclient
    # 시간
    flow_start, flow_end

  entity_gold:
    entity_type(ip|domain|alert), entity_value,
    first_seen, last_seen, related_session_count,
    [ip 전용] total_orig_bytes, total_resp_bytes,
    [alert 전용] signature, category

  relation_gold:
    src_type, src_value, relation_type, dst_type, dst_value, session_id
    relation_type 종류:
      CONNECTED_TO    (ip → ip)
      REQUESTED       (ip → domain)
      TRIGGERED       (session → alert)
      RESOLVED_BY     (domain → ip|domain, DNS answers)
      ENCRYPTED_WITH  (session → tls_cipher)  [신규]
      SERVED_OVER_TLS (session → domain, SNI)  [신규]

Author : Linda
"""

from __future__ import annotations

from airflow.sdk import Asset  # Airflow 3

import io
import json
import logging
import hashlib
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import boto3

from airflow import DAG
from airflow.operators.python import PythonOperator

# ── S3 설정 ───────────────────────────────────────────────────────────────────
S3_BUCKET        = "malware-project-bucket"
S3_KEY           = "unified_events.parquet"
S3_JSONL_KEY     = "unified_events.jsonl"
S3_SESSION_KEY   = "gold/session_gold.jsonl"
S3_ENTITY_KEY    = "gold/entity_gold.jsonl"
S3_RELATION_KEY  = "gold/relation_gold.jsonl"
AWS_REGION       = "ap-northeast-2"

# ── 로컬 임시 경로 ────────────────────────────────────────────────────────────
DATA_DIR     = Path("/opt/airflow/data")
ETAG_PATH    = DATA_DIR / ".last_etag"

# Asset 선언
GOLD_SESSION_ASSET  = Asset("s3://malware-project-bucket/gold/session_gold.jsonl")
GOLD_ENTITY_ASSET   = Asset("s3://malware-project-bucket/gold/entity_gold.jsonl")
GOLD_RELATION_ASSET = Asset("s3://malware-project-bucket/gold/relation_gold.jsonl")

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# 공통 S3 헬퍼
# ══════════════════════════════════════════════════════════════════════════════

def _s3_client():
    return boto3.client("s3")


def _s3_read_jsonl(s3_key: str) -> list[dict]:
    s3 = _s3_client()
    obj = s3.get_object(Bucket=S3_BUCKET, Key=s3_key)
    lines = obj["Body"].read().decode("utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _s3_write_jsonl(s3_key: str, records: list[dict]) -> None:
    s3 = _s3_client()
    body = "\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n"
    s3.put_object(Bucket=S3_BUCKET, Key=s3_key, Body=body.encode("utf-8"))
    logger.info("S3 업로드 완료: s3://%s/%s (%d 레코드)", S3_BUCKET, s3_key, len(records))


# ══════════════════════════════════════════════════════════════════════════════
# Task 0-1 : fetch_from_s3
# ══════════════════════════════════════════════════════════════════════════════

def fetch_from_s3(**ctx) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    s3 = _s3_client()
    head = s3.head_object(Bucket=S3_BUCKET, Key=S3_KEY)
    s3_etag = head["ETag"].strip('"')

    if ETAG_PATH.exists():
        last_etag = ETAG_PATH.read_text().strip()
        if last_etag == s3_etag:
            logger.info("S3 파일 변경 없음 (ETag=%s) — 처리 스킵", s3_etag)
            ctx["ti"].xcom_push(key="skip", value=True)
            return

    ETAG_PATH.write_text(s3_etag)
    logger.info("S3 파일 변경 감지 (ETag=%s) — 처리 시작", s3_etag)
    ctx["ti"].xcom_push(key="skip", value=False)


# ══════════════════════════════════════════════════════════════════════════════
# Task 0-2 : parquet_to_jsonl
# ══════════════════════════════════════════════════════════════════════════════

def parquet_to_jsonl(**ctx) -> None:
    import pandas as pd
    import numpy as np

    skip = ctx["ti"].xcom_pull(task_ids="fetch_from_s3", key="skip")
    if skip:
        logger.info("S3 변경 없음 — parquet 변환 스킵")
        return

    logger.info("S3에서 parquet 직접 로드: s3://%s/%s", S3_BUCKET, S3_KEY)
    s3 = _s3_client()
    obj = s3.get_object(Bucket=S3_BUCKET, Key=S3_KEY)
    df = pd.read_parquet(io.BytesIO(obj["Body"].read()))
    logger.info("  행 수: %d / 컬럼: %s", len(df), list(df.columns))

    def _convert(v):
        if isinstance(v, float) and v != v:
            return None
        if isinstance(v, np.integer):
            return int(v)
        if isinstance(v, np.floating):
            return None if np.isnan(v) else float(v)
        if isinstance(v, np.ndarray):
            return v.tolist()
        if isinstance(v, np.bool_):
            return bool(v)
        return v

    records = []
    for _, row in df.iterrows():
        record = row.to_dict()
        if isinstance(record.get("timeline"), str):
            try:
                record["timeline"] = json.loads(record["timeline"])
            except json.JSONDecodeError:
                record["timeline"] = []
        record = {k: _convert(v) for k, v in record.items()}
        records.append(record)

    _s3_write_jsonl(S3_JSONL_KEY, records)
    logger.info("parquet_to_jsonl 완료 — %d 행 → s3://%s/%s", len(records), S3_BUCKET, S3_JSONL_KEY)
    ctx["ti"].xcom_push(key="jsonl_rows", value=len(records))


# ══════════════════════════════════════════════════════════════════════════════
# 공통 유틸
# ══════════════════════════════════════════════════════════════════════════════

def _make_session_id(community_id: str | None, idx: int) -> str:
    if community_id:
        h = hashlib.sha1(community_id.encode()).hexdigest()[:8]
        return f"s_{h}"
    return f"s_orphan_{idx:04d}"


def _get(ev: dict, *keys: str, default=None) -> Any:
    for k in keys:
        v = ev.get(k)
        if v is not None:
            return v
    return default


def _is_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


# ══════════════════════════════════════════════════════════════════════════════
# Task 1 : validate_input
# ══════════════════════════════════════════════════════════════════════════════

def validate_input(**ctx) -> None:
    skip = ctx["ti"].xcom_pull(task_ids="fetch_from_s3", key="skip")
    if skip:
        logger.info("S3 변경 없음 — validate 스킵")
        return

    s3 = _s3_client()
    obj = s3.get_object(Bucket=S3_BUCKET, Key=S3_JSONL_KEY)
    line_count = sum(1 for line in obj["Body"].iter_lines() if line.strip())

    if line_count == 0:
        raise ValueError("unified_events.jsonl 가 비어 있습니다.")

    logger.info("validate_input OK — 총 %d 행 (s3://%s/%s)", line_count, S3_BUCKET, S3_JSONL_KEY)
    ctx["ti"].xcom_push(key="total_lines", value=line_count)


# ══════════════════════════════════════════════════════════════════════════════
# Task 2 : extract_sessions
# ══════════════════════════════════════════════════════════════════════════════

def _extract_conn(timeline: list[dict]) -> dict:
    """conn.log 지정 필드 추출"""
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
    # fallback: suricata에서 기본 IP/Port만
    for ev in timeline:
        if ev.get("source") == "suricata":
            return {
                "src_ip":       ev.get("src_ip"),
                "src_port":     str(ev.get("src_port", "")),
                "dst_ip":       ev.get("dest_ip"),
                "dst_port":     str(ev.get("dest_port", "")),
                "proto":        ev.get("proto", "").lower(),
                "service":      None,
                "duration":     None,
                "orig_bytes":   None,
                "resp_bytes":   None,
                "conn_state":   None,
                "missed_bytes": None,
                "history":      None,
                "orig_pkts":    None,
                "resp_pkts":    None,
            }
    return {}


def _extract_http(timeline: list[dict]) -> dict:
    """http.log 지정 필드 추출"""
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
    return {k: None for k in [
        "http_method", "http_host", "http_uri", "http_user_agent",
        "http_request_body_len", "http_response_body_len",
        "http_status_code", "http_status_msg",
    ]}


def _extract_dns(timeline: list[dict]) -> dict:
    """dns.log 지정 필드 추출 (첫 번째 DNS 이벤트 기준)"""
    for ev in timeline:
        if ev.get("source") == "zeek_dns":
            return {
                "dns_query":      ev.get("query"),
                "dns_qtype_name": ev.get("qtype_name"),
                "dns_rcode_name": ev.get("rcode_name"),
                "dns_answers":    ev.get("answers"),
                "dns_rtt":        ev.get("rtt"),
            }
    return {k: None for k in [
        "dns_query", "dns_qtype_name", "dns_rcode_name", "dns_answers", "dns_rtt"
    ]}


def _extract_ssl(timeline: list[dict]) -> dict:
    """ssl.log 지정 필드 추출"""
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
    return {k: None for k in [
        "tls_version", "tls_cipher", "tls_curve", "tls_sni",
        "tls_ssl_history", "tls_established", "tls_resumed"
    ]}


def _extract_suricata_stats(timeline: list[dict]) -> dict:
    """suricata 전용 필드 (zeek와 비겹치)"""
    alerts = [ev for ev in timeline
              if ev.get("source") == "suricata" and ev.get("signature")]
    alert_count = len(alerts)
    max_sev = min((int(a["severity"]) for a in alerts
                   if a.get("severity") is not None), default=None)

    # 첫 번째 flow 이벤트에서 통계 추출
    flow_state = flow_reason = None
    pkts_toserver = pkts_toclient = bytes_toserver = bytes_toclient = None
    for ev in timeline:
        if ev.get("source") == "suricata":
            flow_state    = ev.get("flow_state")
            flow_reason   = ev.get("flow_reason")
            pkts_toserver  = ev.get("pkts_toserver")
            pkts_toclient  = ev.get("pkts_toclient")
            bytes_toserver = ev.get("bytes_toserver")
            bytes_toclient = ev.get("bytes_toclient")
            break

    return {
        "alert_count":    alert_count,
        "max_severity":   max_sev,
        "flow_state":     flow_state,
        "flow_reason":    flow_reason,
        "pkts_toserver":  pkts_toserver,
        "pkts_toclient":  pkts_toclient,
        "bytes_toserver": bytes_toserver,
        "bytes_toclient": bytes_toclient,
    }


def extract_sessions(**ctx) -> None:
    """S3에서 JSONL 읽기 → session_gold 생성 → S3 업로드"""
    skip = ctx["ti"].xcom_pull(task_ids="fetch_from_s3", key="skip")
    if skip:
        logger.info("S3 변경 없음 — extract_sessions 스킵")
        return

    raw_sessions = _s3_read_jsonl(S3_JSONL_KEY)

    seen_cids: dict[str, str] = {}
    orphan_idx = 0
    records: list[dict] = []

    for session in raw_sessions:
        cid = session.get("community_id")

        if cid and cid in seen_cids:
            session_id = seen_cids[cid]
        else:
            if cid:
                session_id = _make_session_id(cid, 0)
                seen_cids[cid] = session_id
            else:
                session_id = _make_session_id(None, orphan_idx)
                orphan_idx += 1

        timeline = session.get("timeline", [])

        conn  = _extract_conn(timeline)
        http  = _extract_http(timeline)
        dns   = _extract_dns(timeline)
        ssl   = _extract_ssl(timeline)
        suri  = _extract_suricata_stats(timeline)

        final_alert_count = session.get("alert_count", suri["alert_count"])

        records.append({
            # ── 세션 식별 ──
            "session_id":   session_id,
            "community_id": cid,
            # ── conn.log 지정 필드 ──
            "src_ip":       conn.get("src_ip"),
            "src_port":     conn.get("src_port"),
            "dst_ip":       conn.get("dst_ip"),
            "dst_port":     conn.get("dst_port"),
            "proto":        conn.get("proto"),
            "service":      conn.get("service"),
            "duration":     conn.get("duration"),
            "orig_bytes":   conn.get("orig_bytes"),
            "resp_bytes":   conn.get("resp_bytes"),
            "conn_state":   conn.get("conn_state"),
            "missed_bytes": conn.get("missed_bytes"),
            "history":      conn.get("history"),
            "orig_pkts":    conn.get("orig_pkts"),
            "resp_pkts":    conn.get("resp_pkts"),
            # ── http.log 지정 필드 ──
            **http,
            # ── dns.log 지정 필드 ──
            **dns,
            # ── ssl.log 지정 필드 ──
            **ssl,
            # ── suricata 전용 ──
            "alert_count":    final_alert_count,
            "max_severity":   suri["max_severity"],
            "is_threat":      session.get("is_threat", False),
            "flow_state":     suri["flow_state"],
            "flow_reason":    suri["flow_reason"],
            "pkts_toserver":  suri["pkts_toserver"],
            "pkts_toclient":  suri["pkts_toclient"],
            "bytes_toserver": suri["bytes_toserver"],
            "bytes_toclient": suri["bytes_toclient"],
            # ── 시간 ──
            "flow_start": session.get("flow_start"),
            "flow_end":   session.get("flow_end"),
        })

    _s3_write_jsonl(S3_SESSION_KEY, records)
    logger.info("extract_sessions 완료 — %d 세션 → s3://%s/%s", len(records), S3_BUCKET, S3_SESSION_KEY)
    ctx["ti"].xcom_push(key="session_count", value=len(records))


# ══════════════════════════════════════════════════════════════════════════════
# Task 3 : extract_entities
# ══════════════════════════════════════════════════════════════════════════════

def extract_entities(**ctx) -> None:
    """S3에서 session_gold + JSONL 읽기 → entity_gold 생성 → S3 업로드"""
    skip = ctx["ti"].xcom_pull(task_ids="fetch_from_s3", key="skip")
    if skip:
        logger.info("S3 변경 없음 — extract_entities 스킵")
        return

    sessions = _s3_read_jsonl(S3_SESSION_KEY)
    raw      = _s3_read_jsonl(S3_JSONL_KEY)

    ip_bucket:     dict[str, dict] = {}
    domain_bucket: dict[str, dict] = {}
    alert_bucket:  dict[str, dict] = {}

    def _update_ip(ip, ts, session_id, orig_bytes=0, resp_bytes=0):
        if not ip:
            return
        b = ip_bucket.setdefault(ip, {
            "first_seen": ts, "last_seen": ts,
            "sessions": set(), "orig_bytes": 0, "resp_bytes": 0,
        })
        if ts:
            if not b["first_seen"] or ts < b["first_seen"]: b["first_seen"] = ts
            if not b["last_seen"]  or ts > b["last_seen"]:  b["last_seen"]  = ts
        b["sessions"].add(session_id)
        b["orig_bytes"] += orig_bytes
        b["resp_bytes"] += resp_bytes

    def _update_domain(domain, ts, session_id):
        if not domain:
            return
        b = domain_bucket.setdefault(domain, {
            "first_seen": ts, "last_seen": ts, "sessions": set(),
        })
        if ts:
            if not b["first_seen"] or ts < b["first_seen"]: b["first_seen"] = ts
            if not b["last_seen"]  or ts > b["last_seen"]:  b["last_seen"]  = ts
        b["sessions"].add(session_id)

    def _update_alert(sig_id, sig, category, severity, ts, session_id):
        if not sig_id and not sig:
            return
        key = str(sig_id or sig)
        b = alert_bucket.setdefault(key, {
            "first_seen": ts, "last_seen": ts,
            "sessions": set(), "signature": sig,
            "signature_id": sig_id, "category": category,
        })
        if ts:
            if not b["first_seen"] or ts < b["first_seen"]: b["first_seen"] = ts
            if not b["last_seen"]  or ts > b["last_seen"]:  b["last_seen"]  = ts
        b["sessions"].add(session_id)

    for sess in sessions:
        sid      = sess["session_id"]
        ts_start = sess.get("flow_start")

        _update_ip(sess.get("src_ip"), ts_start, sid)
        _update_ip(sess.get("dst_ip"), ts_start, sid)

        http_host = sess.get("http_host")
        if http_host:
            if _is_ip(http_host):
                _update_ip(http_host, ts_start, sid)
            else:
                _update_domain(http_host, ts_start, sid)

        # SSL SNI → domain
        tls_sni = sess.get("tls_sni")
        if tls_sni:
            _update_domain(tls_sni, ts_start, sid)

        # DNS query → domain
        dns_query = sess.get("dns_query")
        if dns_query:
            _update_domain(dns_query, ts_start, sid)

    cid_to_sid = {s["community_id"]: s["session_id"]
                  for s in sessions if s.get("community_id")}

    for raw_sess in raw:
        cid = raw_sess.get("community_id")
        sid = cid_to_sid.get(cid, "unknown")
        for ev in raw_sess.get("timeline", []):
            source = ev.get("source")
            ts = ev.get("ts")
            if source == "zeek_conn":
                orig_b = int(ev.get("orig_bytes") or 0)
                resp_b = int(ev.get("resp_bytes") or 0)
                _update_ip(ev.get("orig_h"), ts, sid, orig_b, 0)
                _update_ip(ev.get("resp_h"), ts, sid, 0, resp_b)
            elif source == "zeek_dns":
                _update_domain(ev.get("query"), ts, sid)
                answers_raw = ev.get("answers")
                if answers_raw:
                    for ans in str(answers_raw).split(","):
                        ans = ans.strip()
                        parts = ans.split(".")
                        if len(parts) == 4 and all(p.isdigit() for p in parts):
                            _update_ip(ans, ts, sid)
                        elif ans:
                            _update_domain(ans, ts, sid)
            elif source == "zeek_ssl":
                # SSL SNI를 domain 엔티티로 등록
                sni = ev.get("server_name")
                if sni:
                    _update_domain(sni, ts, sid)
            elif source == "suricata":
                if ev.get("signature"):
                    _update_alert(
                        ev.get("signature_id"), ev.get("signature"),
                        ev.get("category"),    ev.get("severity"),
                        ts, sid,
                    )

    records: list[dict] = []
    for ip, b in ip_bucket.items():
        records.append({
            "entity_type":           "ip",
            "entity_value":          ip,
            "first_seen":            b["first_seen"],
            "last_seen":             b["last_seen"],
            "related_session_count": len(b["sessions"]),
            "total_orig_bytes":      b["orig_bytes"],
            "total_resp_bytes":      b["resp_bytes"],
            "signature":             None,
            "category":              None,
        })
    for domain, b in domain_bucket.items():
        records.append({
            "entity_type":           "domain",
            "entity_value":          domain,
            "first_seen":            b["first_seen"],
            "last_seen":             b["last_seen"],
            "related_session_count": len(b["sessions"]),
            "total_orig_bytes":      None,
            "total_resp_bytes":      None,
            "signature":             None,
            "category":              None,
        })
    for key, b in alert_bucket.items():
        records.append({
            "entity_type":           "alert",
            "entity_value":          key,
            "first_seen":            b["first_seen"],
            "last_seen":             b["last_seen"],
            "related_session_count": len(b["sessions"]),
            "total_orig_bytes":      None,
            "total_resp_bytes":      None,
            "signature":             b["signature"],
            "category":              b["category"],
        })

    _s3_write_jsonl(S3_ENTITY_KEY, records)
    logger.info(
        "extract_entities 완료 — ip:%d domain:%d alert:%d → s3://%s/%s",
        len(ip_bucket), len(domain_bucket), len(alert_bucket), S3_BUCKET, S3_ENTITY_KEY,
    )
    ctx["ti"].xcom_push(key="entity_count", value=len(records))


# ══════════════════════════════════════════════════════════════════════════════
# Task 4 : extract_relations
# ══════════════════════════════════════════════════════════════════════════════

def extract_relations(**ctx) -> None:
    """S3에서 session_gold + JSONL 읽기 → relation_gold 생성 → S3 업로드"""
    skip = ctx["ti"].xcom_pull(task_ids="fetch_from_s3", key="skip")
    if skip:
        logger.info("S3 변경 없음 — extract_relations 스킵")
        return

    sessions = _s3_read_jsonl(S3_SESSION_KEY)
    raw      = _s3_read_jsonl(S3_JSONL_KEY)

    cid_to_sid = {s["community_id"]: s["session_id"]
                  for s in sessions if s.get("community_id")}

    seen: set[tuple] = set()
    records: list[dict] = []

    def _add(src_type, src_val, rel, dst_type, dst_val, sid):
        if not src_val or not dst_val:
            return
        key = (src_type, src_val, rel, dst_type, dst_val, sid)
        if key in seen:
            return
        seen.add(key)
        records.append({
            "src_type":      src_type,
            "src_value":     src_val,
            "relation_type": rel,
            "dst_type":      dst_type,
            "dst_value":     dst_val,
            "session_id":    sid,
        })

    for sess in sessions:
        sid       = sess["session_id"]
        src_ip    = sess.get("src_ip")
        dst_ip    = sess.get("dst_ip")
        http_host = sess.get("http_host")
        tls_sni   = sess.get("tls_sni")
        tls_cipher = sess.get("tls_cipher")
        dns_query  = sess.get("dns_query")
        dns_answers = sess.get("dns_answers")

        # ip → ip 연결
        _add("ip", src_ip, "CONNECTED_TO", "ip", dst_ip, sid)

        # HTTP host 요청
        if http_host:
            dst_type = "ip" if _is_ip(http_host) else "domain"
            _add("ip", src_ip, "REQUESTED", dst_type, http_host, sid)

        # SSL SNI: session → domain (SERVED_OVER_TLS) [신규]
        if tls_sni:
            _add("ip", src_ip, "REQUESTED", "domain", tls_sni, sid)
            _add("session", sid, "SERVED_OVER_TLS", "domain", tls_sni, sid)

        # SSL cipher: session → cipher string (ENCRYPTED_WITH) [신규]
        if tls_cipher:
            _add("session", sid, "ENCRYPTED_WITH", "cipher", tls_cipher, sid)

        # DNS query → domain
        if dns_query:
            _add("ip", src_ip, "REQUESTED", "domain", dns_query, sid)
            # DNS answers
            if dns_answers:
                for ans in str(dns_answers).split(","):
                    ans = ans.strip()
                    if not ans:
                        continue
                    parts = ans.split(".")
                    if len(parts) == 4 and all(p.isdigit() for p in parts):
                        _add("domain", dns_query, "RESOLVED_BY", "ip", ans, sid)
                    elif ans != dns_query:
                        _add("domain", dns_query, "RESOLVED_BY", "domain", ans, sid)

    for raw_sess in raw:
        cid = raw_sess.get("community_id")
        sid = cid_to_sid.get(cid, "unknown")
        for ev in raw_sess.get("timeline", []):
            source = ev.get("source")
            if source == "zeek_dns":
                query       = ev.get("query")
                answers_raw = ev.get("answers")
                orig_h      = ev.get("orig_h")
                if orig_h and query:
                    _add("ip", orig_h, "REQUESTED", "domain", query, sid)
                if query and answers_raw:
                    for ans in str(answers_raw).split(","):
                        ans = ans.strip()
                        parts = ans.split(".")
                        if len(parts) == 4 and all(p.isdigit() for p in parts):
                            _add("domain", query, "RESOLVED_BY", "ip", ans, sid)
                        elif ans and ans != query:
                            _add("domain", query, "RESOLVED_BY", "domain", ans, sid)
            elif source == "zeek_ssl":
                # SSL 관계 (raw timeline에서도 보강)
                sni    = ev.get("server_name")
                cipher = ev.get("cipher")
                orig_h = ev.get("orig_h")
                if sni:
                    _add("session", sid, "SERVED_OVER_TLS", "domain", sni, sid)
                if cipher:
                    _add("session", sid, "ENCRYPTED_WITH", "cipher", cipher, sid)
            elif source == "suricata" and ev.get("signature"):
                sig_key = str(ev.get("signature_id") or ev.get("signature"))
                _add("session", sid, "TRIGGERED", "alert", sig_key, sid)

    _s3_write_jsonl(S3_RELATION_KEY, records)
    logger.info("extract_relations 완료 — %d 관계 → s3://%s/%s", len(records), S3_BUCKET, S3_RELATION_KEY)
    ctx["ti"].xcom_push(key="relation_count", value=len(records))


# ══════════════════════════════════════════════════════════════════════════════
# Task 5 : report_stats
# ══════════════════════════════════════════════════════════════════════════════

def report_stats(**ctx) -> None:
    # skip 여부와 무관하게 outlet_events는 항상 emit
    # skip=True일 때도 gold_to_neo4j 트리거가 되어야 하기 때문
    # (S3 파일 미변경 = gold도 그대로 = neo4j 재적재 불필요하지만 의존성 체인은 유지)
    outlet_events = ctx.get("outlet_events")
    if outlet_events is not None:
        outlet_events[GOLD_SESSION_ASSET].add(extra={"source": "unified_to_gold"})
        outlet_events[GOLD_ENTITY_ASSET].add(extra={"source": "unified_to_gold"})
        outlet_events[GOLD_RELATION_ASSET].add(extra={"source": "unified_to_gold"})

    skip = ctx["ti"].xcom_pull(task_ids="fetch_from_s3", key="skip")
    if skip:
        logger.info("S3 변경 없음 — gold 재처리 스킵 (Asset event는 발행 완료)")
        return

    ti = ctx["ti"]
    total_lines    = ti.xcom_pull(task_ids="validate_input",   key="total_lines")
    session_count  = ti.xcom_pull(task_ids="extract_sessions", key="session_count")
    entity_count   = ti.xcom_pull(task_ids="extract_entities", key="entity_count")
    relation_count = ti.xcom_pull(task_ids="extract_relations", key="relation_count")

    sessions  = _s3_read_jsonl(S3_SESSION_KEY)
    entities  = _s3_read_jsonl(S3_ENTITY_KEY)
    relations = _s3_read_jsonl(S3_RELATION_KEY)

    entity_types: dict[str, int] = defaultdict(int)
    for e in entities:
        entity_types[e["entity_type"]] += 1

    rel_types: dict[str, int] = defaultdict(int)
    for r in relations:
        rel_types[r["relation_type"]] += 1

    threat_count = sum(1 for s in sessions if s.get("is_threat"))
    tls_count    = sum(1 for s in sessions if s.get("tls_sni") or s.get("tls_cipher"))

    logger.info("=" * 65)
    logger.info("▶ Gold 전처리 파이프라인 완료 요약 (v4 — SSL 포함)")
    logger.info("=" * 65)
    logger.info("  [Input]  unified_events.jsonl : %s 행", total_lines)
    logger.info("  [Output] session_gold         : %s 세션 (위협 %s개, %.1f%% / TLS %s개)",
                session_count, threat_count,
                100 * threat_count / session_count if session_count else 0,
                tls_count)
    logger.info("  [Output] entity_gold          : %s 엔티티", entity_count)
    for etype, cnt in entity_types.items():
        logger.info("             ├ %-8s : %s", etype, cnt)
    logger.info("  [Output] relation_gold        : %s 관계", relation_count)
    for rtype, cnt in rel_types.items():
        logger.info("             ├ %-25s : %s", rtype, cnt)
    logger.info("=" * 65)
    logger.info("  session_gold  → s3://%s/%s", S3_BUCKET, S3_SESSION_KEY)
    logger.info("  entity_gold   → s3://%s/%s", S3_BUCKET, S3_ENTITY_KEY)
    logger.info("  relation_gold → s3://%s/%s", S3_BUCKET, S3_RELATION_KEY)
    logger.info("=" * 65)


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
    dag_id="unified_events_to_gold_2",
    description="S3 parquet → session/entity/relation gold 전처리 (5분 주기)",
    default_args=default_args,
    start_date=datetime(2026, 1, 1),
    schedule="*/5 * * * *",
    catchup=False,
    max_active_runs=1,
    tags=["cti", "graph-rag", "preprocessing"],
) as dag:

    t_fetch = PythonOperator(
        task_id="fetch_from_s3",
        python_callable=fetch_from_s3,
    )
    t_convert = PythonOperator(
        task_id="parquet_to_jsonl",
        python_callable=parquet_to_jsonl,
    )
    t_validate = PythonOperator(
        task_id="validate_input",
        python_callable=validate_input,
    )
    t_sessions = PythonOperator(
        task_id="extract_sessions",
        python_callable=extract_sessions,
    )
    t_entities = PythonOperator(
        task_id="extract_entities",
        python_callable=extract_entities,
    )
    t_relations = PythonOperator(
        task_id="extract_relations",
        python_callable=extract_relations,
    )
    t_report = PythonOperator(
        task_id="report_stats",
        python_callable=report_stats,
        outlets=[GOLD_SESSION_ASSET, GOLD_ENTITY_ASSET, GOLD_RELATION_ASSET],
    )

    t_fetch >> t_convert >> t_validate >> t_sessions >> t_entities >> t_relations >> t_report