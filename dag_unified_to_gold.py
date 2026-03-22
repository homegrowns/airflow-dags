"""
dag_unified_to_gold.py
S3 unified_events.parquet → session_gold / entity_gold / relation_gold 전처리 DAG

[v5 변경점]
  - session_gold에 uid 필드 추가 (conn.log uid, 원본 역추적용)
  - dst_ip / dst_port → dest_ip / dest_port 필드명 통일
    (preprocess.py v6 겉 틀 및 dag_gold_to_neo4j와 일관성)

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

스키마 (v5):
  session_gold:
    session_id, community_id, uid,          ← [신규 v5]
    src_ip, src_port, dest_ip, dest_port,   ← [v5] dst_* → dest_*
    proto, service, duration, orig_bytes, resp_bytes, conn_state,
    missed_bytes, history, orig_pkts, resp_pkts,
    http_method, http_host, http_uri, http_user_agent,
    http_request_body_len, http_response_body_len, http_status_code, http_status_msg,
    dns_query, dns_qtype_name, dns_rcode_name, dns_answers, dns_rtt,
    tls_version, tls_cipher, tls_curve, tls_sni,
    tls_ssl_history, tls_established, tls_resumed,
    alert_count, max_severity, is_threat,
    flow_state, flow_reason, pkts_toserver, pkts_toclient,
    bytes_toserver, bytes_toclient,
    flow_start, flow_end

Author : Linda
"""

from __future__ import annotations

from airflow.sdk import Asset

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

DATA_DIR   = Path("/opt/airflow/data")
ETAG_PATH  = DATA_DIR / ".last_etag"

GOLD_SESSION_ASSET  = Asset("s3://malware-project-bucket/gold/session_gold.jsonl")
GOLD_ENTITY_ASSET   = Asset("s3://malware-project-bucket/gold/entity_gold.jsonl")
GOLD_RELATION_ASSET = Asset("s3://malware-project-bucket/gold/relation_gold.jsonl")

logger = logging.getLogger(__name__)


# ── 공통 S3 헬퍼 ──────────────────────────────────────────────────────────────

def _s3_client():
    return boto3.client("s3")

def _s3_read_jsonl(s3_key: str) -> list[dict]:
    s3  = _s3_client()
    obj = s3.get_object(Bucket=S3_BUCKET, Key=s3_key)
    return [json.loads(line) for line in obj["Body"].read().decode("utf-8").splitlines() if line.strip()]

def _s3_write_jsonl(s3_key: str, records: list[dict]) -> None:
    s3   = _s3_client()
    body = "\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n"
    s3.put_object(Bucket=S3_BUCKET, Key=s3_key, Body=body.encode("utf-8"))
    logger.info("S3 업로드 완료: s3://%s/%s (%d 레코드)", S3_BUCKET, s3_key, len(records))


# ── Task 0-1 : fetch_from_s3 ──────────────────────────────────────────────────

def fetch_from_s3(**ctx) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    s3      = _s3_client()
    head    = s3.head_object(Bucket=S3_BUCKET, Key=S3_KEY)
    s3_etag = head["ETag"].strip('"')

    if ETAG_PATH.exists():
        if ETAG_PATH.read_text().strip() == s3_etag:
            logger.info("S3 파일 변경 없음 (ETag=%s) — 처리 스킵", s3_etag)
            ctx["ti"].xcom_push(key="skip", value=True)
            return

    ETAG_PATH.write_text(s3_etag)
    logger.info("S3 파일 변경 감지 (ETag=%s) — 처리 시작", s3_etag)
    ctx["ti"].xcom_push(key="skip", value=False)


# ── Task 0-2 : parquet_to_jsonl ───────────────────────────────────────────────

def parquet_to_jsonl(**ctx) -> None:
    import pandas as pd
    import numpy as np

    if ctx["ti"].xcom_pull(task_ids="fetch_from_s3", key="skip"):
        logger.info("S3 변경 없음 — parquet 변환 스킵")
        return

    s3  = _s3_client()
    obj = s3.get_object(Bucket=S3_BUCKET, Key=S3_KEY)
    df  = pd.read_parquet(io.BytesIO(obj["Body"].read()))
    logger.info("  행 수: %d / 컬럼: %s", len(df), list(df.columns))

    def _convert(v):
        if isinstance(v, float) and v != v:  return None
        if isinstance(v, np.integer):         return int(v)
        if isinstance(v, np.floating):        return None if np.isnan(v) else float(v)
        if isinstance(v, np.ndarray):         return v.tolist()
        if isinstance(v, np.bool_):           return bool(v)
        return v

    records = []
    for _, row in df.iterrows():
        record = row.to_dict()
        if isinstance(record.get("timeline"), str):
            try:
                record["timeline"] = json.loads(record["timeline"])
            except json.JSONDecodeError:
                record["timeline"] = []
        records.append({k: _convert(v) for k, v in record.items()})

    _s3_write_jsonl(S3_JSONL_KEY, records)
    logger.info("parquet_to_jsonl 완료 — %d 행", len(records))
    ctx["ti"].xcom_push(key="jsonl_rows", value=len(records))


# ── 공통 유틸 ─────────────────────────────────────────────────────────────────

def _make_session_id(community_id: str | None, idx: int) -> str:
    if community_id:
        return f"s_{hashlib.sha1(community_id.encode()).hexdigest()[:8]}"
    return f"s_orphan_{idx:04d}"

def _is_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


# ── Task 1 : validate_input ───────────────────────────────────────────────────

def validate_input(**ctx) -> None:
    if ctx["ti"].xcom_pull(task_ids="fetch_from_s3", key="skip"):
        logger.info("S3 변경 없음 — validate 스킵")
        return
    s3         = _s3_client()
    obj        = s3.get_object(Bucket=S3_BUCKET, Key=S3_JSONL_KEY)
    line_count = sum(1 for line in obj["Body"].iter_lines() if line.strip())
    if line_count == 0:
        raise ValueError("unified_events.jsonl 가 비어 있습니다.")
    logger.info("validate_input OK — 총 %d 행", line_count)
    ctx["ti"].xcom_push(key="total_lines", value=line_count)


# ── Task 2 : extract_sessions ─────────────────────────────────────────────────

def _extract_conn(timeline: list[dict]) -> dict:
    for ev in timeline:
        if ev.get("source") == "zeek_conn":
            return {
                "uid":          ev.get("uid"),          # [신규 v5]
                "ts":           ev.get("ts"),
                "src_ip":       ev.get("orig_h"),
                "src_port":     ev.get("orig_p"),
                "dest_ip":      ev.get("resp_h"),       # [v5] dst_ip → dest_ip
                "dest_port":    ev.get("resp_p"),       # [v5] dst_port → dest_port
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
                "uid":          None,
                "src_ip":       ev.get("src_ip"),
                "src_port":     str(ev.get("src_port", "")),
                "dest_ip":      ev.get("dest_ip"),
                "dest_port":    str(ev.get("dest_port", "")),
                "proto":        ev.get("proto", "").lower(),
                **{k: None for k in ["service","duration","orig_bytes","resp_bytes",
                                     "conn_state","missed_bytes","history","orig_pkts","resp_pkts"]},
            }
    return {}

def _extract_http(timeline: list[dict]) -> dict:
    _null = {k: None for k in ["http_method","http_host","http_uri","http_user_agent",
                                "http_request_body_len","http_response_body_len",
                                "http_status_code","http_status_msg"]}
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
    _null = {k: None for k in ["dns_query","dns_qtype_name","dns_rcode_name","dns_answers","dns_rtt"]}
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
    _null = {k: None for k in ["tls_version","tls_cipher","tls_curve","tls_sni",
                                "tls_ssl_history","tls_established","tls_resumed"]}
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
    alerts    = [ev for ev in timeline if ev.get("source") == "suricata" and ev.get("signature")]
    alert_cnt = len(alerts)
    max_sev   = min((int(a["severity"]) for a in alerts if a.get("severity") is not None), default=None)
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

def extract_sessions(**ctx) -> None:
    if ctx["ti"].xcom_pull(task_ids="fetch_from_s3", key="skip"):
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
        elif cid:
            session_id = _make_session_id(cid, 0)
            seen_cids[cid] = session_id
        else:
            session_id = _make_session_id(None, orphan_idx)
            orphan_idx += 1

        timeline = session.get("timeline", [])
        conn = _extract_conn(timeline)
        http = _extract_http(timeline)
        dns  = _extract_dns(timeline)
        ssl  = _extract_ssl(timeline)
        suri = _extract_suricata_stats(timeline)

        records.append({
            "session_id":   session_id,
            "community_id": cid,
            "uid":          conn.get("uid"),            # [신규 v5]
            "src_ip":       conn.get("src_ip"),
            "src_port":     conn.get("src_port"),
            "dest_ip":      conn.get("dest_ip"),        # [v5]
            "dest_port":    conn.get("dest_port"),      # [v5]
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
            **http,
            **dns,
            **ssl,
            "alert_count":    session.get("alert_count", suri["alert_count"]),
            "max_severity":   suri["max_severity"],
            "is_threat":      session.get("is_threat", False),
            "flow_state":     suri["flow_state"],
            "flow_reason":    suri["flow_reason"],
            "pkts_toserver":  suri["pkts_toserver"],
            "pkts_toclient":  suri["pkts_toclient"],
            "bytes_toserver": suri["bytes_toserver"],
            "bytes_toclient": suri["bytes_toclient"],
            "flow_start":     session.get("flow_start"),
            "flow_end":       session.get("flow_end"),
        })

    _s3_write_jsonl(S3_SESSION_KEY, records)
    logger.info("extract_sessions 완료 — %d 세션", len(records))
    ctx["ti"].xcom_push(key="session_count", value=len(records))


# ── Task 3 : extract_entities ─────────────────────────────────────────────────

def extract_entities(**ctx) -> None:
    if ctx["ti"].xcom_pull(task_ids="fetch_from_s3", key="skip"):
        logger.info("S3 변경 없음 — extract_entities 스킵")
        return

    sessions = _s3_read_jsonl(S3_SESSION_KEY)
    raw      = _s3_read_jsonl(S3_JSONL_KEY)

    ip_bucket:     dict[str, dict] = {}
    domain_bucket: dict[str, dict] = {}
    alert_bucket:  dict[str, dict] = {}

    def _update_ip(ip, ts, sid, orig=0, resp=0):
        if not ip: return
        b = ip_bucket.setdefault(ip, {"first_seen": ts, "last_seen": ts, "sessions": set(), "orig_bytes": 0, "resp_bytes": 0})
        if ts:
            if not b["first_seen"] or ts < b["first_seen"]: b["first_seen"] = ts
            if not b["last_seen"]  or ts > b["last_seen"]:  b["last_seen"]  = ts
        b["sessions"].add(sid)
        b["orig_bytes"] += orig
        b["resp_bytes"] += resp

    def _update_domain(domain, ts, sid):
        if not domain: return
        b = domain_bucket.setdefault(domain, {"first_seen": ts, "last_seen": ts, "sessions": set()})
        if ts:
            if not b["first_seen"] or ts < b["first_seen"]: b["first_seen"] = ts
            if not b["last_seen"]  or ts > b["last_seen"]:  b["last_seen"]  = ts
        b["sessions"].add(sid)

    def _update_alert(sig_id, sig, category, severity, ts, sid):
        if not sig_id and not sig: return
        key = str(sig_id or sig)
        b = alert_bucket.setdefault(key, {"first_seen": ts, "last_seen": ts, "sessions": set(),
                                          "signature": sig, "signature_id": sig_id, "category": category})
        if ts:
            if not b["first_seen"] or ts < b["first_seen"]: b["first_seen"] = ts
            if not b["last_seen"]  or ts > b["last_seen"]:  b["last_seen"]  = ts
        b["sessions"].add(sid)

    for sess in sessions:
        sid = sess["session_id"]
        ts  = sess.get("flow_start")
        _update_ip(sess.get("src_ip"),  ts, sid)
        _update_ip(sess.get("dest_ip"), ts, sid)   # [v5] dst_ip → dest_ip
        http_host = sess.get("http_host")
        if http_host:
            (_update_ip if _is_ip(http_host) else _update_domain)(http_host, ts, sid)
        if sess.get("tls_sni"):   _update_domain(sess["tls_sni"],   ts, sid)
        if sess.get("dns_query"): _update_domain(sess["dns_query"], ts, sid)

    cid_to_sid = {s["community_id"]: s["session_id"] for s in sessions if s.get("community_id")}

    for raw_sess in raw:
        sid = cid_to_sid.get(raw_sess.get("community_id"), "unknown")
        for ev in raw_sess.get("timeline", []):
            source = ev.get("source")
            ts     = ev.get("ts")
            if source == "zeek_conn":
                _update_ip(ev.get("orig_h"), ts, sid, int(ev.get("orig_bytes") or 0), 0)
                _update_ip(ev.get("resp_h"), ts, sid, 0, int(ev.get("resp_bytes") or 0))
            elif source == "zeek_dns":
                _update_domain(ev.get("query"), ts, sid)
                answers_raw = ev.get("answers")
                if answers_raw:
                    for ans in str(answers_raw).split(","):
                        ans = ans.strip()
                        parts = ans.split(".")
                        (_update_ip if (len(parts)==4 and all(p.isdigit() for p in parts)) else _update_domain)(ans, ts, sid) if ans else None
            elif source == "zeek_ssl":
                if ev.get("server_name"): _update_domain(ev["server_name"], ts, sid)
            elif source == "suricata" and ev.get("signature"):
                _update_alert(ev.get("signature_id"), ev.get("signature"),
                              ev.get("category"), ev.get("severity"), ts, sid)

    records: list[dict] = []
    for ip, b in ip_bucket.items():
        records.append({"entity_type":"ip","entity_value":ip,"first_seen":b["first_seen"],"last_seen":b["last_seen"],
                        "related_session_count":len(b["sessions"]),"total_orig_bytes":b["orig_bytes"],
                        "total_resp_bytes":b["resp_bytes"],"signature":None,"category":None})
    for domain, b in domain_bucket.items():
        records.append({"entity_type":"domain","entity_value":domain,"first_seen":b["first_seen"],"last_seen":b["last_seen"],
                        "related_session_count":len(b["sessions"]),"total_orig_bytes":None,"total_resp_bytes":None,
                        "signature":None,"category":None})
    for key, b in alert_bucket.items():
        records.append({"entity_type":"alert","entity_value":key,"first_seen":b["first_seen"],"last_seen":b["last_seen"],
                        "related_session_count":len(b["sessions"]),"total_orig_bytes":None,"total_resp_bytes":None,
                        "signature":b["signature"],"category":b["category"]})

    _s3_write_jsonl(S3_ENTITY_KEY, records)
    logger.info("extract_entities 완료 — ip:%d domain:%d alert:%d", len(ip_bucket), len(domain_bucket), len(alert_bucket))
    ctx["ti"].xcom_push(key="entity_count", value=len(records))


# ── Task 4 : extract_relations ────────────────────────────────────────────────

def extract_relations(**ctx) -> None:
    if ctx["ti"].xcom_pull(task_ids="fetch_from_s3", key="skip"):
        logger.info("S3 변경 없음 — extract_relations 스킵")
        return

    sessions   = _s3_read_jsonl(S3_SESSION_KEY)
    raw        = _s3_read_jsonl(S3_JSONL_KEY)
    cid_to_sid = {s["community_id"]: s["session_id"] for s in sessions if s.get("community_id")}

    seen: set[tuple] = set()
    records: list[dict] = []

    def _add(src_type, src_val, rel, dst_type, dst_val, sid):
        if not src_val or not dst_val: return
        key = (src_type, src_val, rel, dst_type, dst_val, sid)
        if key in seen: return
        seen.add(key)
        records.append({"src_type":src_type,"src_value":src_val,"relation_type":rel,
                        "dst_type":dst_type,"dst_value":dst_val,"session_id":sid})

    for sess in sessions:
        sid        = sess["session_id"]
        src_ip     = sess.get("src_ip")
        dest_ip    = sess.get("dest_ip")    # [v5]
        http_host  = sess.get("http_host")
        tls_sni    = sess.get("tls_sni")
        tls_cipher = sess.get("tls_cipher")
        dns_query  = sess.get("dns_query")
        dns_answers= sess.get("dns_answers")

        _add("ip", src_ip, "CONNECTED_TO", "ip", dest_ip, sid)  # [v5]

        if http_host:
            _add("ip", src_ip, "REQUESTED", "ip" if _is_ip(http_host) else "domain", http_host, sid)
        if tls_sni:
            _add("ip", src_ip, "REQUESTED", "domain", tls_sni, sid)
            _add("session", sid, "SERVED_OVER_TLS", "domain", tls_sni, sid)
        if tls_cipher:
            _add("session", sid, "ENCRYPTED_WITH", "cipher", tls_cipher, sid)
        if dns_query:
            _add("ip", src_ip, "REQUESTED", "domain", dns_query, sid)
            if dns_answers:
                for ans in str(dns_answers).split(","):
                    ans = ans.strip()
                    if not ans: continue
                    parts = ans.split(".")
                    if len(parts)==4 and all(p.isdigit() for p in parts):
                        _add("domain", dns_query, "RESOLVED_BY", "ip", ans, sid)
                    elif ans != dns_query:
                        _add("domain", dns_query, "RESOLVED_BY", "domain", ans, sid)

    for raw_sess in raw:
        sid = cid_to_sid.get(raw_sess.get("community_id"), "unknown")
        for ev in raw_sess.get("timeline", []):
            source = ev.get("source")
            if source == "zeek_dns":
                query, answers_raw, orig_h = ev.get("query"), ev.get("answers"), ev.get("orig_h")
                if orig_h and query: _add("ip", orig_h, "REQUESTED", "domain", query, sid)
                if query and answers_raw:
                    for ans in str(answers_raw).split(","):
                        ans = ans.strip()
                        parts = ans.split(".")
                        if len(parts)==4 and all(p.isdigit() for p in parts):
                            _add("domain", query, "RESOLVED_BY", "ip", ans, sid)
                        elif ans and ans != query:
                            _add("domain", query, "RESOLVED_BY", "domain", ans, sid)
            elif source == "zeek_ssl":
                if ev.get("server_name"): _add("session", sid, "SERVED_OVER_TLS", "domain", ev["server_name"], sid)
                if ev.get("cipher"):      _add("session", sid, "ENCRYPTED_WITH",   "cipher", ev["cipher"],      sid)
            elif source == "suricata" and ev.get("signature"):
                _add("session", sid, "TRIGGERED", "alert", str(ev.get("signature_id") or ev.get("signature")), sid)

    _s3_write_jsonl(S3_RELATION_KEY, records)
    logger.info("extract_relations 완료 — %d 관계", len(records))
    ctx["ti"].xcom_push(key="relation_count", value=len(records))


# ── Task 5 : report_stats ─────────────────────────────────────────────────────

def report_stats(**ctx) -> None:
    if ctx["ti"].xcom_pull(task_ids="fetch_from_s3", key="skip"):
        logger.info("S3 변경 없음 — report_stats 스킵")
        return

    ti             = ctx["ti"]
    total_lines    = ti.xcom_pull(task_ids="validate_input",    key="total_lines")
    session_count  = ti.xcom_pull(task_ids="extract_sessions",  key="session_count")
    entity_count   = ti.xcom_pull(task_ids="extract_entities",  key="entity_count")
    relation_count = ti.xcom_pull(task_ids="extract_relations", key="relation_count")

    sessions  = _s3_read_jsonl(S3_SESSION_KEY)
    entities  = _s3_read_jsonl(S3_ENTITY_KEY)
    relations = _s3_read_jsonl(S3_RELATION_KEY)

    entity_types: dict[str, int] = defaultdict(int)
    for e in entities: entity_types[e["entity_type"]] += 1
    rel_types: dict[str, int] = defaultdict(int)
    for r in relations: rel_types[r["relation_type"]] += 1

    threat_count = sum(1 for s in sessions if s.get("is_threat"))
    tls_count    = sum(1 for s in sessions if s.get("tls_sni") or s.get("tls_cipher"))
    uid_count    = sum(1 for s in sessions if s.get("uid"))   # [신규 v5]

    logger.info("=" * 65)
    logger.info("▶ Gold 전처리 파이프라인 완료 요약 (v5 — uid 포함)")
    logger.info("=" * 65)
    logger.info("  [Input]  unified_events.jsonl : %s 행", total_lines)
    logger.info("  [Output] session_gold         : %s 세션 (위협 %s개 %.1f%% / TLS %s개 / uid보유 %s개)",
                session_count, threat_count,
                100 * threat_count / session_count if session_count else 0,
                tls_count, uid_count)
    logger.info("  [Output] entity_gold          : %s 엔티티", entity_count)
    for etype, cnt in entity_types.items():
        logger.info("             ├ %-8s : %s", etype, cnt)
    logger.info("  [Output] relation_gold        : %s 관계", relation_count)
    for rtype, cnt in rel_types.items():
        logger.info("             ├ %-25s : %s", rtype, cnt)
    logger.info("=" * 65)


# ── DAG 정의 ──────────────────────────────────────────────────────────────────

default_args = {
    "owner":            "linda",
    "depends_on_past":  False,
    "retries":          1,
    "retry_delay":      timedelta(minutes=3),
    "email_on_failure": False,
}

with DAG(
    dag_id="unified_events_to_gold",
    description="S3 parquet → session/entity/relation gold 전처리 v5 (uid 포함)",
    default_args=default_args,
    start_date=datetime(2026, 1, 1),
    schedule="*/10 * * * *",
    catchup=False,
    max_active_runs=1,
    tags=["cti", "graph-rag", "preprocessing"],
) as dag:

    t_fetch    = PythonOperator(task_id="fetch_from_s3",    python_callable=fetch_from_s3)
    t_convert  = PythonOperator(task_id="parquet_to_jsonl", python_callable=parquet_to_jsonl)
    t_validate = PythonOperator(task_id="validate_input",   python_callable=validate_input)
    t_sessions = PythonOperator(task_id="extract_sessions", python_callable=extract_sessions)
    t_entities = PythonOperator(task_id="extract_entities", python_callable=extract_entities)
    t_relations= PythonOperator(task_id="extract_relations",python_callable=extract_relations)
    t_report   = PythonOperator(task_id="report_stats",     python_callable=report_stats,
                                outlets=[GOLD_SESSION_ASSET, GOLD_ENTITY_ASSET, GOLD_RELATION_ASSET])

    t_fetch >> t_convert >> t_validate >> t_sessions >> t_entities >> t_relations >> t_report