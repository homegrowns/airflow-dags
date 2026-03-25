"""
dag_unified_to_gold.py
S3 silver/common_records (Spark 파티션 parquet) → session_gold / entity_gold / relation_gold

[v7 변경점]
  - parquet_to_jsonl task 제거
  - S3_JSONL_KEY / unified_events.jsonl 중간 파일 완전 제거
  - _load_silver_records() 공통 헬퍼로 parquet 로딩·통합 로직 분리
    · validate_input / extract_sessions / extract_entities / extract_relations
      모두 이 헬퍼를 직접 호출해 parquet → list[dict] 로드
  - fetch_from_s3 가 parquet_keys XCom 을 push → 이후 task 재사용

[v6 변경점 — Spark silver 실제 출력 스키마 대응]

  ※ Spark build_common_records() 실제 출력 컬럼
      community_id, uid, flow_id,
      src_ip, src_port, dest_ip, dest_port, proto, service,
      flow_start (Unix ms int), flow_end (Unix ms int),
      is_threat (bool), threat_level (int|null), alert_count (int),
      timeline (JSON string)

  ※ timeline 내 이벤트 구조 (실측)
      zeek_conn  : source, ts(str), uid, community_id,
                   orig_h, orig_p, resp_h, resp_p,
                   proto, service, duration, orig_bytes, resp_bytes,
                   conn_state, missed_bytes, history, orig_pkts, resp_pkts
      zeek_http  : source, ts, uid, orig_h, orig_p, resp_h, resp_p, version
                   ← method/host/uri 등 HTTP 세부 필드 없음 (Spark zeek.py 미포함)
      zeek_ssl   : source, ts, uid, orig_h, orig_p, resp_h, resp_p,
                   version, curve, established, ssl_history, resumed, cipher, server_name
      zeek_dns   : source, ts, uid, orig_h, orig_p, resp_h, resp_p,
                   query, qtype_name, rcode_name, answers, rtt
      suricata   : source, ts, community_id, proto, event_type,
                   src_ip, dest_ip, src_port, dest_port
                   + flow 전용: flow_state, flow_reason, pkts_*, bytes_*
                   + alert 전용: signature, signature_id, category, severity

  [변경 상세]
  1. 입력 경로
       Before : s3://.../unified_events.parquet  (단일 파일)
       After  : s3://.../silver/common_records/  (dt/hour/batch_seq 파티션 parquet)
  2. 변경 감지
       Before : 단일 파일 ETag
       After  : prefix 내 파일들의 최신 LastModified
  3. parquet_to_jsonl
       · S3 prefix 내 전체 .parquet 열거 → pd.concat
       · 파티션 컬럼(dt/hour/batch_seq) 자동 제거
       · community_id 기준 배치 통합 (timeline 누적, 수치 필드 최신값)
       · flow_start/flow_end Unix ms int → ISO UTC 문자열 변환
  4. _extract_conn
       · top-level src_ip/dest_ip 1순위 (Spark coalesce 확정값)
       · zeek_conn: uid + conn 세부 필드(bytes/pkts 등) 보완
       · suricata: IP 최후 fallback (orig_h/resp_h 없음, src_ip/dest_ip 사용)
  5. _extract_http
       · zeek_http 이벤트에 method/host/uri 없으므로 None 방어
         (추후 Spark zeek.py 확장 시 자동 수용되도록 ev.get() 유지)
  6. _extract_suricata_stats
       · top-level alert_count / threat_level 1순위
       · flow_* 필드: suricata event_type=="flow" 이벤트에서 추출
       · max_severity fallback: event_type=="alert" 이벤트에서 재집계
  7. extract_entities
       · suricata: src_ip/dest_ip 직접 추출 (orig_h/resp_h 아님)
       · alert_bucket: event_type=="alert" 인 것만 수집
  8. extract_relations
       · suricata TRIGGERED: event_type=="alert" 인 것만 생성

Pipeline:
  [fetch_from_s3]    ← silver prefix LastModified 체크 → skip / parquet_keys XCom
       ↓
  [validate_input]   ← parquet 직접 로드 → 레코드 수 검증
       ↓
  [extract_sessions] ← parquet 직접 로드 → session_gold → S3
       ↓
  [extract_entities] ← parquet 직접 로드 + session_gold → entity_gold → S3
       ↓
  [extract_relations]← parquet 직접 로드 + session_gold → relation_gold → S3
       ↓
  [report_stats]     ← 요약 통계 로그

Author : Linda
"""

from __future__ import annotations

import io
import json
import logging
import hashlib
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import boto3

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.sdk import Asset

# ── S3 설정 ───────────────────────────────────────────────────────────────────
S3_BUCKET = "malware-project-bucket"

# Spark silver 파티션 parquet prefix
S3_SILVER_PREFIX = "silver/common_records/"

S3_SESSION_KEY  = "gold/session_gold.jsonl"
S3_ENTITY_KEY   = "gold/entity_gold.jsonl"
S3_RELATION_KEY = "gold/relation_gold.jsonl"

AWS_REGION = "ap-northeast-2"

DATA_DIR           = Path("/opt/airflow/data")
LAST_MODIFIED_PATH = DATA_DIR / ".last_silver_modified"  # [v6] ETag → LastModified

GOLD_SESSION_ASSET  = Asset("s3://malware-project-bucket/gold/session_gold.jsonl")
GOLD_ENTITY_ASSET   = Asset("s3://malware-project-bucket/gold/entity_gold.jsonl")
GOLD_RELATION_ASSET = Asset("s3://malware-project-bucket/gold/relation_gold.jsonl")

logger = logging.getLogger(__name__)


# ── 공통 S3 헬퍼 ──────────────────────────────────────────────────────────────

def _s3_client():
    return boto3.client("s3", region_name=AWS_REGION)

def _s3_read_jsonl(s3_key: str) -> list[dict]:
    s3  = _s3_client()
    obj = s3.get_object(Bucket=S3_BUCKET, Key=s3_key)
    return [
        json.loads(line)
        for line in obj["Body"].read().decode("utf-8").splitlines()
        if line.strip()
    ]

def _s3_write_jsonl(s3_key: str, records: list[dict]) -> None:
    s3   = _s3_client()
    body = "\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n"
    s3.put_object(Bucket=S3_BUCKET, Key=s3_key, Body=body.encode("utf-8"))
    logger.info("S3 업로드 완료: s3://%s/%s (%d 레코드)", S3_BUCKET, s3_key, len(records))


# ── [v6] silver prefix 헬퍼 ───────────────────────────────────────────────────

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

def _latest_silver_modified(keys: list[str]) -> str | None:
    """파일 목록에서 가장 최근 LastModified ISO 문자열 반환."""
    if not keys:
        return None
    s3    = _s3_client()
    times = [s3.head_object(Bucket=S3_BUCKET, Key=k)["LastModified"].isoformat() for k in keys]
    return max(times)


# ── [v6] Unix ms timestamp → ISO UTC 문자열 ───────────────────────────────────

def _ms_to_iso(ms: Any) -> str | None:
    """
    Spark flow_start/flow_end 는 Unix milliseconds (int) 로 저장됨.
    ISO UTC 문자열로 변환해 이후 문자열 비교/저장에 사용한다.
    이미 문자열이면 그대로 반환, None 이면 None 반환.
    """
    if ms is None:
        return None
    if isinstance(ms, str):
        return ms
    try:
        return datetime.fromtimestamp(int(ms) / 1000.0, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError):
        return str(ms)


# ── Task 0-1 : fetch_from_s3 ──────────────────────────────────────────────────

def fetch_from_s3(**ctx) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    keys = _list_silver_parquet_keys()
    if not keys:
        logger.warning("silver prefix 에 parquet 파일 없음 — 처리 스킵")
        ctx["ti"].xcom_push(key="skip", value=True)
        return

    latest_modified = _latest_silver_modified(keys)

    if LAST_MODIFIED_PATH.exists():
        if LAST_MODIFIED_PATH.read_text().strip() == latest_modified:
            logger.info("silver 데이터 변경 없음 (LastModified=%s) — 처리 스킵", latest_modified)
            ctx["ti"].xcom_push(key="skip", value=True)
            return

    LAST_MODIFIED_PATH.write_text(latest_modified)
    logger.info("silver 데이터 변경 감지 (LastModified=%s, 파일 수=%d)", latest_modified, len(keys))
    ctx["ti"].xcom_push(key="skip",         value=False)
    ctx["ti"].xcom_push(key="parquet_keys", value=keys)


# ── [v7] silver parquet 로딩 공통 헬퍼 ───────────────────────────────────────

def _load_silver_records(ctx) -> list[dict]:
    """
    silver/common_records/ prefix 내 parquet 전체 읽기 →
    community_id 기준 통합 → list[dict] 반환.

    parquet_to_jsonl task 를 제거하면서 validate_input / extract_sessions /
    extract_entities / extract_relations 가 직접 호출하는 공통 헬퍼.
    """
    import pandas as pd

    ti   = ctx["ti"]
    keys: list[str] = ti.xcom_pull(task_ids="fetch_from_s3", key="parquet_keys") or []
    if not keys:
        keys = _list_silver_parquet_keys()

    s3 = _s3_client()
    frames: list[pd.DataFrame] = []
    for key in keys:
        try:
            obj = s3.get_object(Bucket=S3_BUCKET, Key=key)
            frames.append(pd.read_parquet(io.BytesIO(obj["Body"].read())))
        except Exception as e:
            logger.warning("parquet 읽기 실패 — %s: %s", key, e)

    if not frames:
        raise ValueError("읽을 수 있는 silver parquet 파일이 없습니다.")

    df = pd.concat(frames, ignore_index=True)
    df = df.drop(columns=[c for c in ("dt", "hour", "batch_seq") if c in df.columns])
    if "flow_start" in df.columns:
        df = df.sort_values("flow_start", na_position="last")

    def _convert(v: Any) -> Any:
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
        record: dict[str, Any] = {k: _convert(v) for k, v in row.to_dict().items()}
        record["flow_start"] = _ms_to_iso(record.get("flow_start"))
        record["flow_end"]   = _ms_to_iso(record.get("flow_end"))

        tl_raw = record.get("timeline", [])
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
        record["timeline"] = tl_parsed

        cid = record.get("community_id")
        if not cid:
            merged[f"_orphan_{orphan_idx}"] = record
            orphan_idx += 1
            continue

        if cid not in merged:
            merged[cid] = record
        else:
            ex = merged[cid]
            ex["timeline"] = ex.get("timeline", []) + tl_parsed
            for f in NUMERIC_FIELDS:
                if record.get(f) is not None:
                    ex[f] = record[f]
            fs_old, fs_new = ex.get("flow_start"), record.get("flow_start")
            if fs_old and fs_new: ex["flow_start"] = min(fs_old, fs_new)
            elif fs_new:          ex["flow_start"] = fs_new
            fe_old, fe_new = ex.get("flow_end"), record.get("flow_end")
            if fe_old and fe_new: ex["flow_end"] = max(fe_old, fe_new)
            elif fe_new:          ex["flow_end"] = fe_new

    records = list(merged.values())
    logger.info("_load_silver_records 완료 — community_id 기준 %d 레코드", len(records))
    return records


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
        logger.info("silver 변경 없음 — validate 스킵")
        return
    records    = _load_silver_records(ctx)
    record_count = len(records)
    if record_count == 0:
        raise ValueError("silver parquet 에서 읽은 레코드가 없습니다.")
    logger.info("validate_input OK — 총 %d 레코드", record_count)
    ctx["ti"].xcom_push(key="total_lines", value=record_count)


# ── Task 2 : extract_sessions ─────────────────────────────────────────────────

def _extract_conn(row: dict, timeline: list[dict]) -> dict:
    """
    [v6] conn 정보 추출 우선순위:
      1. top-level src_ip/dest_ip (Spark coalesce 확정값)
      2. zeek_conn: uid + conn 세부 필드(bytes/pkts/state 등) 보완
         - orig_h/resp_h 는 top-level 이 None 인 경우에만 IP 보완
      3. suricata: IP 최후 fallback
         - suricata 는 src_ip/dest_ip 직접 저장 (orig_h/resp_h 없음)
    """
    base = {
        "uid":      row.get("uid"),
        "ts":       row.get("flow_start"),
        "src_ip":   row.get("src_ip"),
        "src_port": row.get("src_port"),
        "dest_ip":  row.get("dest_ip"),
        "dest_port":row.get("dest_port"),
        "proto":    row.get("proto"),
        "service":  row.get("service"),
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

    # suricata fallback (IP 여전히 없을 때)
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
    """
    [v6] 현재 zeek_http 이벤트 실측 필드: source, ts, uid, orig_h, orig_p, resp_h, resp_p, version
         method/host/uri/user_agent 등 세부 HTTP 필드는 Spark zeek.py 에 미포함.
         ev.get() 으로 읽어두어 추후 Spark 확장 시 자동 수용.
    """
    _null = {k: None for k in [
        "http_method", "http_host", "http_uri", "http_user_agent",
        "http_request_body_len", "http_response_body_len",
        "http_status_code", "http_status_msg",
        "http_version",                          # [v7] 추가
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
            "http_version":           ev.get("version"),  # [v7] zeek_http version 필드
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
    """
    [v6] zeek_ssl timeline 실측 필드명:
         version, curve, established, ssl_history, resumed, cipher, server_name
    """
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
    [v6]
    · alert_count: top-level 값 1순위 (Spark build_suricata_flows 집계 확정값)
    · threat_level → max_severity: top-level 값 1순위
      (Spark: spark_max(severity), 낮을수록 심각이므로 실제론 max가 덜 심각하지만 원본 유지)
    · flow_*: suricata event_type=="flow" 이벤트에서 추출
    · max_severity fallback: event_type=="alert" 이벤트 severity min 재집계
    """
    alert_count  = row.get("alert_count") or 0
    max_severity = row.get("threat_level")

    # event_type=="flow" 이벤트에서 flow 필드 추출
    flow_ev: dict = {}
    for ev in timeline:
        if ev.get("source") == "suricata" and ev.get("event_type") == "flow":
            flow_ev = ev
            break

    # max_severity fallback
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


def extract_sessions(**ctx) -> None:
    if ctx["ti"].xcom_pull(task_ids="fetch_from_s3", key="skip"):
        logger.info("silver 변경 없음 — extract_sessions 스킵")
        return

    raw_sessions = _load_silver_records(ctx)
    seen_cids:  dict[str, str] = {}
    orphan_idx = 0
    records:    list[dict]     = []

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
        conn = _extract_conn(session, timeline)
        http = _extract_http(timeline)
        dns  = _extract_dns(timeline)
        ssl  = _extract_ssl(timeline)
        suri = _extract_suricata_stats(session, timeline)

        records.append({
            "session_id":   session_id,
            "community_id": cid,
            "uid":          conn.get("uid"),
            "ts":           conn.get("ts"),
            "src_ip":       conn.get("src_ip"),
            "src_port":     conn.get("src_port"),
            "dest_ip":      conn.get("dest_ip"),
            "dest_port":    conn.get("dest_port"),
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
            "alert_count":    suri["alert_count"],
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
        logger.info("silver 변경 없음 — extract_entities 스킵")
        return

    sessions = _s3_read_jsonl(S3_SESSION_KEY)
    raw      = _load_silver_records(ctx)

    ip_bucket:     dict[str, dict] = {}
    domain_bucket: dict[str, dict] = {}
    alert_bucket:  dict[str, dict] = {}

    def _update_ip(ip, ts, sid, orig=0, resp=0):
        if not ip: return
        b = ip_bucket.setdefault(ip, {
            "first_seen": ts, "last_seen": ts,
            "sessions": set(), "orig_bytes": 0, "resp_bytes": 0,
        })
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
        b = alert_bucket.setdefault(key, {
            "first_seen": ts, "last_seen": ts, "sessions": set(),
            "signature": sig, "signature_id": sig_id, "category": category,
        })
        if ts:
            if not b["first_seen"] or ts < b["first_seen"]: b["first_seen"] = ts
            if not b["last_seen"]  or ts > b["last_seen"]:  b["last_seen"]  = ts
        b["sessions"].add(sid)

    for sess in sessions:
        sid = sess["session_id"]
        ts  = sess.get("flow_start")
        _update_ip(sess.get("src_ip"),  ts, sid)
        _update_ip(sess.get("dest_ip"), ts, sid)
        http_host = sess.get("http_host")
        if http_host:
            (_update_ip if _is_ip(http_host) else _update_domain)(http_host, ts, sid)
        if sess.get("tls_sni"):   _update_domain(sess["tls_sni"],   ts, sid)
        if sess.get("dns_query"): _update_domain(sess["dns_query"], ts, sid)

    cid_to_sid = {
        s["community_id"]: s["session_id"]
        for s in sessions if s.get("community_id")
    }

    for raw_sess in raw:
        sid = cid_to_sid.get(raw_sess.get("community_id"), "unknown")
        for ev in raw_sess.get("timeline", []):
            source   = ev.get("source", "")
            ts       = ev.get("ts")

            if source == "zeek_conn":
                # zeek_conn: orig_h/resp_h 사용
                _update_ip(ev.get("orig_h"), ts, sid, int(ev.get("orig_bytes") or 0), 0)
                _update_ip(ev.get("resp_h"), ts, sid, 0, int(ev.get("resp_bytes") or 0))

            elif source == "suricata":
                # [v6] suricata: src_ip/dest_ip 직접 사용 (orig_h/resp_h 없음)
                _update_ip(ev.get("src_ip"),  ts, sid)
                _update_ip(ev.get("dest_ip"), ts, sid)
                # [v6] event_type=="alert" 인 것만 alert_bucket 에 추가
                if ev.get("event_type") == "alert" and ev.get("signature"):
                    _update_alert(
                        ev.get("signature_id"), ev.get("signature"),
                        ev.get("category"),     ev.get("severity"), ts, sid,
                    )

            elif source == "zeek_dns":
                _update_domain(ev.get("query"), ts, sid)
                answers_raw = ev.get("answers")
                if answers_raw:
                    for ans in str(answers_raw).split(","):
                        ans = ans.strip()
                        if not ans: continue
                        parts = ans.split(".")
                        (
                            _update_ip if (len(parts) == 4 and all(p.isdigit() for p in parts))
                            else _update_domain
                        )(ans, ts, sid)

            elif source == "zeek_ssl":
                if ev.get("server_name"): _update_domain(ev["server_name"], ts, sid)

    records: list[dict] = []
    for ip, b in ip_bucket.items():
        records.append({
            "entity_type": "ip",    "entity_value": ip,
            "first_seen":  b["first_seen"], "last_seen": b["last_seen"],
            "related_session_count": len(b["sessions"]),
            "total_orig_bytes": b["orig_bytes"], "total_resp_bytes": b["resp_bytes"],
            "signature": None, "category": None,
        })
    for domain, b in domain_bucket.items():
        records.append({
            "entity_type": "domain", "entity_value": domain,
            "first_seen":  b["first_seen"], "last_seen": b["last_seen"],
            "related_session_count": len(b["sessions"]),
            "total_orig_bytes": None, "total_resp_bytes": None,
            "signature": None, "category": None,
        })
    for key, b in alert_bucket.items():
        records.append({
            "entity_type": "alert", "entity_value": key,
            "first_seen":  b["first_seen"], "last_seen": b["last_seen"],
            "related_session_count": len(b["sessions"]),
            "total_orig_bytes": None, "total_resp_bytes": None,
            "signature": b["signature"], "category": b["category"],
        })

    _s3_write_jsonl(S3_ENTITY_KEY, records)
    logger.info(
        "extract_entities 완료 — ip:%d domain:%d alert:%d",
        len(ip_bucket), len(domain_bucket), len(alert_bucket),
    )
    ctx["ti"].xcom_push(key="entity_count", value=len(records))


# ── Task 4 : extract_relations ────────────────────────────────────────────────

def extract_relations(**ctx) -> None:
    if ctx["ti"].xcom_pull(task_ids="fetch_from_s3", key="skip"):
        logger.info("silver 변경 없음 — extract_relations 스킵")
        return

    sessions   = _s3_read_jsonl(S3_SESSION_KEY)
    raw        = _load_silver_records(ctx)
    cid_to_sid = {s["community_id"]: s["session_id"] for s in sessions if s.get("community_id")}

    seen:    set[tuple] = set()
    records: list[dict] = []

    def _add(src_type, src_val, rel, dst_type, dst_val, sid):
        if not src_val or not dst_val: return
        key = (src_type, src_val, rel, dst_type, dst_val, sid)
        if key in seen: return
        seen.add(key)
        records.append({
            "src_type":      src_type, "src_value":  src_val,
            "relation_type": rel,
            "dst_type":      dst_type, "dst_value":  dst_val,
            "session_id":    sid,
        })

    for sess in sessions:
        sid         = sess["session_id"]
        src_ip      = sess.get("src_ip")
        dest_ip     = sess.get("dest_ip")
        http_host   = sess.get("http_host")
        tls_sni     = sess.get("tls_sni")
        tls_cipher  = sess.get("tls_cipher")
        dns_query   = sess.get("dns_query")
        dns_answers = sess.get("dns_answers")

        _add("ip", src_ip, "CONNECTED_TO", "ip", dest_ip, sid)

        if http_host:
            _add("ip", src_ip, "REQUESTED", "ip" if _is_ip(http_host) else "domain", http_host, sid)
        if tls_sni:
            _add("ip",      src_ip, "REQUESTED",       "domain", tls_sni,   sid)
            _add("session", sid,    "SERVED_OVER_TLS", "domain", tls_sni,   sid)
        if tls_cipher:
            _add("session", sid, "ENCRYPTED_WITH", "cipher", tls_cipher, sid)
        if dns_query:
            _add("ip", src_ip, "REQUESTED", "domain", dns_query, sid)
            if dns_answers:
                for ans in str(dns_answers).split(","):
                    ans = ans.strip()
                    if not ans: continue
                    parts = ans.split(".")
                    if len(parts) == 4 and all(p.isdigit() for p in parts):
                        _add("domain", dns_query, "RESOLVED_BY", "ip",     ans, sid)
                    elif ans != dns_query:
                        _add("domain", dns_query, "RESOLVED_BY", "domain", ans, sid)

    for raw_sess in raw:
        sid = cid_to_sid.get(raw_sess.get("community_id"), "unknown")
        for ev in raw_sess.get("timeline", []):
            source = ev.get("source", "")

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
                            _add("domain", query, "RESOLVED_BY", "ip",     ans, sid)
                        elif ans and ans != query:
                            _add("domain", query, "RESOLVED_BY", "domain", ans, sid)

            elif source == "zeek_ssl":
                if ev.get("server_name"):
                    _add("session", sid, "SERVED_OVER_TLS", "domain", ev["server_name"], sid)
                if ev.get("cipher"):
                    _add("session", sid, "ENCRYPTED_WITH",  "cipher", ev["cipher"],      sid)

            elif source == "suricata" and ev.get("event_type") == "alert" and ev.get("signature"):
                # [v6] event_type=="alert" 인 것만 TRIGGERED 관계 생성
                _add(
                    "session", sid, "TRIGGERED", "alert",
                    str(ev.get("signature_id") or ev.get("signature")), sid,
                )

    _s3_write_jsonl(S3_RELATION_KEY, records)
    logger.info("extract_relations 완료 — %d 관계", len(records))
    ctx["ti"].xcom_push(key="relation_count", value=len(records))


# ── Task 5 : report_stats ─────────────────────────────────────────────────────

def report_stats(**ctx) -> None:
    if ctx["ti"].xcom_pull(task_ids="fetch_from_s3", key="skip"):
        logger.info("silver 변경 없음 — report_stats 스킵")
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
    uid_count    = sum(1 for s in sessions if s.get("uid"))

    logger.info("=" * 65)
    logger.info("▶ Gold 전처리 파이프라인 완료 요약 (v7 — Spark silver 대응)")
    logger.info("=" * 65)
    logger.info("  [Input]  silver/common_records (parquet) : %s 레코드", total_lines)
    logger.info(
        "  [Output] session_gold  : %s 세션 (위협 %s개 %.1f%% / TLS %s개 / uid보유 %s개)",
        session_count, threat_count,
        100 * threat_count / session_count if session_count else 0,
        tls_count, uid_count,
    )
    logger.info("  [Output] entity_gold   : %s 엔티티", entity_count)
    for etype, cnt in entity_types.items():
        logger.info("             ├ %-8s : %s", etype, cnt)
    logger.info("  [Output] relation_gold : %s 관계", relation_count)
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
    description="Spark silver parquet → session/entity/relation gold 전처리",
    default_args=default_args,
    start_date=datetime(2026, 1, 1),
    schedule="*/10 * * * *",
    catchup=False,
    max_active_runs=1,
    tags=["cti", "graph-rag", "preprocessing"],
) as dag:

    t_fetch    = PythonOperator(task_id="fetch_from_s3",    python_callable=fetch_from_s3)
    t_validate = PythonOperator(task_id="validate_input",   python_callable=validate_input)
    t_sessions = PythonOperator(task_id="extract_sessions", python_callable=extract_sessions)
    t_entities = PythonOperator(task_id="extract_entities", python_callable=extract_entities)
    t_relations= PythonOperator(task_id="extract_relations",python_callable=extract_relations)
    t_report   = PythonOperator(
        task_id="report_stats",
        python_callable=report_stats,
        outlets=[GOLD_SESSION_ASSET, GOLD_ENTITY_ASSET, GOLD_RELATION_ASSET],
    )

    t_fetch >> t_validate >> t_sessions >> t_entities >> t_relations >> t_report