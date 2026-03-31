"""
dag_unified_events_to_gold.py
S3 silver/common_records (Spark 파티션 parquet) → session_gold / entity_gold / relation_gold

[v9 변경점]
  - max_active_runs: 1 → 4 (배치 동시 처리)
  - wait_for_silver: S3KeysUnchangedSensor → PythonSensor
    · 다음 minute_10 폴더가 생기면 현재 폴더 완성으로 판단
    · 예) minute_10=10 처리 중 → minute_10=20 폴더 감지되면 통과
  - _silver_sensor_prefix / _gold_s3_key: KST 변환 적용
  - _ms_to_iso → _ms_to_kst_iso (KST 변환)
  - _load_silver_records fallback 제거 (wait_for_silver 통과 후 없으면 에러)
  - TriggerDagRunOperator: neo4j_to_rag 트리거 (session_key conf 전달)

Pipeline:
  [wait_for_silver]  ← PythonSensor: 다음 minute_10 폴더 감지 시 통과
          ↓
  [validate_input]   ← parquet 직접 로드 → 레코드 수 검증
          ↓
  [extract_sessions] ← session_gold → S3 parquet + _SUCCESS + trigger_neo4j_to_rag
          ↓
  [extract_entities] ← entity_gold → S3 parquet + _SUCCESS
          ↓
  [extract_relations]← relation_gold → S3 parquet + _SUCCESS
          ↓
  [report_stats]     ← 요약 통계 로그 + Asset emit

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
from zoneinfo import ZoneInfo

import boto3
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.trigger_dagrun import TriggerDagRunOperator
from airflow.sensors.python import PythonSensor
from airflow.sdk import Asset

# ── S3 설정 ───────────────────────────────────────────────────────────────────
S3_BUCKET        = "malware-project-bucket"
S3_SILVER_PREFIX = "silver/common_records/"
S3_GOLD_PREFIX   = "gold"
AWS_REGION       = "ap-northeast-2"

KST = ZoneInfo("Asia/Seoul")

GOLD_SESSION_ASSET  = Asset("s3://malware-project-bucket/gold/session_gold")
GOLD_ENTITY_ASSET   = Asset("s3://malware-project-bucket/gold/entity_gold")
GOLD_RELATION_ASSET = Asset("s3://malware-project-bucket/gold/relation_gold")

logger = logging.getLogger(__name__)


# ── 공통 S3 헬퍼 ──────────────────────────────────────────────────────────────

def _s3_client():
    return boto3.client("s3", region_name=AWS_REGION)


# ── KST 변환 헬퍼 ─────────────────────────────────────────────────────────────

def _to_kst(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(KST)


def _ms_to_kst_iso(ms: Any) -> str | None:
    """Unix ms (int) 또는 ISO 문자열 → KST ISO 문자열."""
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
        return datetime.fromtimestamp(
            int(ms) / 1000.0, tz=timezone.utc
        ).astimezone(KST).isoformat()
    except (ValueError, TypeError, OSError):
        return str(ms)


# ── gold parquet 경로 생성 ────────────────────────────────────────────────────

def _gold_s3_key(table: str, execution_date: datetime) -> str:
    """
    KST 기준 gold parquet 경로.
    예) gold/session_gold/dt=2026-03-29/hour=01/minute_10=50/minute_10=50_session_gold.parquet
    """
    kst       = _to_kst(execution_date)
    dt        = kst.strftime("%Y-%m-%d")
    hour      = kst.strftime("%H")
    minute_10 = f"{(kst.minute // 10) * 10:02d}"
    return (
        f"{S3_GOLD_PREFIX}/{table}"
        f"/dt={dt}/hour={hour}/minute_10={minute_10}"
        f"/minute_10={minute_10}_{table}.parquet"
    )

_TEST_PREFIXES = [
    "silver/common_records/dt=2026-03-28/hour=21/minute_10=30/",
    "silver/common_records/dt=2026-03-28/hour=21/minute_10=40/",
    "silver/common_records/dt=2026-03-28/hour=21/minute_10=50/",
    "silver/common_records/dt=2026-03-28/hour=22/minute_10=00/",
    "silver/common_records/dt=2026-03-28/hour=22/minute_10=10/",
    "silver/common_records/dt=2026-03-28/hour=22/minute_10=20/",
    "silver/common_records/dt=2026-03-28/hour=22/minute_10=30/",
    "silver/common_records/dt=2026-03-28/hour=22/minute_10=40/",
    "silver/common_records/dt=2026-03-28/hour=22/minute_10=50/",
    "silver/common_records/dt=2026-03-28/hour=23/minute_10=00/",
    "silver/common_records/dt=2026-03-28/hour=23/minute_10=10/",
    "silver/common_records/dt=2026-03-28/hour=23/minute_10=20/",
    "silver/common_records/dt=2026-03-28/hour=23/minute_10=30/",
    "silver/common_records/dt=2026-03-28/hour=23/minute_10=40/",
    "silver/common_records/dt=2026-03-28/hour=23/minute_10=50/",
]

def _silver_sensor_prefix(execution_date: datetime) -> str:
    # ── 임시 테스트용 override ─────────────────────────────
    # backfill CLI로 20개 순차 실행 시 logical_date 기반으로 인덱스 결정
    import bisect
    from datetime import datetime as dt
    anchors = [
        dt(2026, 3, 26, 20, 40), dt(2026, 3, 26, 20, 50),
        dt(2026, 3, 26, 21,  0), dt(2026, 3, 26, 21, 10),
        dt(2026, 3, 26, 21, 20), dt(2026, 3, 26, 21, 30),
        dt(2026, 3, 26, 21, 40), dt(2026, 3, 26, 21, 50),
        dt(2026, 3, 26, 22,  0), dt(2026, 3, 26, 22, 10),
        dt(2026, 3, 26, 22, 20), dt(2026, 3, 26, 22, 30),
        dt(2026, 3, 26, 22, 40), dt(2026, 3, 26, 22, 50),
        dt(2026, 3, 26, 23,  0), dt(2026, 3, 26, 23, 10),
        dt(2026, 3, 26, 23, 20), dt(2026, 3, 26, 23, 30),
        dt(2026, 3, 26, 23, 40), dt(2026, 3, 26, 23, 50),
    ]
    naive = execution_date.replace(tzinfo=None) if execution_date.tzinfo else execution_date
    idx   = min(bisect.bisect_right(anchors, naive), len(_TEST_PREFIXES) - 1)
    prefix = _TEST_PREFIXES[idx]
    logger.warning("_silver_sensor_prefix: TEST override [%d] — %s", idx, prefix)
    return prefix
    # ── 테스트 끝나면 제거 ────────────────────────────────
    # """KST 기준 silver prefix."""
    # kst       = _to_kst(execution_date)
    # dt        = kst.strftime("%Y-%m-%d")
    # hour      = kst.strftime("%H")
    # minute_10 = f"{(kst.minute // 10) * 10:02d}"
    # return f"{S3_SILVER_PREFIX}dt={dt}/hour={hour}/minute_10={minute_10}/"


def _next_silver_prefix(execution_date: datetime) -> str:
    """현재 배치의 다음 minute_10 silver prefix (KST 기준)."""
    kst          = _to_kst(execution_date)
    next_minute  = ((kst.minute // 10) + 1) * 10

    if next_minute >= 60:
        next_kst    = kst.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        next_minute = 0
    else:
        next_kst = kst

    dt        = next_kst.strftime("%Y-%m-%d")
    hour      = next_kst.strftime("%H")
    return f"{S3_SILVER_PREFIX}dt={dt}/hour={hour}/minute_10={next_minute:02d}/"


# ── parquet 읽기/쓰기 ─────────────────────────────────────────────────────────

def _s3_write_parquet(s3_key: str, records: list[dict]) -> None:
    import pandas as pd
    df  = pd.DataFrame(records)
    buf = io.BytesIO()
    df.to_parquet(buf, index=False)
    buf.seek(0)
    s3 = _s3_client()
    s3.put_object(
        Bucket=S3_BUCKET, Key=s3_key,
        Body=buf.read(), ContentType="application/octet-stream",
    )
    # 쓰기 완료 마커
    success_key = s3_key.rsplit("/", 1)[0] + "/_SUCCESS"
    s3.put_object(
        Bucket=S3_BUCKET, Key=success_key,
        Body=b"", ContentType="application/octet-stream",
    )
    logger.info(
        "S3 parquet 업로드 완료: s3://%s/%s (%d 레코드) | _SUCCESS: %s",
        S3_BUCKET, s3_key, len(records), success_key,
    )


def _s3_read_parquet(s3_key: str) -> list[dict]:
    import pandas as pd
    obj = _s3_client().get_object(Bucket=S3_BUCKET, Key=s3_key)
    df  = pd.read_parquet(io.BytesIO(obj["Body"].read()))
    return df.where(df.notna(), None).to_dict(orient="records")


# ── silver prefix 헬퍼 ────────────────────────────────────────────────────────

def _list_silver_parquet_keys(prefix: str) -> list[str]:
    s3        = _s3_client()
    paginator = s3.get_paginator("list_objects_v2")
    keys: list[str] = []
    for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith(".parquet") and "_SUCCESS" not in key:
                keys.append(key)
    return keys


# ── silver parquet 로딩 공통 헬퍼 ────────────────────────────────────────────

def _load_silver_records(ctx) -> list[dict]:
    """
    DAG 실행 시각 기준 silver prefix 내 parquet 전체 읽기
    → community_id 기준 통합 → list[dict] 반환.
    """
    import pandas as pd

    execution_date: datetime = ctx["logical_date"]
    prefix = _silver_sensor_prefix(execution_date)
    keys   = _list_silver_parquet_keys(prefix)

    if not keys:
        # wait_for_silver 통과 후 여기 오면 안 됨
        raise ValueError(f"silver parquet 없음 — prefix: {prefix}")

    s3 = _s3_client()
    frames: list = []
    for key in keys:
        try:
            obj = s3.get_object(Bucket=S3_BUCKET, Key=key)
            frames.append(pd.read_parquet(io.BytesIO(obj["Body"].read())))
        except Exception as e:
            logger.warning("parquet 읽기 실패 — %s: %s", key, e)

    if not frames:
        raise ValueError("읽을 수 있는 silver parquet 파일이 없습니다.")

    df = pd.concat(frames, ignore_index=True)
    df = df.drop(columns=[c for c in ("dt", "hour", "batch_seq", "minute_10") if c in df.columns])
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
        record["flow_start"] = _ms_to_kst_iso(record.get("flow_start"))
        record["flow_end"]   = _ms_to_kst_iso(record.get("flow_end"))

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
    logger.info(
        "_load_silver_records 완료 — community_id 기준 %d 레코드 (prefix: %s)",
        len(records), prefix,
    )
    return records


# ── 공통 유틸 ─────────────────────────────────────────────────────────────────

def _make_session_id(community_id: str | None, idx: int) -> str:
    if community_id:
        return f"s_{hashlib.sha1(community_id.encode()).hexdigest()[:8]}"
    return f"s_orphan_{idx:04d}"

def _is_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


# ══════════════════════════════════════════════════════════════════════════════
# Sensor : wait_for_silver
# ══════════════════════════════════════════════════════════════════════════════

def _check_next_partition_exists(**ctx) -> bool:
    """
    다음 minute_10 폴더가 S3에 존재하면 True → 현재 배치 완성으로 판단.
    예) 현재=minute_10=10 → minute_10=20 폴더에 파일 있으면 통과.
    """
    execution_date: datetime = ctx["logical_date"]
    next_prefix = _next_silver_prefix(execution_date)
    keys        = _list_silver_parquet_keys(next_prefix)

    if keys:
        logger.info(
            "wait_for_silver: 다음 파티션 감지 → 현재 배치 완성 판단\n"
            "  next_prefix: %s (%d개)", next_prefix, len(keys),
        )
        return True

    current_prefix = _silver_sensor_prefix(execution_date)
    logger.info(
        "wait_for_silver: 대기 중\n"
        "  current: %s\n"
        "  waiting: %s", current_prefix, next_prefix,
    )
    return False


# ══════════════════════════════════════════════════════════════════════════════
# Task 1 : validate_input
# ══════════════════════════════════════════════════════════════════════════════

def validate_input(**ctx) -> None:
    records      = _load_silver_records(ctx)
    record_count = len(records)
    if record_count == 0:
        raise ValueError("silver parquet 에서 읽은 레코드가 없습니다.")
    logger.info("validate_input OK — 총 %d 레코드", record_count)
    ctx["ti"].xcom_push(key="total_lines", value=record_count)


# ══════════════════════════════════════════════════════════════════════════════
# Task 2 : extract_sessions
# ══════════════════════════════════════════════════════════════════════════════

def _extract_conn(row: dict, timeline: list[dict]) -> dict:
    base = {
        "uid":       row.get("uid"),
        "ts":        row.get("flow_start"),
        "src_ip":    row.get("src_ip"),
        "src_port":  row.get("src_port"),
        "dest_ip":   row.get("dest_ip"),
        "dest_port": row.get("dest_port"),
        "proto":     row.get("proto"),
        "service":   row.get("service"),
        "duration":     None, "orig_bytes":   None, "resp_bytes":   None,
        "conn_state":   None, "missed_bytes": None, "history":      None,
        "orig_pkts":    None, "resp_pkts":    None,
    }
    for ev in timeline:
        if ev.get("source") != "zeek_conn":
            continue
        if not base["uid"]:       base["uid"]       = ev.get("uid")
        if not base["src_ip"]:    base["src_ip"]    = ev.get("orig_h")
        if not base["dest_ip"]:   base["dest_ip"]   = ev.get("resp_h")
        if not base["src_port"]:  base["src_port"]  = ev.get("orig_p")
        if not base["dest_port"]: base["dest_port"] = ev.get("resp_p")
        base["duration"]     = ev.get("duration")
        base["orig_bytes"]   = ev.get("orig_bytes")
        base["resp_bytes"]   = ev.get("resp_bytes")
        base["conn_state"]   = ev.get("conn_state")
        base["missed_bytes"] = ev.get("missed_bytes")
        base["history"]      = ev.get("history")
        base["orig_pkts"]    = ev.get("orig_pkts")
        base["resp_pkts"]    = ev.get("resp_pkts")
        break
    if not base["src_ip"] or not base["dest_ip"]:
        for ev in timeline:
            if ev.get("source") != "suricata":
                continue
            if not base["src_ip"]:    base["src_ip"]    = ev.get("src_ip")
            if not base["dest_ip"]:   base["dest_ip"]   = ev.get("dest_ip")
            if not base["src_port"]:  base["src_port"]  = ev.get("src_port")
            if not base["dest_port"]: base["dest_port"] = ev.get("dest_port")
            if not base["proto"] and ev.get("proto"):
                base["proto"] = ev["proto"].lower()
            break
    return base


def _extract_http(timeline: list[dict]) -> dict:
    _null = {k: None for k in [
        "http_method", "http_host", "http_uri", "http_user_agent",
        "http_request_body_len", "http_response_body_len",
        "http_status_code", "http_status_msg", "http_version",
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


def extract_sessions(**ctx) -> None:
    execution_date: datetime = ctx["logical_date"]
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
            "session_id":     session_id,
            "community_id":   cid,
            "uid":            conn.get("uid"),
            "ts":             conn.get("ts"),
            "src_ip":         conn.get("src_ip"),
            "src_port":       conn.get("src_port"),
            "dest_ip":        conn.get("dest_ip"),
            "dest_port":      conn.get("dest_port"),
            "proto":          conn.get("proto"),
            "service":        conn.get("service"),
            "duration":       conn.get("duration"),
            "orig_bytes":     conn.get("orig_bytes"),
            "resp_bytes":     conn.get("resp_bytes"),
            "conn_state":     conn.get("conn_state"),
            "missed_bytes":   conn.get("missed_bytes"),
            "history":        conn.get("history"),
            "orig_pkts":      conn.get("orig_pkts"),
            "resp_pkts":      conn.get("resp_pkts"),
            **http,
            **dns,
            **ssl,
            "alert_count":    suri["alert_count"],
            "max_severity":   suri["max_severity"],
            "is_threat":      session.get("is_threat", False),
            "timeline":     json.dumps(timeline, ensure_ascii=False),
            "flow_state":     suri["flow_state"],
            "flow_reason":    suri["flow_reason"],
            "pkts_toserver":  suri["pkts_toserver"],
            "pkts_toclient":  suri["pkts_toclient"],
            "bytes_toserver": suri["bytes_toserver"],
            "bytes_toclient": suri["bytes_toclient"],
            "flow_start":     session.get("flow_start"),
            "flow_end":       session.get("flow_end"),
        })

    session_key = _gold_s3_key("session_gold", execution_date)
    _s3_write_parquet(session_key, records)
    logger.info("extract_sessions 완료 — %d 세션 → %s", len(records), session_key)
    ctx["ti"].xcom_push(key="session_key",   value=session_key)
    ctx["ti"].xcom_push(key="session_count", value=len(records))


# ══════════════════════════════════════════════════════════════════════════════
# Task 3 : extract_entities
# ══════════════════════════════════════════════════════════════════════════════

def extract_entities(**ctx) -> None:
    execution_date: datetime = ctx["logical_date"]
    session_key = ctx["ti"].xcom_pull(task_ids="extract_sessions", key="session_key")
    sessions    = _s3_read_parquet(session_key)
    raw         = _load_silver_records(ctx)

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
        b = domain_bucket.setdefault(domain, {
            "first_seen": ts, "last_seen": ts, "sessions": set(),
        })
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
            source = ev.get("source", "")
            ts     = ev.get("ts")
            if source == "zeek_conn":
                _update_ip(ev.get("orig_h"), ts, sid, int(ev.get("orig_bytes") or 0), 0)
                _update_ip(ev.get("resp_h"), ts, sid, 0, int(ev.get("resp_bytes") or 0))
            elif source == "suricata":
                _update_ip(ev.get("src_ip"),  ts, sid)
                _update_ip(ev.get("dest_ip"), ts, sid)
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
            "entity_type": "ip", "entity_value": ip,
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

    entity_key = _gold_s3_key("entity_gold", execution_date)
    _s3_write_parquet(entity_key, records)
    logger.info(
        "extract_entities 완료 — ip:%d domain:%d alert:%d → %s",
        len(ip_bucket), len(domain_bucket), len(alert_bucket), entity_key,
    )
    ctx["ti"].xcom_push(key="entity_key",   value=entity_key)
    ctx["ti"].xcom_push(key="entity_count", value=len(records))


# ══════════════════════════════════════════════════════════════════════════════
# Task 4 : extract_relations
# ══════════════════════════════════════════════════════════════════════════════

def extract_relations(**ctx) -> None:
    execution_date: datetime = ctx["logical_date"]
    session_key = ctx["ti"].xcom_pull(task_ids="extract_sessions", key="session_key")
    sessions    = _s3_read_parquet(session_key)
    raw         = _load_silver_records(ctx)
    cid_to_sid  = {
        s["community_id"]: s["session_id"]
        for s in sessions if s.get("community_id")
    }

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
        sid        = sess["session_id"]
        src_ip     = sess.get("src_ip")
        dest_ip    = sess.get("dest_ip")
        http_host  = sess.get("http_host")
        tls_sni    = sess.get("tls_sni")
        tls_cipher = sess.get("tls_cipher")
        dns_query  = sess.get("dns_query")
        dns_answers= sess.get("dns_answers")

        _add("ip", src_ip, "CONNECTED_TO", "ip", dest_ip, sid)
        if http_host:
            _add("ip", src_ip, "REQUESTED", "ip" if _is_ip(http_host) else "domain", http_host, sid)
        if tls_sni:
            _add("ip",      src_ip, "REQUESTED",       "domain", tls_sni, sid)
            _add("session", sid,    "SERVED_OVER_TLS", "domain", tls_sni, sid)
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
                _add(
                    "session", sid, "TRIGGERED", "alert",
                    str(ev.get("signature_id") or ev.get("signature")), sid,
                )

    relation_key = _gold_s3_key("relation_gold", execution_date)
    _s3_write_parquet(relation_key, records)
    logger.info("extract_relations 완료 — %d 관계 → %s", len(records), relation_key)
    ctx["ti"].xcom_push(key="relation_key",   value=relation_key)
    ctx["ti"].xcom_push(key="relation_count", value=len(records))


# ══════════════════════════════════════════════════════════════════════════════
# Task 5 : report_stats
# ══════════════════════════════════════════════════════════════════════════════

def report_stats(**ctx) -> None:
    ti             = ctx["ti"]
    total_lines    = ti.xcom_pull(task_ids="validate_input",    key="total_lines")
    session_count  = ti.xcom_pull(task_ids="extract_sessions",  key="session_count")
    entity_count   = ti.xcom_pull(task_ids="extract_entities",  key="entity_count")
    relation_count = ti.xcom_pull(task_ids="extract_relations", key="relation_count")
    session_key    = ti.xcom_pull(task_ids="extract_sessions",  key="session_key")
    entity_key     = ti.xcom_pull(task_ids="extract_entities",  key="entity_key")
    relation_key   = ti.xcom_pull(task_ids="extract_relations", key="relation_key")

    sessions  = _s3_read_parquet(session_key)
    entities  = _s3_read_parquet(entity_key)
    relations = _s3_read_parquet(relation_key)

    entity_types: dict[str, int] = defaultdict(int)
    for e in entities: entity_types[e["entity_type"]] += 1
    rel_types: dict[str, int] = defaultdict(int)
    for r in relations: rel_types[r["relation_type"]] += 1

    threat_count = sum(1 for s in sessions if s.get("is_threat"))
    tls_count    = sum(1 for s in sessions if s.get("tls_sni") or s.get("tls_cipher"))
    uid_count    = sum(1 for s in sessions if s.get("uid"))

    logger.info("=" * 65)
    logger.info("▶ Gold 전처리 파이프라인 완료 요약 (v9)")
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
    logger.info("  [저장 경로]")
    logger.info("    session  : s3://%s/%s", S3_BUCKET, session_key)
    logger.info("    entity   : s3://%s/%s", S3_BUCKET, entity_key)
    logger.info("    relation : s3://%s/%s", S3_BUCKET, relation_key)
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
    dag_id="unified_events_to_gold",
    description="Spark silver parquet → session/entity/relation gold 전처리 (v9)",
    default_args=default_args,
    start_date=datetime(2026, 1, 1),
    schedule="*/10 * * * *",
    catchup=False,
    max_active_runs=4,    # 배치 동시 처리
    max_active_tasks=6,
    tags=["cti", "graph-rag", "preprocessing"],
) as dag:

    # 다음 minute_10 폴더가 생기면 현재 배치 완성으로 판단
    wait_for_silver = PythonSensor(
        task_id="wait_for_silver",
        python_callable=_check_next_partition_exists,
        poke_interval=60,
        timeout=60 * 60,   # 최대 1시간 대기
        mode="poke",
    )

    t_validate  = PythonOperator(task_id="validate_input",    python_callable=validate_input)
    t_sessions  = PythonOperator(task_id="extract_sessions",  python_callable=extract_sessions)
    t_entities  = PythonOperator(task_id="extract_entities",  python_callable=extract_entities)
    t_relations = PythonOperator(task_id="extract_relations", python_callable=extract_relations)
    t_report    = PythonOperator(
        task_id="report_stats",
        python_callable=report_stats,
        outlets=[GOLD_SESSION_ASSET, GOLD_ENTITY_ASSET, GOLD_RELATION_ASSET],
    )

    # extract_sessions 완료 직후 neo4j_to_rag 트리거
    # run_id를 conf로 전달 → gold_to_neo4j / neo4j_to_rag 가 정확한 배치 식별
    t_trigger_rag = TriggerDagRunOperator(
        task_id="trigger_neo4j_to_rag",
        trigger_dag_id="neo4j_to_rag",
        wait_for_completion=False,
        conf={
            "session_key": "{{ ti.xcom_pull(task_ids='extract_sessions', key='session_key') }}",
            "source_run_id": "{{ run_id }}",   # ← run_id 전달 (gold_to_neo4j XCom 조회용)
        },
        reset_dag_run=True,
    )

    wait_for_silver >> t_validate >> t_sessions
    t_sessions >> t_trigger_rag
    t_sessions >> t_entities >> t_relations >> t_report