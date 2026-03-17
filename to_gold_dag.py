"""
dag_unified_to_gold.py
S3 unified_events.parquet → session_gold / entity_gold / relation_gold 전처리 DAG

Pipeline:
  [fetch_from_s3]      ← S3에서 unified_events.parquet 다운로드 (5분 주기)
       ↓
  [parquet_to_jsonl]   ← parquet → unified_events.jsonl 변환
       ↓
  [validate_input]     ← JSONL 파일 존재 및 행 수 검증
       ↓
  [extract_sessions]   ← unified_events.jsonl 행별 파싱 → session_gold.jsonl
       ↓
  [extract_entities]   ← session_gold 기반 IP·Domain·Alert 집계 → entity_gold.jsonl
       ↓
  [extract_relations]  ← session_gold + entity_gold 기반 관계 추출 → relation_gold.jsonl
       ↓
  [report_stats]       ← 3개 gold 파일 요약 통계 로그

스키마:
  session_gold  : session_id, community_id, src_ip, dst_ip, dst_port,
                  http_host, uri, tls_sni, alert_count, max_severity,
                  is_threat, flow_start, flow_end, proto, service

  entity_gold   : entity_type(ip|domain|alert), entity_value,
                  first_seen, last_seen, related_session_count,
                  [ip 전용] total_orig_bytes, total_resp_bytes,
                  [alert 전용] signature, category

  relation_gold : src_type, src_value, relation_type, dst_type, dst_value,
                  session_id
                  relation_type 종류:
                    CONNECTED_TO   (ip → ip)
                    REQUESTED      (ip → domain)
                    TRIGGERED      (session → alert)
                    RESOLVED_BY    (domain → ip, DNS answers)

Author : Linda
"""

from __future__ import annotations

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

from airflow.providers.amazon.aws.hooks.s3 import S3Hook

# ── S3 설정 (환경에 맞게 수정) ───────────────────────────────────────────────
S3_BUCKET        = "malware-project-bucket"                        # S3 버킷명
S3_KEY           = "unified_events.parquet"     # S3 오브젝트 경로
AWS_REGION       = "ap-northeast-2"                      # 리전
# AWS 자격증명은 환경변수(AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) 또는
# Airflow Connection(conn_id="aws_default") 으로 관리 권장

# ── 로컬 경로 설정 ────────────────────────────────────────────────────────────
DATA_DIR     = Path("/opt/airflow/data")
PARQUET_PATH = DATA_DIR / "unified_events.parquet"
INPUT_PATH   = DATA_DIR / "unified_events.jsonl"
OUTPUT_DIR   = DATA_DIR / "gold"
SESSION_OUT  = OUTPUT_DIR / "session_gold.jsonl"
ENTITY_OUT   = OUTPUT_DIR / "entity_gold.jsonl"
RELATION_OUT = OUTPUT_DIR / "relation_gold.jsonl"

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# Task 0-1 : fetch_from_s3
# ══════════════════════════════════════════════════════════════════════════════

def fetch_from_s3(**ctx) -> None:
    """
    S3에서 unified_events.parquet 를 로컬로 다운로드.

    변경 없으면 스킵:
      S3 ETag vs 로컬에 저장된 마지막 ETag 비교 → 동일하면 skip_flag XCom 전달
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    etag_path = DATA_DIR / ".last_etag"

    # ← region_name 제거, 인자 없이 사용 (성공한 DAG와 동일 방식)
    # s3 = boto3.client("s3")
    hook = S3Hook(aws_conn_id="aws_default")
    s3 = hook.get_conn()

    # ── 임시 진단: 버킷 루트 목록 확인 ──
    try:
        resp = s3.list_objects_v2(Bucket=S3_BUCKET, MaxKeys=10)
        for obj in resp.get("Contents", []):
            logger.info("버킷 내 파일: %s", obj["Key"])
    except Exception as e:
        logger.error("list_objects 실패: %s", e)

    # S3 오브젝트 메타데이터로 ETag 확인
    head = s3.head_object(Bucket=S3_BUCKET, Key=S3_KEY)
    s3_etag = head["ETag"].strip('"')

    # 이전 ETag와 비교
    if etag_path.exists():
        last_etag = etag_path.read_text().strip()
        if last_etag == s3_etag:
            logger.info("S3 파일 변경 없음 (ETag=%s) — 다운로드 스킵", s3_etag)
            ctx["ti"].xcom_push(key="skip", value=True)
            return

    # 다운로드
    logger.info("S3 다운로드 시작: s3://%s/%s", S3_BUCKET, S3_KEY)
    s3.download_file(S3_BUCKET, S3_KEY, str(PARQUET_PATH))
    etag_path.write_text(s3_etag)
    logger.info("다운로드 완료 → %s (ETag=%s)", PARQUET_PATH, s3_etag)
    ctx["ti"].xcom_push(key="skip", value=False)


# ══════════════════════════════════════════════════════════════════════════════
# Task 0-2 : parquet_to_jsonl
# ══════════════════════════════════════════════════════════════════════════════

def parquet_to_jsonl(**ctx) -> None:
    """
    unified_events.parquet → unified_events.jsonl 변환.

    fetch_from_s3 에서 skip=True 를 받으면 변환도 스킵
    (이미 최신 JSONL 이 로컬에 존재하는 경우).

    Parquet 스키마 가정:
      - timeline 컬럼: JSON 직렬화된 문자열 또는 list[dict]
      - 나머지 컬럼: community_id, flow_start, flow_end,
                    is_threat, threat_level, alert_count
    """
    import pandas as pd
    import io

    skip = ctx["ti"].xcom_pull(task_ids="fetch_from_s3", key="skip")
    if skip and INPUT_PATH.exists():
        logger.info("S3 변경 없음 — parquet 변환 스킵")
        return
    
    # 로컬 파일 대신 s3에서 직접 읽기
    # if not PARQUET_PATH.exists():
     #   raise FileNotFoundError(f"Parquet 파일 없음: {PARQUET_PATH}")

    logger.info("S3에서 parquet 직접 로드: %s", PARQUET_PATH)
    s3 = boto3.client("s3")
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

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(INPUT_PATH, "w", encoding="utf-8") as f:
        for _, row in df.iterrows():
            record = row.to_dict()

            # timeline 컬럼이 문자열로 저장된 경우 파싱
            if isinstance(record.get("timeline"), str):
                try:
                    record["timeline"] = json.loads(record["timeline"])
                except json.JSONDecodeError:
                    record["timeline"] = []

            # NaN → None 정리
            record = {k: _convert(v) for k, v in record.items()}
            
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

    logger.info("parquet_to_jsonl 완료 — %d 행 → %s", count, INPUT_PATH)
    ctx["ti"].xcom_push(key="jsonl_rows", value=count)


# ══════════════════════════════════════════════════════════════════════════════
# 공통 유틸
# ══════════════════════════════════════════════════════════════════════════════

def _make_session_id(community_id: str | None, idx: int) -> str:
    """
    community_id가 있으면 SHA-1 앞 8자리, 없으면 seq 번호로 session_id 생성.
    예) s_a1b2c3d4  /  s_orphan_0042
    """
    if community_id:
        h = hashlib.sha1(community_id.encode()).hexdigest()[:8]
        return f"s_{h}"
    return f"s_orphan_{idx:04d}"


def _get(ev: dict, *keys: str, default=None) -> Any:
    """이벤트 딕셔너리에서 첫 번째로 값이 있는 키 반환"""
    for k in keys:
        v = ev.get(k)
        if v is not None:
            return v
    return default


def _load_jsonl(path: Path) -> list[dict]:
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


# ══════════════════════════════════════════════════════════════════════════════
# Task 1 : validate_input
# ══════════════════════════════════════════════════════════════════════════════

def validate_input(**ctx) -> None:
    """입력 파일 존재 여부 및 최소 행 수 검증"""
    if not INPUT_PATH.exists():
        raise FileNotFoundError(f"입력 파일 없음: {INPUT_PATH}")

    line_count = sum(1 for _ in open(INPUT_PATH, "r", encoding="utf-8"))
    if line_count == 0:
        raise ValueError("unified_events.jsonl 가 비어 있습니다.")

    logger.info("validate_input OK — 총 %d 행", line_count)
    ctx["ti"].xcom_push(key="total_lines", value=line_count)


# ══════════════════════════════════════════════════════════════════════════════
# Task 2 : extract_sessions
# ══════════════════════════════════════════════════════════════════════════════

def _extract_conn(timeline: list[dict]) -> dict:
    """zeek_conn 이벤트에서 네트워크 식별자 추출"""
    for ev in timeline:
        if ev.get("source") == "zeek_conn":
            return {
                "src_ip":   ev.get("orig_h"),
                "src_port": ev.get("orig_p"),
                "dst_ip":   ev.get("resp_h"),
                "dst_port": ev.get("resp_p"),
                "proto":    ev.get("proto"),
                "service":  ev.get("service"),
            }
    # zeek_conn 없으면 suricata에서 폴백
    for ev in timeline:
        if ev.get("source") == "suricata":
            return {
                "src_ip":   ev.get("src_ip"),
                "src_port": str(ev.get("src_port", "")),
                "dst_ip":   ev.get("dest_ip"),
                "dst_port": str(ev.get("dest_port", "")),
                "proto":    ev.get("proto", "").lower(),
                "service":  None,
            }
    return {}


def _is_ip(value: str) -> bool:
    """단순 IPv4 판별 (entity 분류용)"""
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _extract_http(timeline: list[dict]) -> tuple[str | None, str | None]:
    """zeek_http → (host, uri) 첫 번째 값

    host 우선, uri는 경로 정보.
    "1.234.184.156:443" 처럼 포트가 붙는 경우 포트를 제거하고 반환.
    """
    for ev in timeline:
        if ev.get("source") == "zeek_http":
            host = ev.get("host")
            if host and ":" in host:
                # "host:port" → "host"
                host = host.rsplit(":", 1)[0]
            return host, ev.get("uri")
    return None, None


def _extract_sni(timeline: list[dict]) -> str | None:
    """zeek_ssl → server_name"""
    for ev in timeline:
        if ev.get("source") == "zeek_ssl":
            return ev.get("server_name")
    return None


def _extract_alert_stats(timeline: list[dict]) -> tuple[int, int | None]:
    """suricata 이벤트 중 실제 alert(signature 있는 것)만 집계"""
    severities = []
    alert_count = 0
    for ev in timeline:
        if ev.get("source") == "suricata" and ev.get("signature"):
            alert_count += 1
            if ev.get("severity") is not None:
                severities.append(int(ev["severity"]))
    max_sev = min(severities) if severities else None  # 숫자 낮을수록 높은 위험
    return alert_count, max_sev


def extract_sessions(**ctx) -> None:
    """
    unified_events.jsonl 행 → session_gold 레코드 생성
    중복 community_id는 마지막 등장 레코드로 덮어씀 (orphan은 별도 seq)
    """
    raw_sessions = _load_jsonl(INPUT_PATH)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    seen_cids: dict[str, str] = {}   # community_id → session_id (중복 추적)
    orphan_idx = 0
    records: list[dict] = []

    for session in raw_sessions:
        cid = session.get("community_id")

        # session_id 결정 (중복 community_id 재사용)
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
        conn     = _extract_conn(timeline)
        http_host, uri = _extract_http(timeline)
        tls_sni  = _extract_sni(timeline)
        alert_count, max_severity = _extract_alert_stats(timeline)

        # alert_count는 preprocess_raw 집계 값을 우선, fallback은 재계산 값
        final_alert_count = session.get("alert_count", alert_count)

        records.append({
            "session_id":   session_id,
            "community_id": cid,
            "src_ip":       conn.get("src_ip"),
            "src_port":     conn.get("src_port"),
            "dst_ip":       conn.get("dst_ip"),
            "dst_port":     conn.get("dst_port"),
            "proto":        conn.get("proto"),
            "service":      conn.get("service"),
            "http_host":    http_host,
            "uri":          uri,
            "tls_sni":      tls_sni,
            "alert_count":  final_alert_count,
            "max_severity": max_severity,
            "is_threat":    session.get("is_threat", False),
            "flow_start":   session.get("flow_start"),
            "flow_end":     session.get("flow_end"),
        })

    _write_jsonl(SESSION_OUT, records)
    logger.info("extract_sessions 완료 — %d 세션 → %s", len(records), SESSION_OUT)
    ctx["ti"].xcom_push(key="session_count", value=len(records))


# ══════════════════════════════════════════════════════════════════════════════
# Task 3 : extract_entities
# ══════════════════════════════════════════════════════════════════════════════

def extract_entities(**ctx) -> None:
    """
    session_gold + unified timeline 기반 entity 집계

    entity_type:
      ip     – src_ip / dst_ip / DNS 응답 IP
      domain – http_host / tls_sni / DNS query·answers
      alert  – 고유 (signature_id, signature) 쌍
    """
    sessions  = _load_jsonl(SESSION_OUT)
    raw       = _load_jsonl(INPUT_PATH)     # timeline 원본 (DNS answers 등)

    # session_id → session (빠른 조회)
    sid_map = {s["session_id"]: s for s in sessions}

    # ── 집계 버킷 ─────────────────────────────────────────────────────────────
    # ip_bucket[ip] = {first_seen, last_seen, sessions, orig_bytes, resp_bytes}
    ip_bucket:     dict[str, dict] = {}
    domain_bucket: dict[str, dict] = {}
    alert_bucket:  dict[str, dict] = {}

    def _update_ip(ip: str, ts: str | None, session_id: str,
                   orig_bytes: int = 0, resp_bytes: int = 0) -> None:
        if not ip:
            return
        b = ip_bucket.setdefault(ip, {
            "first_seen": ts, "last_seen": ts,
            "sessions": set(), "orig_bytes": 0, "resp_bytes": 0,
        })
        if ts:
            if not b["first_seen"] or ts < b["first_seen"]:
                b["first_seen"] = ts
            if not b["last_seen"] or ts > b["last_seen"]:
                b["last_seen"] = ts
        b["sessions"].add(session_id)
        b["orig_bytes"] += orig_bytes
        b["resp_bytes"] += resp_bytes

    def _update_domain(domain: str, ts: str | None, session_id: str) -> None:
        if not domain:
            return
        b = domain_bucket.setdefault(domain, {
            "first_seen": ts, "last_seen": ts, "sessions": set(),
        })
        if ts:
            if not b["first_seen"] or ts < b["first_seen"]:
                b["first_seen"] = ts
            if not b["last_seen"] or ts > b["last_seen"]:
                b["last_seen"] = ts
        b["sessions"].add(session_id)

    def _update_alert(sig_id: Any, sig: str | None,
                      category: str | None, severity: Any,
                      ts: str | None, session_id: str) -> None:
        if not sig_id and not sig:
            return
        key = str(sig_id or sig)
        b = alert_bucket.setdefault(key, {
            "first_seen": ts, "last_seen": ts,
            "sessions": set(), "signature": sig,
            "signature_id": sig_id, "category": category,
        })
        if ts:
            if not b["first_seen"] or ts < b["first_seen"]:
                b["first_seen"] = ts
            if not b["last_seen"] or ts > b["last_seen"]:
                b["last_seen"] = ts
        b["sessions"].add(session_id)

    # ── session_gold 기반 IP / Domain 집계 ───────────────────────────────────
    for sess in sessions:
        sid = sess["session_id"]
        ts_start = sess.get("flow_start")

        _update_ip(sess.get("src_ip"), ts_start, sid)
        _update_ip(sess.get("dst_ip"), ts_start, sid)
        # http_host가 IP("1.2.3.4")인지 도메인인지 분기
        http_host = sess.get("http_host")
        if http_host:
            if _is_ip(http_host):
                _update_ip(http_host, ts_start, sid)
            else:
                _update_domain(http_host, ts_start, sid)
        _update_domain(sess.get("tls_sni"), ts_start, sid)

    # ── timeline 원본 기반 세부 집계 ─────────────────────────────────────────
    # session_id를 community_id로 역조회하기 위해 cid→sid 맵 생성
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
                # DNS 응답의 IP들도 entity로 등록
                answers_raw = ev.get("answers")
                if answers_raw:
                    for ans in str(answers_raw).split(","):
                        ans = ans.strip()
                        # 간단한 IPv4 체크
                        parts = ans.split(".")
                        if len(parts) == 4 and all(p.isdigit() for p in parts):
                            _update_ip(ans, ts, sid)
                        elif ans:
                            _update_domain(ans, ts, sid)

            elif source == "suricata":
                if ev.get("signature"):     # 실제 alert만
                    _update_alert(
                        ev.get("signature_id"), ev.get("signature"),
                        ev.get("category"),    ev.get("severity"),
                        ts, sid,
                    )

    # ── 레코드 직렬화 ─────────────────────────────────────────────────────────
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

    _write_jsonl(ENTITY_OUT, records)
    logger.info(
        "extract_entities 완료 — ip:%d domain:%d alert:%d → %s",
        len(ip_bucket), len(domain_bucket), len(alert_bucket), ENTITY_OUT,
    )
    ctx["ti"].xcom_push(key="entity_count", value=len(records))


# ══════════════════════════════════════════════════════════════════════════════
# Task 4 : extract_relations
# ══════════════════════════════════════════════════════════════════════════════

def extract_relations(**ctx) -> None:
    """
    relation_gold 생성

    relation_type:
      CONNECTED_TO  : ip → ip          (zeek_conn / suricata src→dst)
      REQUESTED     : ip → domain      (http_host, tls_sni)
      TRIGGERED     : session → alert  (suricata signature 있는 이벤트)
      RESOLVED_BY   : domain → ip      (zeek_dns answers)
    """
    sessions = _load_jsonl(SESSION_OUT)
    raw      = _load_jsonl(INPUT_PATH)

    cid_to_sid = {s["community_id"]: s["session_id"]
                  for s in sessions if s.get("community_id")}

    # 중복 제거용 set
    seen: set[tuple] = set()
    records: list[dict] = []

    def _add(src_type, src_val, rel, dst_type, dst_val, sid) -> None:
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

    # ── session_gold 기반 기본 관계 ───────────────────────────────────────────
    for sess in sessions:
        sid      = sess["session_id"]
        src_ip   = sess.get("src_ip")
        dst_ip   = sess.get("dst_ip")
        http_host = sess.get("http_host")
        tls_sni  = sess.get("tls_sni")

        # CONNECTED_TO
        _add("ip", src_ip, "CONNECTED_TO", "ip", dst_ip, sid)

        # REQUESTED (http_host) — IP면 dst_type을 "ip"로 분기
        if http_host:
            dst_type = "ip" if _is_ip(http_host) else "domain"
            _add("ip", src_ip, "REQUESTED", dst_type, http_host, sid)

        # REQUESTED (tls_sni)
        if tls_sni:
            _add("ip", src_ip, "REQUESTED", "domain", tls_sni, sid)

    # ── timeline 원본 기반 세부 관계 ─────────────────────────────────────────
    for raw_sess in raw:
        cid = raw_sess.get("community_id")
        sid = cid_to_sid.get(cid, "unknown")

        for ev in raw_sess.get("timeline", []):
            source = ev.get("source")

            if source == "zeek_dns":
                query       = ev.get("query")
                answers_raw = ev.get("answers")
                orig_h      = ev.get("orig_h")

                # ip REQUESTED domain (DNS query)
                if orig_h and query:
                    _add("ip", orig_h, "REQUESTED", "domain", query, sid)

                # domain RESOLVED_BY ip (DNS answers)
                if query and answers_raw:
                    for ans in str(answers_raw).split(","):
                        ans = ans.strip()
                        parts = ans.split(".")
                        if len(parts) == 4 and all(p.isdigit() for p in parts):
                            _add("domain", query, "RESOLVED_BY", "ip", ans, sid)
                        elif ans and ans != query:
                            # CNAME chain
                            _add("domain", query, "RESOLVED_BY", "domain", ans, sid)

            elif source == "suricata" and ev.get("signature"):
                # session TRIGGERED alert
                sig_key = str(ev.get("signature_id") or ev.get("signature"))
                _add("session", sid, "TRIGGERED", "alert", sig_key, sid)

    _write_jsonl(RELATION_OUT, records)
    logger.info("extract_relations 완료 — %d 관계 → %s", len(records), RELATION_OUT)
    ctx["ti"].xcom_push(key="relation_count", value=len(records))


# ══════════════════════════════════════════════════════════════════════════════
# Task 5 : report_stats
# ══════════════════════════════════════════════════════════════════════════════

def report_stats(**ctx) -> None:
    ti = ctx["ti"]
    total_lines    = ti.xcom_pull(task_ids="validate_input",   key="total_lines")
    session_count  = ti.xcom_pull(task_ids="extract_sessions", key="session_count")
    entity_count   = ti.xcom_pull(task_ids="extract_entities", key="entity_count")
    relation_count = ti.xcom_pull(task_ids="extract_relations", key="relation_count")

    # entity 타입별 분류
    entity_types: dict[str, int] = defaultdict(int)
    for e in _load_jsonl(ENTITY_OUT):
        entity_types[e["entity_type"]] += 1

    # relation 타입별 분류
    rel_types: dict[str, int] = defaultdict(int)
    for r in _load_jsonl(RELATION_OUT):
        rel_types[r["relation_type"]] += 1

    # threat 세션 비율
    threat_count = sum(1 for s in _load_jsonl(SESSION_OUT) if s.get("is_threat"))

    logger.info("=" * 60)
    logger.info("▶ Gold 전처리 파이프라인 완료 요약")
    logger.info("=" * 60)
    logger.info("  [Input]  unified_events.jsonl : %s 행", total_lines)
    logger.info("  [Output] session_gold         : %s 세션 (위협 %s개, %.1f%%)",
                session_count, threat_count,
                100 * threat_count / session_count if session_count else 0)
    logger.info("  [Output] entity_gold          : %s 엔티티", entity_count)
    for etype, cnt in entity_types.items():
        logger.info("             ├ %-8s : %s", etype, cnt)
    logger.info("  [Output] relation_gold        : %s 관계", relation_count)
    for rtype, cnt in rel_types.items():
        logger.info("             ├ %-20s : %s", rtype, cnt)
    logger.info("=" * 60)
    logger.info("  session_gold  → %s", SESSION_OUT)
    logger.info("  entity_gold   → %s", ENTITY_OUT)
    logger.info("  relation_gold → %s", RELATION_OUT)
    logger.info("=" * 60)


# ══════════════════════════════════════════════════════════════════════════════
# DAG 정의
# ══════════════════════════════════════════════════════════════════════════════

default_args = {
    "owner":            "cti_lab",
    "depends_on_past":  False,
    "retries":          1,
    "retry_delay":      timedelta(minutes=3),
    "email_on_failure": False,
}

with DAG(
    dag_id="unified_events_to_gold",
    description="S3 parquet → session/entity/relation gold 전처리 (5분 주기)",
    default_args=default_args,
    start_date=datetime(2026, 1, 1),
    schedule="*/5 * * * *",    # 5분마다 실행
    catchup=False,
    max_active_runs=1,                   # 동시 실행 1개 제한 (중복 방지)
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
    )

    # ── 의존성 체인 ────────────────────────────────────────────────────────────
    t_fetch >> t_convert >> t_validate >> t_sessions >> t_entities >> t_relations >> t_report
