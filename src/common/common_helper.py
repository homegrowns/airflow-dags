import io
from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo
import hashlib

from airflow.models import Variable

from security_metadata.aws_config import (
    S3_BUCKET,
    AWS_REGION,
    BATCH_SIZE,
)

import boto3

def s3_client():
    return boto3.client("s3", region_name=AWS_REGION)


# ══════════════════════════════════════════════════════════════════════════════
# unified_to_gold 공통 헬퍼
# TODO: 아래 시간 변환 함수 다 같은거 아닌가?
# ══════════════════════════════════════════════════════════════════════════════

def to_kst(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(KST)


def ms_to_kst_iso(ms: Any) -> str | None:
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
        return (
            datetime.fromtimestamp(int(ms) / 1000.0, tz=timezone.utc)
            .astimezone(KST)
            .isoformat()
        )
    except (ValueError, TypeError, OSError):
        return str(ms)


# ══════════════════════════════════════════════════════════════════════════════
# gold_to_neo4j 공통 헬퍼
# ══════════════════════════════════════════════════════════════════════════════

def s3_read_parquet(s3_key: str) -> list[dict]:
    import pandas as pd

    obj = _s3_client().get_object(Bucket=S3_BUCKET, Key=s3_key)
    df = pd.read_parquet(io.BytesIO(obj["Body"].read()))
    return df.where(df.notna(), None).to_dict(orient="records")


def neo4j_driver():
    from neo4j import GraphDatabase

    uri = Variable.get("NEO4J_URI")
    user = Variable.get("NEO4J_USER")
    pw = Variable.get("NEO4J_PASSWORD")
    return GraphDatabase.driver(uri, auth=(user, pw))


def run_batches(
    session, query: str, records: list[dict], batch_size: int = BATCH_SIZE
) -> int:
    total = 0
    for i in range(0, len(records), batch_size):
        session.run(query, rows=records[i : i + batch_size])
        total += len(records[i : i + batch_size])
    return total


def sibling_key(session_key: str, table: str) -> str:
    return session_key.replace("session_gold", table)


def prefix_from_key(s3_key: str) -> str:
    return s3_key.rsplit("/", 1)[0] + "/"


def to_kst_iso(ts: Any) -> str | None:
    if ts is None:
        return None
    if isinstance(ts, str):
        try:
            s = ts.replace(" ", "T")
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(KST).isoformat()
        except Exception:
            return ts
    try:
        v = float(ts)
        if v > 1e10:
            v /= 1000.0
        return datetime.fromtimestamp(v, tz=timezone.utc).astimezone(KST).isoformat()
    except Exception:
        return str(ts)


def get_source_run_id(ctx) -> str | None:
    """
    Asset 트리거한 unified_events_to_gold 의 run_id 추출.
    consumed_asset_events 에서 session_gold Asset 을 emit 한 run_id 반환.
    """
    try:
        events = ctx["dag_run"].consumed_asset_events or []
        for event in events:
            if "session_gold" in str(getattr(event, "asset_uri", "")):
                return event.source_run_id
        # fallback: 첫 번째 이벤트 run_id
        if events:
            return events[0].source_run_id
    except Exception as e:
        logger.warning("_get_source_run_id: consumed_asset_events 조회 실패 — %s", e)
    return None

# ══════════════════════════════════════════════════════════════════════════════
# neo4_to_rag 공통 헬퍼
# ══════════════════════════════════════════════════════════════════════════════

def neo4j_driver():
    from neo4j import GraphDatabase

    uri = Variable.get("NEO4J_URI")
    user = Variable.get("NEO4J_USER")
    pw = Variable.get("NEO4J_PASSWORD")
    return GraphDatabase.driver(uri, auth=(user, pw))


def groq_client():
    from groq import Groq

    return Groq(api_key=Variable.get("GROQ_API_KEY"), max_retries=1, timeout=10.0)


def groq_model() -> str:
    try:
        return Variable.get("GROQ_MODEL")
    except Exception:
        return GROQ_MODEL_DEFAULT


def make_session_id(community_id: str | None, idx: int) -> str:
    if community_id:
        return f"s_{hashlib.sha1(community_id.encode()).hexdigest()[:8]}"
    return f"s_orphan_{idx:04d}"


def now_kst_iso() -> str:
    return datetime.now(tz=KST).isoformat()


def ms_to_kst_iso(ms: Any) -> str | None:
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
        return (
            datetime.fromtimestamp(int(ms) / 1000.0, tz=timezone.utc)
            .astimezone(KST)
            .isoformat()
        )
    except Exception:
        return str(ms)

