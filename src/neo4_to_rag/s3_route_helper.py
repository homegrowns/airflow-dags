import re

from src.common.common_helper import s3_client
from src.security_metadata.aws_config import (
    S3_BUCKET,
    S3_SESSION_GOLD_PREFIX,
    S3_RAG_PREFIX,
)

# ══════════════════════════════════════════════════════════════════════════════
# session_gold S3 경로 헬퍼
# ══════════════════════════════════════════════════════════════════════════════


def list_session_gold_keys(prefix: str) -> list[str]:
    s3 = s3_client()
    paginator = s3.get_paginator("list_objects_v2")
    keys: list[str] = []
    for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith(".parquet") and "_SUCCESS" not in key:
                keys.append(key)
    return keys


def parse_gold_partition(prefix: str) -> dict[str, str]:
    dt_m = re.search(r"dt=([^/]+)", prefix)
    hour_m = re.search(r"hour=(\d+)", prefix)
    minute_m = re.search(r"minute(?:_10)?=(\d+)", prefix)

    if dt_m and hour_m and minute_m:
        return {
            "dt": dt_m.group(1),
            "hour": hour_m.group(1),
            "minute": minute_m.group(1),
        }

    now = datetime.now(tz=KST)
    logger.warning("_parse_gold_partition: 파싱 실패 — KST 현재값 fallback")
    return {
        "dt": now.strftime("%Y-%m-%d"),
        "hour": str(now.hour),
        "minute": str((now.minute // 10) * 10),
    }


def build_rag_s3_key(partition: dict[str, str]) -> str:
    dt = partition["dt"]
    hour = int(partition["hour"])
    minute = int(partition["minute"])
    return (
        f"{S3_RAG_PREFIX}/"
        f"dt={dt}/"
        f"hour={hour:02d}_minute={minute:02d}_rag_results.jsonl"
    )
