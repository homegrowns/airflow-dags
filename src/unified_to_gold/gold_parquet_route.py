from datetime import datetime, timezone, timedelta

from security_metadata.aws_config import (
    S3_SILVER_PREFIX,
    S3_GOLD_PREFIX,
)
from src.common.common_helper import (
    to_kst,
)

# ── gold parquet 경로 생성 ────────────────────────────────────────────────────


def gold_s3_key(table: str, execution_date: datetime) -> str:
    """
    KST 기준 gold parquet 경로.
    예) gold/session_gold/dt=2026-03-29/hour=01/minute_10=50/minute_10=50_session_gold.parquet
    """
    kst = to_kst(execution_date)
    dt = kst.strftime("%Y-%m-%d")
    hour = kst.strftime("%H")
    minute_10 = f"{(kst.minute // 10) * 10:02d}"
    return (
        f"{S3_GOLD_PREFIX}/{table}"
        f"/dt={dt}/hour={hour}/minute_10={minute_10}"
        f"/minute_10={minute_10}_{table}.parquet"
    )


def silver_sensor_prefix(execution_date: datetime) -> str:
    # # ── 임시 테스트용 override ─────────────────────────────
    # TEST_PREFIX = "silver/common_records/dt=2026-03-29/hour=03/minute_10=50/"
    # logger.warning("_silver_sensor_prefix: TEST_PREFIX override — %s", TEST_PREFIX)
    # return TEST_PREFIX
    # ── 테스트 끝나면 제거 ────────────────────────────────
    """KST 기준 silver prefix."""
    kst = to_kst(execution_date)
    dt = kst.strftime("%Y-%m-%d")
    hour = kst.strftime("%H")
    minute_10 = f"{(kst.minute // 10) * 10:02d}"
    return f"{S3_SILVER_PREFIX}dt={dt}/hour={hour}/minute_10={minute_10}/"


def next_silver_prefix(execution_date: datetime) -> str:
    # ── 임시: 이미 존재하는 경로로 고정 ──────────────────
    # return "silver/common_records/dt=2026-03-29/hour=04/minute_10=00/"
    # """현재 배치의 다음 minute_10 silver prefix (KST 기준)."""
    kst = to_kst(execution_date)
    next_minute = ((kst.minute // 10) + 1) * 10

    if next_minute >= 60:
        next_kst = kst.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        next_minute = 0
    else:
        next_kst = kst

    dt = next_kst.strftime("%Y-%m-%d")
    hour = next_kst.strftime("%H")
    return f"{S3_SILVER_PREFIX}dt={dt}/hour={hour}/minute_10={next_minute:02d}/"

