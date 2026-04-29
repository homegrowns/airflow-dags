import hashlib
import io
import json
import logging
from datetime import datetime
from typing import Any

from src.common.common_helper import (
    ms_to_kst_iso,
    s3_client,
)
from src.security_metadata.aws_config import S3_BUCKET
from src.unified_to_gold.gold_parquet_route import silver_sensor_prefix

logger = logging.getLogger(__name__)


# silver prefix 헬퍼
def list_silver_parquet_keys(prefix: str) -> list[str]:
    s3 = s3_client()
    paginator = s3.get_paginator("list_objects_v2")
    keys: list[str] = []
    for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith(".parquet") and "_SUCCESS" not in key:
                keys.append(key)
    return keys


# silver parquet 로딩 공통 헬퍼
def load_silver_records(ctx) -> list[dict]:
    """
    DAG 실행 시각 기준 silver prefix 내 parquet 전체 읽기
    → community_id 기준 통합 → list[dict] 반환.
    """
    import pandas as pd

    # ── 테스트 모드: conf에 test_prefix가 있으면 고정 prefix 사용 ──
    """
    test_prefix 예시
    {
    "test_prefix": "silver/common_records/dt=2026-04-03/hour=22/minute_10=30/batch_seq=00000/"
    }
    """
    conf = ctx["dag_run"].conf or {}
    test_prefix = conf.get("test_prefix")

    if test_prefix:
        prefix = test_prefix
        logger.info("_load_silver_records: 테스트 모드 — prefix=%s", prefix)
    else:
        execution_date: datetime = ctx["logical_date"]
        prefix = silver_sensor_prefix(execution_date)

    keys = list_silver_parquet_keys(prefix)

    if not keys:
        # wait_for_silver 통과 후 여기 오면 안 됨
        raise ValueError(f"silver parquet 없음 — prefix: {prefix}")

    s3 = s3_client()
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
    df = df.drop(
        columns=[c for c in ("dt", "hour", "batch_seq", "minute_10") if c in df.columns]
    )
    if "flow_start" in df.columns:
        df = df.sort_values("flow_start", na_position="last")

    def _convert(v: Any) -> Any:
        if isinstance(v, float) and v != v:
            return None
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, str)):
            return v
        if hasattr(v, "item"):
            return v.item()
        if isinstance(v, list):
            return v
        return v

    NON_NULL_OVERWRITE_FIELDS = (
        "uid",
        "flow_id",
        "src_ip",
        "src_port",
        "dest_ip",
        "dest_port",
        "proto",
        "service",
        "is_threat",
        "alert_count",
        "threat_level",
    )

    merged: dict[str, dict] = {}
    orphan_idx = 0

    for row in df.to_dict(orient="records"):
        record = {k: _convert(v) for k, v in row.items()}
        record["flow_start"] = ms_to_kst_iso(record.get("flow_start"))
        record["flow_end"] = ms_to_kst_iso(record.get("flow_end"))

        tl_raw = record.get("timeline", [])
        if isinstance(tl_raw, str):
            try:
                tl_parsed = json.loads(tl_raw)
                if not isinstance(tl_parsed, list):
                    tl_parsed = []
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
            for f in NON_NULL_OVERWRITE_FIELDS:
                if record.get(f) is not None:
                    ex[f] = record[f]
            fs_old, fs_new = ex.get("flow_start"), record.get("flow_start")
            if fs_old and fs_new:
                ex["flow_start"] = min(fs_old, fs_new)
            elif fs_new:
                ex["flow_start"] = fs_new
            fe_old, fe_new = ex.get("flow_end"), record.get("flow_end")
            if fe_old and fe_new:
                ex["flow_end"] = max(fe_old, fe_new)
            elif fe_new:
                ex["flow_end"] = fe_new

    records = list(merged.values())
    logger.info(
        "_load_silver_records 완료 — community_id 기준 %d 레코드 (prefix: %s)",
        len(records),
        prefix,
    )
    return records


# 공통 유틸


def make_session_id(community_id: str | None, idx: int) -> str:
    if community_id:
        return f"s_{hashlib.sha1(community_id.encode()).hexdigest()[:8]}"
    return f"s_orphan_{idx:04d}"


def is_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)
