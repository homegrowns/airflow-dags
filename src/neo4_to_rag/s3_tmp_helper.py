import json
from typing import Any
from src.common.common_helper import s3_client
from security_metadata.aws_config import (
    S3_BUCKET,
    S3_TMP_PREFIX,
)


# ══════════════════════════════════════════════════════════════════════════════
# S3 tmp 읽기/쓰기 헬퍼
# ══════════════════════════════════════════════════════════════════════════════


def s3_tmp_key(run_id: str, stage: str) -> str:
    safe_run_id = re.sub(r"[^a-zA-Z0-9_\-.]", "-", run_id)
    return f"{S3_TMP_PREFIX}/{safe_run_id}/{stage}.json"


def s3_write_json(s3_key: str, data: Any) -> None:
    body = json.dumps(data, ensure_ascii=False).encode("utf-8")
    s3_client().put_object(
        Bucket=S3_BUCKET,
        Key=s3_key,
        Body=body,
        ContentType="application/json",
    )
    logger.info("_s3_write_json: s3://%s/%s (%d bytes)", S3_BUCKET, s3_key, len(body))


def s3_read_json(s3_key: str) -> Any:
    obj = s3_client().get_object(Bucket=S3_BUCKET, Key=s3_key)
    data = json.loads(obj["Body"].read().decode("utf-8"))
    logger.info("_s3_read_json: s3://%s/%s 로드 완료", S3_BUCKET, s3_key)
    return data


def s3_delete(s3_key: str) -> None:
    try:
        s3_client().delete_object(Bucket=S3_BUCKET, Key=s3_key)
        logger.info("_s3_delete: %s 삭제 완료", s3_key)
    except Exception as e:
        logger.warning("_s3_delete: %s 삭제 실패 — %s", s3_key, e)
