import threading

from src.common.common_helper import s3_client
from security_metadata.aws_config import (
    S3_BUCKET,
)


# ══════════════════════════════════════════════════════════════════════════════
# S3StreamingWriter (단일 청크 내 write용)
# ══════════════════════════════════════════════════════════════════════════════


class _S3StreamingWriter:
    def __init__(self, s3_key: str):
        self._s3_key = s3_key
        self._lines: list[str] = []
        self._lock = threading.Lock()
        self._write_errors: list[str] = []
        self._checkpoint_keys: list[str] = []
        self._executor = ThreadPoolExecutor(
            max_workers=S3_WRITE_WORKERS,
            thread_name_prefix="s3_rag_writer",
        )
        self._futures: list[Future] = []

    def start(self) -> None:
        pass

    def put(self, result: dict) -> None:
        line = json.dumps(result, ensure_ascii=False)
        with self._lock:
            self._lines.append(line)
            f = self._executor.submit(self._write_single_line, line)
            self._futures.append(f)

    def finish(self) -> tuple[int, int]:
        with self._lock:
            futures_snapshot = list(self._futures)

        for f in futures_snapshot:
            try:
                f.result()
            except Exception as e:
                self._write_errors.append(str(e))

        self._executor.shutdown(wait=True)

        with self._lock:
            lines_snapshot = list(self._lines)

        if lines_snapshot:
            body = "\n".join(lines_snapshot)
            try:
                _s3_client().put_object(
                    Bucket=S3_BUCKET,
                    Key=self._s3_key,
                    Body=body.encode("utf-8"),
                    ContentType="application/jsonl",
                )
                logger.info(
                    "_S3StreamingWriter.finish: s3://%s/%s → %d 건 업로드",
                    S3_BUCKET,
                    self._s3_key,
                    len(lines_snapshot),
                )
            except Exception as e:
                logger.error("_S3StreamingWriter.finish: 업로드 실패 — %s", e)
                self._write_errors.append(str(e))

        self._cleanup_checkpoints()
        return len(lines_snapshot), len(self._write_errors)

    def _write_single_line(self, line: str) -> None:
        ck_key = self._s3_key.replace(
            ".jsonl",
            f"_checkpoint_{abs(hash(line)) % 100000:05d}.jsonl",
        )
        try:
            _s3_client().put_object(
                Bucket=S3_BUCKET,
                Key=ck_key,
                Body=(line + "\n").encode("utf-8"),
                ContentType="application/jsonl",
            )
            with self._lock:
                self._checkpoint_keys.append(ck_key)
        except Exception as e:
            logger.warning("_S3StreamingWriter._write_single_line 실패 — %s", e)

    def _cleanup_checkpoints(self) -> None:
        with self._lock:
            keys = list(self._checkpoint_keys)
        if not keys:
            return
        s3 = _s3_client()
        BATCH = 1000
        deleted_total = 0
        for i in range(0, len(keys), BATCH):
            batch = keys[i : i + BATCH]
            try:
                resp = s3.delete_objects(
                    Bucket=S3_BUCKET,
                    Delete={"Objects": [{"Key": k} for k in batch], "Quiet": True},
                )
                errors = resp.get("Errors", [])
                deleted_total += len(batch) - len(errors)
                for err in errors:
                    logger.warning(
                        "_cleanup_checkpoints: 삭제 실패 — key=%s code=%s",
                        err.get("Key"),
                        err.get("Code"),
                    )
            except Exception as e:
                logger.warning("_cleanup_checkpoints: batch 삭제 오류 — %s", e)
        logger.info(
            "_cleanup_checkpoints: 체크포인트 %d/%d 건 삭제 완료",
            deleted_total,
            len(keys),
        )
