from typing import Final

S3_BUCKET: Final[str] = "malware-project-bucket"
S3_SESSION_GOLD_PREFIX: Final[str] = "gold/session_gold/"
S3_RAG_PREFIX: Final[str] = "rag_result"
S3_TMP_PREFIX: Final[str] = "tmp/neo4j_to_rag"
AWS_REGION: Final[str] = "ap-northeast-2"

S3_WRITE_WORKERS: Final[int] = 2