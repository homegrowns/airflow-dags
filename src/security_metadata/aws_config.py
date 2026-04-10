from typing import Final

S3_BUCKET: Final[str] = "malware-project-bucket"
S3_SESSION_GOLD_PREFIX: Final[str] = "gold/session_gold/"
S3_RAG_PREFIX: Final[str] = "rag_result"
S3_TMP_PREFIX: Final[str] = "tmp/neo4j_to_rag"
AWS_REGION: Final[str] = "ap-northeast-2"

GOLD_SESSION_ASSET: Final[str] = "s3://malware-project-bucket/gold/session_gold"
GOLD_ENTITY_ASSET: Final[str] = "s3://malware-project-bucket/gold/entity_gold"
GOLD_RELATION_ASSET: Final[str] = "s3://malware-project-bucket/gold/relation_gold"

S3_SILVER_PREFIX: Final[str] = "silver/common_records/"
S3_GOLD_PREFIX: Final[str] = "gold"

S3_WRITE_WORKERS: Final[int] = 2
BATCH_SIZE: Final[int] = 10000