"""
dag_gold_to_neo4j.py
Gold JSONL (S3) → Neo4j 그래프 적재 DAG  (v5 — uid / dest_* 반영)

[v5 변경점]
  - :Session 노드에 uid 속성 추가 (원본 로그 역추적용)
  - dst_ip / dst_port → dest_ip / dest_port 필드명 통일
  - CLEAR_GRAPH_ENABLED Variable로 clear_graph on/off 제어
    Airflow Admin → Variables → CLEAR_GRAPH_ENABLED = "true" | "false"
    (기본값 "true" — 값 없으면 초기화 실행)

Pipeline:
  [clear_graph]    ← CLEAR_GRAPH_ENABLED=true 일 때만 Neo4j 전체 초기화
       ↓
  [load_sessions]  ← session_gold.jsonl → (:Session) 노드
       ↓
  [load_entities]  ← entity_gold.jsonl  → (:IP) / (:Domain) / (:Alert)
       ↓
  [load_relations] ← relation_gold.jsonl → 관계 엣지
       ↓
  [create_indexes] ← 인덱스 / 제약 조건 생성 (멱등)
       ↓
  [report_stats]   ← Neo4j 카운트 로그

Author : Linda
"""

from __future__ import annotations

from airflow.sdk import Asset

import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta

import boto3
from airflow import DAG
from airflow.models import Variable
from airflow.operators.python import PythonOperator

logger = logging.getLogger(__name__)

S3_BUCKET       = "malware-project-bucket"
S3_SESSION_KEY  = "gold/session_gold.jsonl"
S3_ENTITY_KEY   = "gold/entity_gold.jsonl"
S3_RELATION_KEY = "gold/relation_gold.jsonl"
AWS_REGION      = "ap-northeast-2"
BATCH_SIZE      = 10000

GOLD_SESSION_ASSET  = Asset("s3://malware-project-bucket/gold/session_gold.jsonl")
GOLD_ENTITY_ASSET   = Asset("s3://malware-project-bucket/gold/entity_gold.jsonl")
GOLD_RELATION_ASSET = Asset("s3://malware-project-bucket/gold/relation_gold.jsonl")


# ── 공통 헬퍼 ─────────────────────────────────────────────────────────────────

def _s3_client():
    return boto3.client("s3", region_name=AWS_REGION)

def _s3_read_jsonl(s3_key: str) -> list[dict]:
    s3  = _s3_client()
    obj = s3.get_object(Bucket=S3_BUCKET, Key=s3_key)
    return [json.loads(line) for line in obj["Body"].read().decode("utf-8").splitlines() if line.strip()]

def _neo4j_driver():
    from neo4j import GraphDatabase
    uri  = Variable.get("NEO4J_URI")
    user = Variable.get("NEO4J_USER")
    pw   = Variable.get("NEO4J_PASSWORD")
    return GraphDatabase.driver(uri, auth=(user, pw))

def _run_batches(session, query: str, records: list[dict], batch_size: int = BATCH_SIZE) -> int:
    total = 0
    for i in range(0, len(records), batch_size):
        session.run(query, rows=records[i:i+batch_size])
        total += len(records[i:i+batch_size])
    return total


# ── Task 1 : clear_graph ──────────────────────────────────────────────────────

def clear_graph(**ctx) -> None:
    """
    CLEAR_GRAPH_ENABLED Variable가 'false'이면 스킵.
    기본값(Variable 없음 또는 'true')이면 전체 초기화.
    """
    enabled = Variable.get("CLEAR_GRAPH_ENABLED", default_var="true").lower()
    if enabled == "false":
        logger.info("clear_graph: CLEAR_GRAPH_ENABLED=false — 초기화 스킵")
        return

    driver = _neo4j_driver()
    labels = ["Session", "IP", "Domain", "Alert", "Cipher"]

    with driver.session() as neo_sess:
        for label in labels:
            deleted = 10000
            while deleted == 10000:
                result  = neo_sess.run(
                    f"MATCH (n:{label}) WITH n LIMIT 10000 DETACH DELETE n RETURN count(n) AS deleted"
                )
                deleted = result.single()["deleted"]
            logger.info("clear_graph: :%s 전체 삭제 완료", label)

    driver.close()
    logger.info("clear_graph 완료")


# ── Task 2 : load_sessions ────────────────────────────────────────────────────

_SESSION_QUERY = """
UNWIND $rows AS r
MERGE (s:Session {session_id: r.session_id})
SET
  s.community_id           = r.community_id,
  s.uid                    = r.uid,
  s.src_ip                 = r.src_ip,
  s.src_port               = r.src_port,
  s.dest_ip                = r.dest_ip,
  s.dest_port              = r.dest_port,
  s.proto                  = r.proto,
  s.service                = r.service,
  s.duration               = r.duration,
  s.orig_bytes             = r.orig_bytes,
  s.resp_bytes             = r.resp_bytes,
  s.conn_state             = r.conn_state,
  s.missed_bytes           = r.missed_bytes,
  s.history                = r.history,
  s.orig_pkts              = r.orig_pkts,
  s.resp_pkts              = r.resp_pkts,
  s.http_method            = r.http_method,
  s.http_host              = r.http_host,
  s.http_uri               = r.http_uri,
  s.http_user_agent        = r.http_user_agent,
  s.http_request_body_len  = r.http_request_body_len,
  s.http_response_body_len = r.http_response_body_len,
  s.http_status_code       = r.http_status_code,
  s.http_status_msg        = r.http_status_msg,
  s.dns_query              = r.dns_query,
  s.dns_qtype_name         = r.dns_qtype_name,
  s.dns_rcode_name         = r.dns_rcode_name,
  s.dns_answers            = r.dns_answers,
  s.dns_rtt                = r.dns_rtt,
  s.tls_version            = r.tls_version,
  s.tls_cipher             = r.tls_cipher,
  s.tls_curve              = r.tls_curve,
  s.tls_sni                = r.tls_sni,
  s.tls_ssl_history        = r.tls_ssl_history,
  s.tls_established        = r.tls_established,
  s.tls_resumed            = r.tls_resumed,
  s.alert_count            = r.alert_count,
  s.max_severity           = r.max_severity,
  s.is_threat              = r.is_threat,
  s.flow_state             = r.flow_state,
  s.flow_reason            = r.flow_reason,
  s.pkts_toserver          = r.pkts_toserver,
  s.pkts_toclient          = r.pkts_toclient,
  s.bytes_toserver         = r.bytes_toserver,
  s.bytes_toclient         = r.bytes_toclient,
  s.flow_start             = r.flow_start,
  s.flow_end               = r.flow_end
"""

def load_sessions(**ctx) -> None:
    records = _s3_read_jsonl(S3_SESSION_KEY)
    driver  = _neo4j_driver()
    with driver.session() as neo_sess:
        total = _run_batches(neo_sess, _SESSION_QUERY, records)
    driver.close()
    logger.info("load_sessions 완료 — %d 세션 노드", total)
    ctx["ti"].xcom_push(key="session_count", value=total)


# ── Task 3 : load_entities ────────────────────────────────────────────────────

_IP_QUERY = """
UNWIND $rows AS r
MERGE (n:IP {value: r.entity_value})
SET n.first_seen=r.first_seen, n.last_seen=r.last_seen,
    n.related_session_count=r.related_session_count,
    n.total_orig_bytes=r.total_orig_bytes, n.total_resp_bytes=r.total_resp_bytes
"""
_DOMAIN_QUERY = """
UNWIND $rows AS r
MERGE (n:Domain {value: r.entity_value})
SET n.first_seen=r.first_seen, n.last_seen=r.last_seen,
    n.related_session_count=r.related_session_count
"""
_ALERT_QUERY = """
UNWIND $rows AS r
MERGE (n:Alert {value: r.entity_value})
SET n.first_seen=r.first_seen, n.last_seen=r.last_seen,
    n.related_session_count=r.related_session_count,
    n.signature=r.signature, n.category=r.category
"""

def load_entities(**ctx) -> None:
    records   = _s3_read_jsonl(S3_ENTITY_KEY)
    buckets: dict[str, list[dict]] = defaultdict(list)
    for r in records: buckets[r["entity_type"]].append(r)

    driver = _neo4j_driver()
    counts: dict[str, int] = {}
    with driver.session() as neo_sess:
        for etype, query in [("ip",_IP_QUERY),("domain",_DOMAIN_QUERY),("alert",_ALERT_QUERY)]:
            rows = buckets.get(etype, [])
            if rows:
                counts[etype] = _run_batches(neo_sess, query, rows)
                logger.info("load_entities: :%s %d 노드", etype.capitalize(), counts[etype])
    driver.close()
    total = sum(counts.values())
    logger.info("load_entities 완료 — 총 %d 엔티티", total)
    ctx["ti"].xcom_push(key="entity_count", value=total)


# ── Task 4 : load_relations ───────────────────────────────────────────────────

_SESSION_CONN_QUERY = """
UNWIND $rows AS r
MATCH (src:Session {session_id: r.session_id})
MATCH (dst:IP      {value:      r.dest_ip})
MERGE (src)-[:CONNECTED_TO {session_id: r.session_id}]->(dst)
"""
_SESSION_ORIG_QUERY = """
UNWIND $rows AS r
MATCH (src:Session {session_id: r.session_id})
MATCH (dst:IP      {value:      r.src_ip})
MERGE (src)-[:ORIGINATED_FROM {session_id: r.session_id}]->(dst)
"""
_RELATION_QUERIES: dict[str, str] = {
    "REQUESTED_domain": "UNWIND $rows AS r MATCH (src:IP {value:r.src_value}) MATCH (dst:Domain {value:r.dst_value}) MERGE (src)-[:REQUESTED {session_id:r.session_id}]->(dst)",
    "REQUESTED_ip":     "UNWIND $rows AS r MATCH (src:IP {value:r.src_value}) MATCH (dst:IP     {value:r.dst_value}) MERGE (src)-[:REQUESTED {session_id:r.session_id}]->(dst)",
    "RESOLVED_BY_ip":   "UNWIND $rows AS r MATCH (src:Domain {value:r.src_value}) MATCH (dst:IP     {value:r.dst_value}) MERGE (src)-[:RESOLVED_BY {session_id:r.session_id}]->(dst)",
    "RESOLVED_BY_domain":"UNWIND $rows AS r MATCH (src:Domain {value:r.src_value}) MATCH (dst:Domain {value:r.dst_value}) MERGE (src)-[:RESOLVED_BY {session_id:r.session_id}]->(dst)",
    "TRIGGERED":        "UNWIND $rows AS r MATCH (src:Session {session_id:r.src_value}) MATCH (dst:Alert {value:r.dst_value}) MERGE (src)-[:TRIGGERED {session_id:r.session_id}]->(dst)",
    "SERVED_OVER_TLS":  "UNWIND $rows AS r MATCH (src:Session {session_id:r.src_value}) MERGE (dst:Domain {value:r.dst_value}) MERGE (src)-[:SERVED_OVER_TLS {session_id:r.session_id}]->(dst)",
    "ENCRYPTED_WITH":   "UNWIND $rows AS r MATCH (src:Session {session_id:r.src_value}) MERGE (dst:Cipher {value:r.dst_value}) MERGE (src)-[:ENCRYPTED_WITH {session_id:r.session_id}]->(dst)",
}

def load_relations(**ctx) -> None:
    raw_relations = _s3_read_jsonl(S3_RELATION_KEY)
    sessions      = _s3_read_jsonl(S3_SESSION_KEY)
    sess_dst: list[dict] = []
    sess_src: list[dict] = []

    driver = _neo4j_driver()
    with driver.session() as neo_sess:
        sess_dst = [{"session_id": s["session_id"], "dest_ip": s["dest_ip"]}   # [v5]
                    for s in sessions if s.get("dest_ip")]
        if sess_dst:
            cnt = _run_batches(neo_sess, _SESSION_CONN_QUERY, sess_dst)
            logger.info("load_relations: Session-[:CONNECTED_TO]→IP  %d", cnt)

        sess_src = [{"session_id": s["session_id"], "src_ip": s["src_ip"]}
                    for s in sessions if s.get("src_ip")]
        if sess_src:
            cnt = _run_batches(neo_sess, _SESSION_ORIG_QUERY, sess_src)
            logger.info("load_relations: Session-[:ORIGINATED_FROM]→IP  %d", cnt)

        buckets: dict[str, list[dict]] = defaultdict(list)
        for r in raw_relations:
            rel = r["relation_type"]
            dst = r.get("dst_type", "")
            if rel == "CONNECTED_TO": continue
            key = f"{rel}_{dst}" if rel in ("REQUESTED","RESOLVED_BY") else rel
            buckets[key].append(r)

        counts: dict[str, int] = {}
        for key, rows in buckets.items():
            query = _RELATION_QUERIES.get(key)
            if not query:
                logger.warning("알 수 없는 relation 키: %s — 스킵", key)
                continue
            counts[key] = _run_batches(neo_sess, query, rows)
            logger.info("load_relations: [%s] %d 관계", key, counts[key])

    driver.close()
    total = sum(counts.values()) + len(sess_dst) + len(sess_src)
    logger.info("load_relations 완료 — 총 %d 관계", total)
    ctx["ti"].xcom_push(key="relation_count", value=total)


# ── Task 5 : create_indexes ───────────────────────────────────────────────────

_CONSTRAINTS = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Session) REQUIRE n.session_id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:IP)      REQUIRE n.value IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Domain)  REQUIRE n.value IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Alert)   REQUIRE n.value IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Cipher)  REQUIRE n.value IS UNIQUE",
]
_INDEXES = [
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.community_id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.uid)",           # [신규 v5]
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.is_threat)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.src_ip)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.dest_ip)",       # [v5]
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.flow_start)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.conn_state)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.tls_sni)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.tls_version)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.http_status_code)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.dns_query)",
    "CREATE INDEX IF NOT EXISTS FOR (n:IP)      ON (n.first_seen)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Alert)   ON (n.category)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Domain)  ON (n.first_seen)",
]

def create_indexes(**ctx) -> None:
    driver = _neo4j_driver()
    with driver.session() as neo_sess:
        for cypher in _CONSTRAINTS + _INDEXES:
            neo_sess.run(cypher)
            logger.info("인덱스/제약 적용: %s", cypher[:80])
    driver.close()
    logger.info("create_indexes 완료")


# ── Task 6 : report_stats ─────────────────────────────────────────────────────

def report_stats(**ctx) -> None:
    ti             = ctx["ti"]
    session_count  = ti.xcom_pull(task_ids="load_sessions",  key="session_count")
    entity_count   = ti.xcom_pull(task_ids="load_entities",  key="entity_count")
    relation_count = ti.xcom_pull(task_ids="load_relations", key="relation_count")

    driver = _neo4j_driver()
    node_counts: dict[str, int] = {}
    rel_counts:  dict[str, int] = {}

    with driver.session() as neo_sess:
        for label in ["Session","IP","Domain","Alert","Cipher"]:
            node_counts[label] = neo_sess.run(f"MATCH (n:{label}) RETURN count(n) AS cnt").single()["cnt"]
        for rel in ["CONNECTED_TO","ORIGINATED_FROM","REQUESTED","RESOLVED_BY","TRIGGERED","SERVED_OVER_TLS","ENCRYPTED_WITH"]:
            rel_counts[rel] = neo_sess.run(f"MATCH ()-[r:{rel}]->() RETURN count(r) AS cnt").single()["cnt"]
        threat_cnt = neo_sess.run("MATCH (s:Session {is_threat:true}) RETURN count(s) AS cnt").single()["cnt"]
        tls_cnt    = neo_sess.run("MATCH (s:Session) WHERE s.tls_sni IS NOT NULL RETURN count(s) AS cnt").single()["cnt"]
        uid_cnt    = neo_sess.run("MATCH (s:Session) WHERE s.uid IS NOT NULL RETURN count(s) AS cnt").single()["cnt"]  # [신규 v5]

    driver.close()

    logger.info("=" * 70)
    logger.info("▶ gold_to_neo4j 파이프라인 완료 요약 (v5 — uid 포함)")
    logger.info("=" * 70)
    logger.info("  [적재 건수] session:%s entity:%s relation:%s", session_count, entity_count, relation_count)
    logger.info("  [노드 합계] %d", sum(node_counts.values()))
    for label, cnt in node_counts.items(): logger.info("      ├ :%-10s %d", label, cnt)
    logger.info("  [관계 합계] %d", sum(rel_counts.values()))
    for rel, cnt in rel_counts.items(): logger.info("      ├ %-25s %d", rel, cnt)
    logger.info("  [위협 세션] %d / %d (%.1f%%)", threat_cnt, node_counts.get("Session",1),
                100*threat_cnt/max(node_counts.get("Session",1),1))
    logger.info("  [TLS 세션]  %d / %d (%.1f%%)", tls_cnt, node_counts.get("Session",1),
                100*tls_cnt/max(node_counts.get("Session",1),1))
    logger.info("  [uid 보유]  %d / %d (%.1f%%)", uid_cnt, node_counts.get("Session",1),
                100*uid_cnt/max(node_counts.get("Session",1),1))
    logger.info("=" * 70)


# ── DAG 정의 ──────────────────────────────────────────────────────────────────

default_args = {
    "owner":            "linda",
    "depends_on_past":  False,
    "retries":          2,
    "retry_delay":      timedelta(minutes=2),
    "email_on_failure": False,
}

with DAG(
    dag_id="gold_to_neo4j",
    description="Gold JSONL (S3) → Neo4j 그래프 적재 v5 (uid / dest_* / clear on/off)",
    default_args=default_args,
    start_date=datetime(2026, 1, 1),
    schedule=[GOLD_SESSION_ASSET, GOLD_ENTITY_ASSET, GOLD_RELATION_ASSET],
    catchup=False,
    max_active_runs=1,
    tags=["cti", "graph-rag", "neo4j"],
) as dag:

    t_clear    = PythonOperator(task_id="clear_graph",    python_callable=clear_graph)
    t_sessions = PythonOperator(task_id="load_sessions",  python_callable=load_sessions)
    t_entities = PythonOperator(task_id="load_entities",  python_callable=load_entities)
    t_relations= PythonOperator(task_id="load_relations", python_callable=load_relations)
    t_indexes  = PythonOperator(task_id="create_indexes", python_callable=create_indexes)
    t_report   = PythonOperator(task_id="report_stats",   python_callable=report_stats)

    t_clear >> t_sessions >> t_entities >> t_relations >> t_indexes >> t_report