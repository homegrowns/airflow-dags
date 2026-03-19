"""
dag_gold_to_neo4j.py
Gold JSONL (S3) → Neo4j 그래프 적재 DAG  (v4 — SSL 포함)

Pipeline:
  [clear_graph]         ← Neo4j 기존 노드/관계 전체 삭제 (재적재 보장)
         ↓
  [load_sessions]       ← session_gold.jsonl → (:Session) 노드
         ↓
  [load_entities]       ← entity_gold.jsonl  → (:IP) / (:Domain) / (:Alert) 노드
         ↓
  [load_relations]      ← relation_gold.jsonl → 관계 엣지 생성
         ↓
  [create_indexes]      ← 그래프 인덱스 / 제약 조건 생성 (멱등)
         ↓
  [report_stats]        ← Neo4j 노드/관계 카운트 로그 출력

노드 레이블 & 속성:

  (:Session) {
      session_id, community_id,
      -- conn.log --
      src_ip, src_port, dst_ip, dst_port,
      proto, service, duration, orig_bytes, resp_bytes, conn_state,
      missed_bytes, history, orig_pkts, resp_pkts,
      -- http.log --
      http_method, http_host, http_uri, http_user_agent,
      http_request_body_len, http_response_body_len,
      http_status_code, http_status_msg,
      -- dns.log --
      dns_query, dns_qtype_name, dns_rcode_name, dns_answers, dns_rtt,
      -- ssl.log --
      tls_version, tls_cipher, tls_curve, tls_sni,
      tls_ssl_history, tls_established, tls_resumed,
      -- suricata --
      alert_count, max_severity, is_threat,
      flow_state, flow_reason,
      pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient,
      -- 시간 --
      flow_start, flow_end
  }

  (:IP)     {value, first_seen, last_seen, related_session_count,
             total_orig_bytes, total_resp_bytes}

  (:Domain) {value, first_seen, last_seen, related_session_count}

  (:Alert)  {value, signature, category, first_seen, last_seen,
             related_session_count}

  (:Cipher) {value}   [신규 v4]

관계 타입:
  (:Session)-[:CONNECTED_TO]→(:IP)
  (:Session)-[:ORIGINATED_FROM]→(:IP)
  (:IP)-[:REQUESTED]→(:Domain|:IP)
  (:Domain)-[:RESOLVED_BY]→(:IP|:Domain)
  (:Session)-[:TRIGGERED]→(:Alert)
  (:Session)-[:SERVED_OVER_TLS]→(:Domain)   [신규 v4]
  (:Session)-[:ENCRYPTED_WITH]→(:Cipher)    [신규 v4]

Author : Linda
"""

from __future__ import annotations

from airflow.sdk import Asset  # Airflow 3

import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta

import boto3
from airflow import DAG
from airflow.models import Variable
from airflow.operators.python import PythonOperator

logger = logging.getLogger(__name__)

# ── S3 설정 ────────────────────────────────────────────────────────────────────
S3_BUCKET       = "malware-project-bucket"
S3_SESSION_KEY  = "gold/session_gold.jsonl"
S3_ENTITY_KEY   = "gold/entity_gold.jsonl"
S3_RELATION_KEY = "gold/relation_gold.jsonl"
AWS_REGION      = "ap-northeast-2"

# ── Neo4j 설정 ────────────────────────────────────────────────────────────────
# Variable.get()은 DAG 파싱 시점에 실행되면 VARIABLE_NOT_FOUND 에러 발생
# → 모듈 레벨에서 읽지 않고 _neo4j_driver() 함수 안에서만 호출
NEO4J_URI      = "bolt://localhost:7687"   # fallback default (Variable 미등록 시)
NEO4J_USER     = "neo4j"
NEO4J_PASSWORD = "lindaliam"

BATCH_SIZE = 10000

# Asset 선언
GOLD_SESSION_ASSET  = Asset("s3://malware-project-bucket/gold/session_gold.jsonl")
GOLD_ENTITY_ASSET   = Asset("s3://malware-project-bucket/gold/entity_gold.jsonl")
GOLD_RELATION_ASSET = Asset("s3://malware-project-bucket/gold/relation_gold.jsonl")


# ══════════════════════════════════════════════════════════════════════════════
# 공통 헬퍼
# ══════════════════════════════════════════════════════════════════════════════

def _s3_client():
    return boto3.client("s3", region_name=AWS_REGION)


def _s3_read_jsonl(s3_key: str) -> list[dict]:
    s3  = _s3_client()
    obj = s3.get_object(Bucket=S3_BUCKET, Key=s3_key)
    return [
        json.loads(line)
        for line in obj["Body"].read().decode("utf-8").splitlines()
        if line.strip()
    ]


def _neo4j_driver():
    from neo4j import GraphDatabase
    uri  = Variable.get("NEO4J_URI",      default_var=NEO4J_URI)
    user = Variable.get("NEO4J_USER",     default_var=NEO4J_USER)
    pw   = Variable.get("NEO4J_PASSWORD", default_var=NEO4J_PASSWORD)
    return GraphDatabase.driver(uri, auth=(user, pw))


def _run_batches(session, query: str, records: list[dict], batch_size: int = BATCH_SIZE) -> int:
    """UNWIND 기반 배치 실행. 총 처리 레코드 수 반환."""
    total = 0
    for i in range(0, len(records), batch_size):
        batch = records[i : i + batch_size]
        session.run(query, rows=batch)
        total += len(batch)
    return total


# ══════════════════════════════════════════════════════════════════════════════
# Task 1 : clear_graph
# ══════════════════════════════════════════════════════════════════════════════

def clear_graph(**ctx) -> None:
    """
    Neo4j 그래프 초기화.
    레이블별 순차 삭제로 메모리 스파이크 방지.
    v4: Cipher 레이블 추가.
    """
    driver = _neo4j_driver()
    labels = ["Session", "IP", "Domain", "Alert", "Cipher"]  # [v4] Cipher 추가

    with driver.session() as neo_sess:
        for label in labels:
            deleted = 10000
            while deleted == 10000:
                result = neo_sess.run(
                    f"MATCH (n:{label}) "
                    "WITH n LIMIT 10000 "
                    "DETACH DELETE n "
                    "RETURN count(n) AS deleted"
                )
                deleted = result.single()["deleted"]
            logger.info("clear_graph: :%s 전체 삭제 완료", label)

    driver.close()
    logger.info("clear_graph 완료")


# ══════════════════════════════════════════════════════════════════════════════
# Task 2 : load_sessions
# ══════════════════════════════════════════════════════════════════════════════

# v4: dag_unified_to_gold_2.py의 session_gold 전 필드 반영
_SESSION_QUERY = """
UNWIND $rows AS r
MERGE (s:Session {session_id: r.session_id})
SET
  s.community_id           = r.community_id,
  s.src_ip                 = r.src_ip,
  s.src_port               = r.src_port,
  s.dst_ip                 = r.dst_ip,
  s.dst_port               = r.dst_port,
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


# ══════════════════════════════════════════════════════════════════════════════
# Task 3 : load_entities
# ══════════════════════════════════════════════════════════════════════════════

_IP_QUERY = """
UNWIND $rows AS r
MERGE (n:IP {value: r.entity_value})
SET
  n.first_seen            = r.first_seen,
  n.last_seen             = r.last_seen,
  n.related_session_count = r.related_session_count,
  n.total_orig_bytes      = r.total_orig_bytes,
  n.total_resp_bytes      = r.total_resp_bytes
"""

_DOMAIN_QUERY = """
UNWIND $rows AS r
MERGE (n:Domain {value: r.entity_value})
SET
  n.first_seen            = r.first_seen,
  n.last_seen             = r.last_seen,
  n.related_session_count = r.related_session_count
"""

_ALERT_QUERY = """
UNWIND $rows AS r
MERGE (n:Alert {value: r.entity_value})
SET
  n.first_seen            = r.first_seen,
  n.last_seen             = r.last_seen,
  n.related_session_count = r.related_session_count,
  n.signature             = r.signature,
  n.category              = r.category
"""


def load_entities(**ctx) -> None:
    records = _s3_read_jsonl(S3_ENTITY_KEY)

    buckets: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        buckets[r["entity_type"]].append(r)

    query_map = {
        "ip":     _IP_QUERY,
        "domain": _DOMAIN_QUERY,
        "alert":  _ALERT_QUERY,
    }

    driver = _neo4j_driver()
    counts: dict[str, int] = {}

    with driver.session() as neo_sess:
        for etype, query in query_map.items():
            rows = buckets.get(etype, [])
            if rows:
                cnt = _run_batches(neo_sess, query, rows)
                counts[etype] = cnt
                logger.info("load_entities: :%s %d 노드", etype.capitalize(), cnt)

    driver.close()
    total = sum(counts.values())
    logger.info("load_entities 완료 — 총 %d 엔티티 노드 %s", total, dict(counts))
    ctx["ti"].xcom_push(key="entity_count", value=total)


# ══════════════════════════════════════════════════════════════════════════════
# Task 4 : load_relations
# ══════════════════════════════════════════════════════════════════════════════

# Session → dst_ip  (:Session)-[:CONNECTED_TO]→(:IP)
_SESSION_CONN_QUERY = """
UNWIND $rows AS r
MATCH (src:Session {session_id: r.session_id})
MATCH (dst:IP      {value:      r.dst_ip})
MERGE (src)-[:CONNECTED_TO {session_id: r.session_id}]->(dst)
"""

# Session → src_ip  (:Session)-[:ORIGINATED_FROM]→(:IP)
_SESSION_ORIG_QUERY = """
UNWIND $rows AS r
MATCH (src:Session {session_id: r.session_id})
MATCH (dst:IP      {value:      r.src_ip})
MERGE (src)-[:ORIGINATED_FROM {session_id: r.session_id}]->(dst)
"""

# relation_gold의 relation_type x dst_type 조합별 Cypher
_RELATION_QUERIES: dict[str, str] = {

    # (:IP)-[:REQUESTED]→(:Domain)
    "REQUESTED_domain": """
UNWIND $rows AS r
MATCH (src:IP     {value: r.src_value})
MATCH (dst:Domain {value: r.dst_value})
MERGE (src)-[:REQUESTED {session_id: r.session_id}]->(dst)
""",
    # (:IP)-[:REQUESTED]→(:IP)
    "REQUESTED_ip": """
UNWIND $rows AS r
MATCH (src:IP {value: r.src_value})
MATCH (dst:IP {value: r.dst_value})
MERGE (src)-[:REQUESTED {session_id: r.session_id}]->(dst)
""",

    # (:Domain)-[:RESOLVED_BY]→(:IP)
    "RESOLVED_BY_ip": """
UNWIND $rows AS r
MATCH (src:Domain {value: r.src_value})
MATCH (dst:IP     {value: r.dst_value})
MERGE (src)-[:RESOLVED_BY {session_id: r.session_id}]->(dst)
""",
    # (:Domain)-[:RESOLVED_BY]→(:Domain)
    "RESOLVED_BY_domain": """
UNWIND $rows AS r
MATCH (src:Domain {value: r.src_value})
MATCH (dst:Domain {value: r.dst_value})
MERGE (src)-[:RESOLVED_BY {session_id: r.session_id}]->(dst)
""",

    # (:Session)-[:TRIGGERED]→(:Alert)
    "TRIGGERED": """
UNWIND $rows AS r
MATCH (src:Session {session_id: r.src_value})
MATCH (dst:Alert   {value:      r.dst_value})
MERGE (src)-[:TRIGGERED {session_id: r.session_id}]->(dst)
""",

    # (:Session)-[:SERVED_OVER_TLS]→(:Domain)  [신규 v4]
    # entity_gold에 없는 SNI domain도 있을 수 있으므로 MERGE로 생성 보장
    "SERVED_OVER_TLS": """
UNWIND $rows AS r
MATCH  (src:Session {session_id: r.src_value})
MERGE  (dst:Domain  {value:      r.dst_value})
MERGE  (src)-[:SERVED_OVER_TLS {session_id: r.session_id}]->(dst)
""",

    # (:Session)-[:ENCRYPTED_WITH]→(:Cipher)  [신규 v4]
    # Cipher는 entity_gold에 없으므로 항상 MERGE로 생성
    "ENCRYPTED_WITH": """
UNWIND $rows AS r
MATCH  (src:Session {session_id: r.src_value})
MERGE  (dst:Cipher  {value:      r.dst_value})
MERGE  (src)-[:ENCRYPTED_WITH {session_id: r.session_id}]->(dst)
""",
}


def load_relations(**ctx) -> None:
    raw_relations = _s3_read_jsonl(S3_RELATION_KEY)
    sessions      = _s3_read_jsonl(S3_SESSION_KEY)

    # with 블록 밖 total 계산에서 NameError 방지용 초기화
    sess_dst: list[dict] = []
    sess_src: list[dict] = []

    driver = _neo4j_driver()

    with driver.session() as neo_sess:

        # ── Session → dst_ip (CONNECTED_TO) ──────────────────────────────────
        sess_dst = [
            {"session_id": s["session_id"], "dst_ip": s["dst_ip"]}
            for s in sessions if s.get("dst_ip")
        ]
        if sess_dst:
            cnt = _run_batches(neo_sess, _SESSION_CONN_QUERY, sess_dst)
            logger.info("load_relations: Session-[:CONNECTED_TO]→IP  %d", cnt)

        # ── Session → src_ip (ORIGINATED_FROM) ───────────────────────────────
        sess_src = [
            {"session_id": s["session_id"], "src_ip": s["src_ip"]}
            for s in sessions if s.get("src_ip")
        ]
        if sess_src:
            cnt = _run_batches(neo_sess, _SESSION_ORIG_QUERY, sess_src)
            logger.info("load_relations: Session-[:ORIGINATED_FROM]→IP  %d", cnt)

        # ── relation_gold 기반 엣지 ───────────────────────────────────────────
        buckets: dict[str, list[dict]] = defaultdict(list)
        for r in raw_relations:
            rel = r["relation_type"]
            dst = r.get("dst_type", "")

            # ip→ip CONNECTED_TO 는 위에서 session 기준으로 처리 완료
            if rel == "CONNECTED_TO":
                continue

            if rel in ("REQUESTED", "RESOLVED_BY"):
                key = f"{rel}_{dst}"
            else:
                # TRIGGERED / SERVED_OVER_TLS / ENCRYPTED_WITH
                key = rel

            buckets[key].append(r)

        counts: dict[str, int] = {}
        for key, rows in buckets.items():
            query = _RELATION_QUERIES.get(key)
            if not query:
                logger.warning("알 수 없는 relation 키: %s — 스킵", key)
                continue
            cnt = _run_batches(neo_sess, query, rows)
            counts[key] = cnt
            logger.info("load_relations: [%s] %d 관계", key, cnt)

    driver.close()

    total = sum(counts.values()) + len(sess_dst) + len(sess_src)
    logger.info("load_relations 완료 — 총 %d 관계", total)
    ctx["ti"].xcom_push(key="relation_count", value=total)


# ══════════════════════════════════════════════════════════════════════════════
# Task 5 : create_indexes
# ══════════════════════════════════════════════════════════════════════════════

_CONSTRAINTS = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Session) REQUIRE n.session_id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:IP)      REQUIRE n.value IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Domain)  REQUIRE n.value IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Alert)   REQUIRE n.value IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Cipher)  REQUIRE n.value IS UNIQUE",  # [신규 v4]
]

_INDEXES = [
    # Session
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.community_id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.is_threat)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.src_ip)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.dst_ip)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.flow_start)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.conn_state)",        # [신규 v4]
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.tls_sni)",           # [신규 v4]
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.tls_version)",       # [신규 v4]
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.http_status_code)",  # [신규 v4]
    "CREATE INDEX IF NOT EXISTS FOR (n:Session) ON (n.dns_query)",         # [신규 v4]
    # 기타 노드
    "CREATE INDEX IF NOT EXISTS FOR (n:IP)      ON (n.first_seen)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Alert)   ON (n.category)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Domain)  ON (n.first_seen)",
]


def create_indexes(**ctx) -> None:
    driver = _neo4j_driver()
    with driver.session() as neo_sess:
        for cypher in _CONSTRAINTS + _INDEXES:
            neo_sess.run(cypher)
            logger.info("인덱스/제약 적용: %s", cypher.strip().split("\n")[0][:80])
    driver.close()
    logger.info("create_indexes 완료")


# ══════════════════════════════════════════════════════════════════════════════
# Task 6 : report_stats
# ══════════════════════════════════════════════════════════════════════════════

def report_stats(**ctx) -> None:
    ti = ctx["ti"]
    session_count  = ti.xcom_pull(task_ids="load_sessions",  key="session_count")
    entity_count   = ti.xcom_pull(task_ids="load_entities",  key="entity_count")
    relation_count = ti.xcom_pull(task_ids="load_relations", key="relation_count")

    driver = _neo4j_driver()
    node_counts: dict[str, int] = {}
    rel_counts:  dict[str, int] = {}

    node_labels = ["Session", "IP", "Domain", "Alert", "Cipher"]  # [v4] Cipher 추가
    rel_types   = [
        "CONNECTED_TO", "ORIGINATED_FROM",
        "REQUESTED", "RESOLVED_BY", "TRIGGERED",
        "SERVED_OVER_TLS", "ENCRYPTED_WITH",  # [신규 v4]
    ]

    with driver.session() as neo_sess:
        for label in node_labels:
            result = neo_sess.run(f"MATCH (n:{label}) RETURN count(n) AS cnt")
            node_counts[label] = result.single()["cnt"]

        for rel in rel_types:
            result = neo_sess.run(f"MATCH ()-[r:{rel}]->() RETURN count(r) AS cnt")
            rel_counts[rel] = result.single()["cnt"]

        threat_result = neo_sess.run(
            "MATCH (s:Session {is_threat: true}) RETURN count(s) AS cnt"
        )
        threat_cnt = threat_result.single()["cnt"]

        tls_result = neo_sess.run(
            "MATCH (s:Session) WHERE s.tls_sni IS NOT NULL RETURN count(s) AS cnt"
        )
        tls_cnt = tls_result.single()["cnt"]

    driver.close()

    total_nodes = sum(node_counts.values())
    total_rels  = sum(rel_counts.values())

    logger.info("=" * 70)
    logger.info("▶ gold_to_neo4j 파이프라인 완료 요약 (v4 — SSL 포함)")
    logger.info("=" * 70)
    logger.info("  [적재 건수 (XCom)]")
    logger.info("    session_gold  : %s", session_count)
    logger.info("    entity_gold   : %s", entity_count)
    logger.info("    relation_gold : %s", relation_count)
    logger.info("  [Neo4j 실제 카운트]")
    logger.info("    노드 합계 : %d", total_nodes)
    for label, cnt in node_counts.items():
        logger.info("      ├ :%-10s %d", label, cnt)
    logger.info("    관계 합계 : %d", total_rels)
    for rel, cnt in rel_counts.items():
        logger.info("      ├ %-25s %d", rel, cnt)
    logger.info("  [위협 세션] %d / %d (%.1f%%)",
                threat_cnt, node_counts.get("Session", 1),
                100 * threat_cnt / max(node_counts.get("Session", 1), 1))
    logger.info("  [TLS 세션]  %d / %d (%.1f%%)",
                tls_cnt, node_counts.get("Session", 1),
                100 * tls_cnt / max(node_counts.get("Session", 1), 1))
    logger.info("=" * 70)


# ══════════════════════════════════════════════════════════════════════════════
# DAG 정의
# ══════════════════════════════════════════════════════════════════════════════

default_args = {
    "owner":            "linda",
    "depends_on_past":  False,
    "retries":          2,
    "retry_delay":      timedelta(minutes=2),
    "email_on_failure": False,
}

with DAG(
    dag_id="gold_to_neo4j",
    description="Gold JSONL (S3) → Neo4j 그래프 적재 (v4 — SSL 포함)",
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