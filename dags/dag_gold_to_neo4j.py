"""
dag_gold_to_neo4j.py
Gold parquet (S3) → Neo4j 그래프 적재 DAG (v7 — run_id 기반 XCom / max_active_runs=4)

[v7 변경점]
  - max_active_runs: 1 → 4 (unified_events_to_gold 동시 실행 대응)
  - load_sessions XCom 조회: include_prior_dates → run_id 기반
    · consumed_asset_events.source_run_id 로 어떤 unified run이 트리거했는지 추적
    · 정확한 배치의 session_key 조회 보장

Pipeline:
  [clear_graph]    ← CLEAR_GRAPH_ENABLED=true 일 때만 Neo4j 전체 초기화
       ↓
  [load_sessions]  ← session_gold parquet → (:Session) 노드
       ↓
  [load_entities]  ← entity_gold parquet  → (:IP) / (:Domain) / (:Alert)
       ↓
  [load_relations] ← relation_gold parquet → 관계 엣지
       ↓
  [create_indexes] ← 인덱스 / 제약 조건 생성 (멱등)
       ↓
  [report_stats]   ← Neo4j 카운트 로그

Author : Linda
"""

from __future__ import annotations

import io
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

from airflow import DAG
from airflow.models import Variable
from airflow.models.xcom import XCom
from airflow.operators.python import PythonOperator
from airflow.sdk import Asset

from src.gold_to_neo4j.neo4j.session_query_v1 import (
    SESSION_QUERY,
    IP_QUERY,
    DOMAIN_QUERY,
    ALERT_QUERY,
    SESSION_CONN_QUERY,
    SESSION_ORIG_QUERY,
    RELATION_QUERIES,
    CONSTRAINTS,
    INDEXES,
)

from security_metadata.aws_config import (
    S3_BUCKET,
    AWS_REGION,
    S3_SESSION_GOLD_PREFIX,
    GOLD_SESSION_ASSET,
    GOLD_ENTITY_ASSET,
    GOLD_RELATION_ASSET,
)

from src.common.common_helper import (
    s3_client,
    neo4j_driver,
    s3_read_parquet,
    run_batches,
    sibling_key,
    prefix_from_key,
    to_kst_iso,
    get_source_run_id,
)

import boto3

logger = logging.getLogger(__name__)

KST = ZoneInfo("Asia/Seoul")

GOLD_SESSION_ASSET = Asset(GOLD_SESSION_ASSET)
GOLD_ENTITY_ASSET = Asset(GOLD_ENTITY_ASSET)
GOLD_RELATION_ASSET = Asset(GOLD_RELATION_ASSET)

# ══════════════════════════════════════════════════════════════════════════════
# Task 1 : clear_graph
# ══════════════════════════════════════════════════════════════════════════════


def clear_graph(**ctx) -> None:
    enabled = Variable.get("CLEAR_GRAPH_ENABLED", default_var="true").lower()
    if enabled == "false":
        logger.info("clear_graph: CLEAR_GRAPH_ENABLED=false — 초기화 스킵")
        return
    driver = neo4j_driver()
    with driver.session() as neo_sess:
        for label in ["Session", "IP", "Domain", "Alert", "Cipher"]:
            deleted = 10000
            while deleted == 10000:
                result = neo_sess.run(
                    f"MATCH (n:{label}) WITH n LIMIT 10000 DETACH DELETE n RETURN count(n) AS deleted"
                )
                deleted = result.single()["deleted"]
            logger.info("clear_graph: :%s 전체 삭제 완료", label)
    driver.close()
    logger.info("clear_graph 완료")


def load_sessions(**ctx) -> None:
    # ── Asset 트리거한 unified run_id 기반으로 session_key XCom 조회 ──────────
    source_run_id = get_source_run_id(ctx)
    logger.info("load_sessions: source_run_id = %s", source_run_id)

    session_key = XCom.get_one(
        key="session_key",
        dag_id="unified_events_to_gold",
        task_id="extract_sessions",
        run_id=source_run_id,  # 해당 배치 run의 XCom만 조회
    )

    if not session_key:
        raise ValueError(
            f"load_sessions: session_key XCom 없음 (source_run_id={source_run_id})"
        )
    logger.info("load_sessions: session_key = %s", session_key)

    records = s3_read_parquet(session_key)
    for r in records:
        r["flow_start"] = to_kst_iso(r.get("flow_start"))
        r["flow_end"] = to_kst_iso(r.get("flow_end"))
        r["ts"] = to_kst_iso(r.get("ts"))

    driver = neo4j_driver()
    with driver.session() as neo_sess:
        total = run_batches(neo_sess, SESSION_QUERY, records)
    driver.close()
    logger.info("load_sessions 완료 — %d 세션 노드", total)

    session_gold_prefix = prefix_from_key(session_key)
    ctx["ti"].xcom_push(key="session_count", value=total)
    ctx["ti"].xcom_push(key="session_key", value=session_key)
    ctx["ti"].xcom_push(key="session_gold_prefix", value=session_gold_prefix)
    logger.info("load_sessions: session_gold prefix → %s", session_gold_prefix)


def load_entities(**ctx) -> None:
    session_key: str = ctx["ti"].xcom_pull(task_ids="load_sessions", key="session_key")
    entity_key = sibling_key(session_key, "entity_gold")
    logger.info("load_entities: entity_key = %s", entity_key)

    records = s3_read_parquet(entity_key)
    buckets: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        buckets[r["entity_type"]].append(r)

    driver = neo4j_driver()
    counts: dict[str, int] = {}
    with driver.session() as neo_sess:
        for etype, query in [
            ("ip", IP_QUERY),
            ("domain", DOMAIN_QUERY),
            ("alert", ALERT_QUERY),
        ]:
            rows = buckets.get(etype, [])
            if rows:
                counts[etype] = run_batches(neo_sess, query, rows)
                logger.info(
                    "load_entities: :%s %d 노드", etype.capitalize(), counts[etype]
                )
    driver.close()
    total = sum(counts.values())
    logger.info("load_entities 완료 — 총 %d 엔티티", total)
    ctx["ti"].xcom_push(key="entity_count", value=total)


def load_relations(**ctx) -> None:
    session_key: str = ctx["ti"].xcom_pull(task_ids="load_sessions", key="session_key")
    relation_key = sibling_key(session_key, "relation_gold")
    logger.info("load_relations: relation_key = %s", relation_key)

    raw_relations = s3_read_parquet(relation_key)
    sessions = s3_read_parquet(session_key)

    driver = neo4j_driver()
    with driver.session() as neo_sess:
        sess_dst = [
            {"session_id": s["session_id"], "dest_ip": s["dest_ip"]}
            for s in sessions
            if s.get("dest_ip")
        ]
        sess_src = [
            {"session_id": s["session_id"], "src_ip": s["src_ip"]}
            for s in sessions
            if s.get("src_ip")
        ]

        if sess_dst:
            cnt = run_batches(neo_sess, SESSION_CONN_QUERY, sess_dst)
            logger.info("load_relations: Session-[:CONNECTED_TO]→IP  %d", cnt)
        if sess_src:
            cnt = run_batches(neo_sess, SESSION_ORIG_QUERY, sess_src)
            logger.info("load_relations: Session-[:ORIGINATED_FROM]→IP  %d", cnt)

        buckets: dict[str, list[dict]] = defaultdict(list)
        for r in raw_relations:
            rel = r["relation_type"]
            dst = r.get("dst_type", "")
            if rel == "CONNECTED_TO":
                continue
            key = f"{rel}_{dst}" if rel in ("REQUESTED", "RESOLVED_BY") else rel
            buckets[key].append(r)

        counts: dict[str, int] = {}
        for key, rows in buckets.items():
            query = RELATION_QUERIES.get(key)
            if not query:
                logger.warning("알 수 없는 relation 키: %s — 스킵", key)
                continue
            counts[key] = run_batches(neo_sess, query, rows)
            logger.info("load_relations: [%s] %d 관계", key, counts[key])

    driver.close()
    total = sum(counts.values()) + len(sess_dst) + len(sess_src)
    logger.info("load_relations 완료 — 총 %d 관계", total)
    ctx["ti"].xcom_push(key="relation_count", value=total)


def create_indexes(**ctx) -> None:
    driver = neo4j_driver()
    with driver.session() as neo_sess:
        for cypher in CONSTRAINTS + INDEXES:
            neo_sess.run(cypher)
            logger.info("인덱스/제약 적용: %s", cypher[:80])
    driver.close()
    logger.info("create_indexes 완료")


# ══════════════════════════════════════════════════════════════════════════════
# Task 6 : report_stats
# ══════════════════════════════════════════════════════════════════════════════


def report_stats(**ctx) -> None:
    ti = ctx["ti"]
    session_count = ti.xcom_pull(task_ids="load_sessions", key="session_count")
    entity_count = ti.xcom_pull(task_ids="load_entities", key="entity_count")
    relation_count = ti.xcom_pull(task_ids="load_relations", key="relation_count")
    session_key = ti.xcom_pull(task_ids="load_sessions", key="session_key")

    driver = neo4j_driver()
    node_counts: dict[str, int] = {}
    rel_counts: dict[str, int] = {}
    with driver.session() as neo_sess:
        for label in ["Session", "IP", "Domain", "Alert", "Cipher"]:
            node_counts[label] = neo_sess.run(
                f"MATCH (n:{label}) RETURN count(n) AS cnt"
            ).single()["cnt"]
        for rel in [
            "CONNECTED_TO",
            "ORIGINATED_FROM",
            "REQUESTED",
            "RESOLVED_BY",
            "TRIGGERED",
            "SERVED_OVER_TLS",
            "ENCRYPTED_WITH",
        ]:
            rel_counts[rel] = neo_sess.run(
                f"MATCH ()-[r:{rel}]->() RETURN count(r) AS cnt"
            ).single()["cnt"]
        threat_cnt = neo_sess.run(
            "MATCH (s:Session {is_threat:true}) RETURN count(s) AS cnt"
        ).single()["cnt"]
        tls_cnt = neo_sess.run(
            "MATCH (s:Session) WHERE s.tls_sni IS NOT NULL RETURN count(s) AS cnt"
        ).single()["cnt"]
        uid_cnt = neo_sess.run(
            "MATCH (s:Session) WHERE s.uid IS NOT NULL RETURN count(s) AS cnt"
        ).single()["cnt"]
    driver.close()

    logger.info("=" * 70)
    logger.info("▶ gold_to_neo4j 파이프라인 완료 요약 (v7)")
    logger.info("=" * 70)
    logger.info("  [소스]  session_gold parquet   : s3://%s/%s", S3_BUCKET, session_key)
    logger.info(
        "  [적재]  session:%s  entity:%s  relation:%s",
        session_count,
        entity_count,
        relation_count,
    )
    logger.info("  [노드 합계] %d", sum(node_counts.values()))
    for label, cnt in node_counts.items():
        logger.info("      ├ :%-10s %d", label, cnt)
    logger.info("  [관계 합계] %d", sum(rel_counts.values()))
    for rel, cnt in rel_counts.items():
        logger.info("      ├ %-25s %d", rel, cnt)
    logger.info(
        "  [위협 세션] %d / %d (%.1f%%)",
        threat_cnt,
        node_counts.get("Session", 1),
        100 * threat_cnt / max(node_counts.get("Session", 1), 1),
    )
    logger.info(
        "  [TLS 세션]  %d / %d (%.1f%%)",
        tls_cnt,
        node_counts.get("Session", 1),
        100 * tls_cnt / max(node_counts.get("Session", 1), 1),
    )
    logger.info(
        "  [uid 보유]  %d / %d (%.1f%%)",
        uid_cnt,
        node_counts.get("Session", 1),
        100 * uid_cnt / max(node_counts.get("Session", 1), 1),
    )
    logger.info("=" * 70)


# ══════════════════════════════════════════════════════════════════════════════
# DAG 정의
# ══════════════════════════════════════════════════════════════════════════════

default_args = {
    "owner": "linda",
    "depends_on_past": False,
    "retries": 2,
    "retry_delay": timedelta(minutes=2),
    "email_on_failure": False,
}

with DAG(
    dag_id="gold_to_neo4j",
    description="Gold parquet (S3) → Neo4j 그래프 적재 v7 (run_id XCom / max_active_runs=4)",
    default_args=default_args,
    start_date=datetime(2026, 1, 1),
    schedule=[GOLD_SESSION_ASSET, GOLD_ENTITY_ASSET, GOLD_RELATION_ASSET],
    catchup=False,
    max_active_runs=4,  # unified_events_to_gold 동시 실행 수와 맞춤
    tags=["cti", "graph-rag", "neo4j"],
) as dag:

    t_clear = PythonOperator(task_id="clear_graph", python_callable=clear_graph)
    t_sessions = PythonOperator(task_id="load_sessions", python_callable=load_sessions)
    t_entities = PythonOperator(task_id="load_entities", python_callable=load_entities)
    t_relations = PythonOperator(
        task_id="load_relations", python_callable=load_relations
    )
    t_indexes = PythonOperator(task_id="create_indexes", python_callable=create_indexes)
    t_report = PythonOperator(task_id="report_stats", python_callable=report_stats)

    t_clear >> t_sessions >> t_entities >> t_relations >> t_indexes >> t_report
