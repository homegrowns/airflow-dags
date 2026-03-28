# airflow-dags
eks airflow dag

---
*주요 dag 의존 관계 요약*

unified_events_to_gold
  extract_sessions → parquet 저장 + _SUCCESS 생성 + XCom: session_key
  report_stats     → Asset emit (gold_to_neo4j 트리거)

gold_to_neo4j  (Asset 트리거)
  load_sessions → XCom pull: session_key → parquet 읽기 → Neo4j 적재
                → XCom push: session_gold_prefix (참고용)

neo4j_to_rag  (*/10 스케줄 + S3KeySensor)
  wait_for_session_gold       → _SUCCESS 15초 폴링 감지
  resolve_session_gold_prefix → 최신 _SUCCESS → prefix/partition 파싱
  load_session_gold           → 해당 배치만 읽기
  save_rag_results            → rag_result/dt=..._hour=.._minute=.._rag_results.jsonl