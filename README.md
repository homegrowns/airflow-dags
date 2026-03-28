# airflow-dags
eks airflow dag

---
*주요 dag 의존 관계 요약*

unified_events_to_gold (*/10 스케줄)
  wait_for_silver
  validate_input
  extract_sessions
    ├── session_gold parquet + _SUCCESS 생성
    ├── XCom push: session_key
    │
    ├── trigger_neo4j_to_rag      ← conf={session_key} 전달, 즉시 트리거
    │         ↓
    │   neo4j_to_rag (schedule=None)
    │     resolve_session_gold_prefix  ← conf에서 session_key 수신
    │     load_session_gold            ← 해당 배치만 읽기
    │     filter_whitelist
    │     build_subgraphs
    │     run_rag_analysis
    │     save_rag_results
    │     report_rag_stats
    │
    └── extract_entities               ← 병렬 진행
        extract_relations
        report_stats                   ← Asset emit → gold_to_neo4j 트리거
