# airflow-dags

EKS Airflow DAG 모음 — 네트워크 위협 탐지 CTI 파이프라인

## DAG 구성

```
repo-root/
├── dags/
│   ├── dag_unified_events_to_gold.py
│   ├── dag_gold_to_neo4j.py
│   └── dag_neo4j_to_rag.py
├── plugins/                
└── src/ 
    ├── __init__.py
    ├── security_metadata/
    │   ├── __init__.py
    │   ├── aws_config.py   aws 설정
    │   └── mappings.py     CATEGORY_TO_CLASSTYPE , CLASSTYPE_SCORE_RANGE 등 위치
    ├── common/   
    │   ├── common_helper.py
    │   └── query_v1.py
    │  
    ├── gold_to_neo4j/
    │   
    ├── neo4_to_rag/
    │   ├── __init__.py
    │   ├── s3_route_helper.py
    │   ├── s3_streaming_writer.py
    │   ├── s3_tmp_helper.py
    │   └── prompt.py
    └── unified_to_gold/
        ├── __init__.py
        └── gold_parquet_route.py

helm values.yaml에서 extraEnv 항목 - name: PYTHONPATH 필요  value: /opt/airflow/dags/repo 추가
```

| DAG | 스케줄 | 역할 |
|---|---|---|
| `unified_events_to_gold` | `*/10 * * * *` | Silver parquet → Gold parquet 전처리 |
| `gold_to_neo4j` | Asset 트리거 | Gold parquet → Neo4j 그래프 적재 |
| `neo4j_to_rag` | 외부 트리거 | Session gold → Groq RAG 위협 분석 |

---

## 파이프라인 흐름

```
Spark
  └── silver/common_records/ (parquet)
              ↓
unified_events_to_gold
  ├── wait_for_silver         S3KeysUnchangedSensor — silver 업로드 완료 감지
  ├── validate_input          레코드 수 검증
  ├── extract_sessions        session_gold parquet + _SUCCESS 생성
  │     ├── trigger_neo4j_to_rag     session_key 전달, 즉시 트리거
  │     └── extract_entities         병렬 진행
  │           └── extract_relations
  │                 └── report_stats     Asset emit → gold_to_neo4j 트리거
  │
  ├─────────────────────────────────────────────────────────────┐
  ↓                                                             ↓
gold_to_neo4j  (Asset 트리거)                       neo4j_to_rag  (즉시 트리거)
  ├── clear_graph                                     ├── resolve_session_gold_prefix
  ├── load_sessions                                   ├── load_session_gold
  ├── load_entities                                   ├── filter_whitelist
  ├── load_relations                                  ├── build_subgraphs
  ├── create_indexes                                  ├── run_rag_analysis
  └── report_stats                                    ├── save_rag_results
                                                      └── report_rag_stats
```

---

## S3 경로

```
s3://malware-project-bucket/
├── silver/common_records/dt=*/hour=*/minute_10=*/         # Spark 출력
├── gold/session_gold/dt=*/hour=*/minute_10=*/             # 세션 gold
├── gold/entity_gold/dt=*/hour=*/minute_10=*/              # 엔티티 gold
├── gold/relation_gold/dt=*/hour=*/minute_10=*/            # 관계 gold
└── rag_result/dt=*_hour=*_minute=*_rag_results.jsonl      # RAG 추론 결과
```

---

## Airflow Variables

| Key | 설명 |
|---|---|
| `NEO4J_URI` | Neo4j 접속 URI |
| `NEO4J_USER` | Neo4j 사용자명 |
| `NEO4J_PASSWORD` | Neo4j 비밀번호 |
| `GROQ_API_KEY` | Groq API 키 |
| `GROQ_MODEL` | 사용 모델 (기본값: `llama-3.3-70b-versatile`) |
| `CLEAR_GRAPH_ENABLED` | Neo4j 초기화 여부 (`true` / `false`) |

---

## 주요 특징

- **KST 기준** — 모든 ts 필드 및 `inference_datetime` KST ISO 형식
- **중복 처리 방지** — `_SUCCESS` 마커로 배치 처리 완료 여부 판단
- **Rate Limit 대응** — Groq RPM 초과 시 `llama-3.1-8b-instant` fallback 자동 전환
- **whitelist 필터** — IP / CIDR 기반 + suspicion score 30점 미만 세션 제외
