import pytest
from airflow.models import DagBag
from src.common.common_helper import *
from security_metadata.aws_config import *
from security_metadata.mappings import *
from src.gold_to_neo4j.neo4j.session_query_v1 import *
from src.neo4_to_rag.s3_route_helper import *
from src.neo4_to_rag.s3_tmp_helper import *
from src.neo4_to_rag.s3_streaming_writer import *
from src.neo4_to_rag.neo4j.prompt import *
from src.unified_to_gold.gold_parquet_route import *

def test_dag_bag():
    # DAG 폴더 내의 모든 파일을 로드하여 임포트 에러가 발생하는지 체크
    dag_bag = DagBag(dag_folder='dags/', include_examples=False)
    
    # 1. 임포트 에러 확인
    assert len(dag_bag.import_errors) == 0, f"DAG Import Errors: {dag_bag.import_errors}"
    
    # 2. 모든 DAG에 cycle(순환 참조)이 없는지 확인
    for dag_id, dag in dag_bag.dags.items():
        assert len(dag.tasks) > 0