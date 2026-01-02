from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.operators.python import PythonOperator

# 1. 기본 설정 (에러 발생 시 알림 등)
default_args = {
    "owner": "airflow",
    "depends_on_past": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=5),
}

# 2. DAG 정의
with DAG(
    dag_id="hello_world_eks",  # UI에 표시될 이름
    default_args=default_args,
    description="EKS S3 Sync Test DAG",
    schedule=timedelta(days=1),  # 매일 실행
    start_date=datetime(2025, 12, 1),  # 시작 날짜
    catchup=False,  # 과거 기록 실행 방지
    tags=["example", "eks"],
) as dag:
    # Task 1: Bash 명령어로 인사하기
    t1 = BashOperator(
        task_id="print_hello_bash",
        bash_command='echo "Hello World from Bash! (Running on EKS Worker)"',
    )

    # Task 2: Python 함수로 인사하기
    def print_hello_python():
        print("Hello World from Python! S3 Sync is working perfectly.")
        return "Hello World from Python! S3 Sync is working perfectly."

    t2 = PythonOperator(
        task_id="print_hello_python",
        python_callable=print_hello_python,
    )

    # 3. 작업 순서 정하기 (t1 실행 후 t2 실행)
    t1 >> t2
