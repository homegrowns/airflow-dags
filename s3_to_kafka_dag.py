import json
from datetime import datetime
from io import BytesIO

import boto3
import pandas as pd
from airflow import DAG
from airflow.operators.python import PythonOperator
from confluent_kafka import Producer

# BytesIO(data)는


# 바이트를 파일처럼 흉내내는 객체
def to_json_safe(record: dict) -> str:
    # dict 내부의 NaN을 None으로 변환
    for k, v in list(record.items()):
        if isinstance(v, float) and math.isnan(v):
            record[k] = None
    # JSON 표준 강제 (NaN 있으면 여기서 터짐)
    return json.dumps(record, allow_nan=False)


def s3_to_kafka():
    total_rows = 0
    bootstrap = "kafka-broker-headless.kafka.svc.cluster.local:9092"
    # 또는 더 짧게
    # bootstrap = "kafka-broker-headless.kafka:9092"

    producer = Producer({"bootstrap.servers": bootstrap})
    s3 = boto3.client("s3")
    bucket = "malware-project-bucket"
    prefix = "honeypot/raw/zeek/http/2026-02-11/"

    response = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)

    for obj in response.get("Contents", []):
        key = obj["Key"]
        if not key.endswith(".parquet"):
            continue
        data = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        df = pd.read_parquet(BytesIO(data))

        total_rows += len(df)

        for record in df.to_dict("records"):
            producer.produce(
                topic="zeek-http",
                key=record.get("community_id"),
                value=to_json_safe(record),
            )
            producer.poll(0)

    producer.flush()
    print("총 레코드 수:", total_rows)


with DAG(
    dag_id="s3_to_kafka_http",
    start_date=datetime(2026, 2, 20),
    schedule="0 12 * * *",
    catchup=False,
) as dag:
    task = PythonOperator(task_id="send_http_logs", python_callable=s3_to_kafka)
