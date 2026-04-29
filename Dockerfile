FROM apache/airflow:3.1.6-python3.12

COPY requirements.txt /opt/airflow/requirements.txt

# 1단계: Airflow provider는 constraints로 설치
RUN pip install --no-cache-dir \
    "apache-airflow==3.1.6" \
    "apache-airflow-providers-amazon" \
    -c "https://raw.githubusercontent.com/apache/airflow/constraints-3.1.6/constraints-3.12.txt"

# 2단계: 내 requirements는 constraints 없이 설치
RUN pip install --no-cache-dir \
    "apache-airflow==3.1.6" \
    -r /opt/airflow/requirements.txt