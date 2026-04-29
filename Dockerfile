# FROM apache/airflow:3.0.2-python3.11
FROM apache/airflow:3.2.1-python3.13
USER airflow
WORKDIR /opt/airflow

COPY requirements.txt /opt/airflow/requirements.txt

# RUN pip install --no-cache-dir \
#     "apache-airflow-providers-amazon==9.8.0" \
#     -c "https://raw.githubusercontent.com/apache/airflow/constraints-3.2.1/constraints-3.13.txt" \
#  && pip install --no-cache-dir -r /opt/airflow/requirements.txt

RUN pip install --no-cache-dir \
    apache-airflow-providers-amazon \
    -r /opt/airflow/requirements.txt \
    -c "https://raw.githubusercontent.com/apache/airflow/constraints-3.2.1/constraints-3.13.txt"