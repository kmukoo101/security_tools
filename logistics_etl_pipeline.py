import pandas as pd
import sqlite3
import requests
import airflow
from airflow import DAG
from airflow.operators.python import PythonOperator
from datetime import datetime, timedelta

# Define ETL functions
def extract_data():
    """Extracts data."""
    url = "https://some/API-here"  # TODO: Change to API of choice
    response = requests.get(url)
    data = response.json()
    df = pd.DataFrame(data)
    df.to_csv("raw_load_data.csv", index=False)
    print("Data extracted successfully.")


def transform_data():
    """Processes and cleans data."""
    df = pd.read_csv("raw_load_data.csv")
    df.dropna(inplace=True)
    df["Profit_per_mile"] = df["Revenue"] / df["Total_Miles"]
    df.to_csv("cleaned_load_data.csv", index=False)
    print("Data transformed successfully.")


def load_data():
    """Loads transformed data into SQL database."""
    conn = sqlite3.connect("logistics.db")
    df = pd.read_csv("cleaned_load_data.csv")
    df.to_sql("load_data", conn, if_exists="replace", index=False)
    conn.close()
    print("Data loaded successfully.")

# Define Airflow DAG
default_args = {
    "owner": "airflow",
    "depends_on_past": False,
    "start_date": datetime(2024, 3, 6),
    "retries": 1,
    "retry_delay": timedelta(minutes=5),
}

dag = DAG(
    "logistics_etl_pipeline",
    default_args=default_args,
    schedule_interval=timedelta(days=1),
    catchup=False,
)

extract_task = PythonOperator(
    task_id="extract_data",
    python_callable=extract_data,
    dag=dag,
)

transform_task = PythonOperator(
    task_id="transform_data",
    python_callable=transform_data,
    dag=dag,
)

load_task = PythonOperator(
    task_id="load_data",
    python_callable=load_data,
    dag=dag,
)

extract_task >> transform_task >> load_task
