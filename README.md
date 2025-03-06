# security_tools

## ETL Pipeline for Load Data (Logistics BI Project)

## Overview
This project implements an ETL pipeline that automates the ingestion, processing, and storage of transportation and logistics data. The pipeline fetches data from an API, processes it using **Pandas and SQL**, and stores it in a SQLite database. Additionally, Apache Airflow is used for task scheduling and automation.

## Features
- **Extracts transportation data** from an external API or CSV source.
- **Transforms raw data** by cleaning, handling missing values, and calculating profit per mile.
- **Loads the processed data** into a SQLite database for further analysis.
- **Automated pipeline scheduling** with **Apache Airflow**.
- **Scalable and adaptable** for integration with other data sources.

## Tech Used
- **Python** (Pandas, Requests, SQLite3)
- **Apache Airflow** (Task Scheduling & Automation)
- **SQL** (Data Storage & Querying)
- **ETL Process Automation**

## Setup

### Clone Repo
```sh
git clone https://github.com/yourusername/etl-logistics-pipeline.git
cd etl-logistics-pipeline
```

### Create Virtual Environment
To ensure dependency isolation, create a virtual environment.

#### **Windows**
```sh
python -m venv venv
venv\Scripts\activate
```

#### **Mac and Linux**
```sh
python3 -m venv venv
source venv/bin/activate
```

### Install Required Dependencies (*Optional - would need to add this file*)
```sh
pip install -r requirements.txt
```

### Either start with Apache Airflow (*Optional*)
If you are using *Airflow*, initialize the db and start web server.
```sh
airflow db init
airflow webserver -p 8080
airflow scheduler
```

### Or, run manually 
If you want to execute the ETL process **without** scheduling it in Apache Airflow:
```sh
python etl_pipeline.py
```

## File Structure
```
├── logistics_etl_pipeline.py  # Logistics ETL pipeline script
├── requirements.txt  # Make sure to add required dependencies file (not included)
├── raw_load_data.csv  # Extracted data (not included - can change filename if needed)
├── cleaned_load_data.csv  # Processed data after transformation
├── logistics.db  # SQLite database storing final data
├── README.md  # Docs
```

## Database Schema (SQLite Table Structure)
| Column Name     | Data Type |
|----------------|-----------|
| Load_ID        | INTEGER PRIMARY KEY |
| Revenue        | FLOAT |
| Total_Miles    | FLOAT |
| Profit_per_mile | FLOAT |
| Fuel_Cost      | FLOAT |
| Driver_Pay     | FLOAT |
| Tolls          | FLOAT |

## Future Enhancement Ideas
- Integrate with AWS S3 or Google BigQuery for cloud-based data storage.
- Deploy in Apache Spark for large-scale data processing.
- Develop a Power BI dashboard to visualize key trends.

