import requests
import json
import pandas as pd
import re
import sqlite3
import logging
from datetime import datetime

# Loggingn configs
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Setup db
def setup_database():
    conn = sqlite3.connect("security_tools.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cve_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT,
        description TEXT,
        published_date TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        event TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_intel (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT,
        data TEXT
    )
    """)
    conn.commit()
    conn.close()
    logging.info("Database setup completed.")

# Get most recent vulns from NVD
def fetch_cve_data():
    url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    response = requests.get(url)
    data = response.json()
    
    cve_list = []
    for item in data['result']['CVE_Items']:
        cve_id = item['cve']['CVE_data_meta']['ID']
        description = item['cve']['description']['description_data'][0]['value']
        pub_date = item['publishedDate']
        cve_list.append((cve_id, description, pub_date))
    
    conn = sqlite3.connect("security_tools.db")
    cursor = conn.cursor()
    cursor.executemany("INSERT INTO cve_data (cve_id, description, published_date) VALUES (?, ?, ?)", cve_list)
    conn.commit()
    conn.close()
    logging.info("CVE Data fetched and stored successfully.")

# Extract security events from logs
def analyze_logs(log_file):
    with open(log_file, 'r') as f:
        logs = f.readlines()
    
    events = []
    pattern = re.compile(r'\b(Failed login|Unauthorized access|Suspicious activity)\b', re.IGNORECASE)
    
    for log in logs:
        match = pattern.search(log)
        if match:
            events.append((datetime.now().strftime("%Y-%m-%d %H:%M:%S"), log.strip()))
    
    conn = sqlite3.connect("security_tools.db")
    cursor = conn.cursor()
    cursor.executemany("INSERT INTO security_logs (timestamp, event) VALUES (?, ?)", events)
    conn.commit()
    conn.close()
    logging.info("Security log analysis completed and stored successfully.")

# Threat Intelligence Feeds Collector
# TODO: Change from example links and add more as needed
def fetch_threat_intel():
    apis = {
        "VirusTotal": "https://www.virustotal.com/api/v3/domains/some_example.com",
        "AlienVault": "https://otx.alienvault.com/api/v1/indicators/domain/some_example.com/general",
        "Shodan": "https://api.shodan.io/shodan/host/search?query=some_example"
    }
    
    intel_data = []
    for source, url in apis.items():
        response = requests.get(url)
        if response.status_code == 200:
            intel_data.append((source, json.dumps(response.json())))
    
    conn = sqlite3.connect("security_tools.db")
    cursor = conn.cursor()
    cursor.executemany("INSERT INTO threat_intel (source, data) VALUES (?, ?)", intel_data)
    conn.commit()
    conn.close()
    logging.info("Threat intelligence data collected and stored successfully.")

if __name__ == "__main__":
    setup_database()
    fetch_cve_data()
    analyze_logs("security_logs.txt")
    fetch_threat_intel()
