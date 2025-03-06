# Security Tools

Current Tools Available: 
1. [ETL Pipeline for Logistics Data](#1-etl-pipeline-for-logistics-data)
2. [Security Automation Toolbox](#2-security-automation-toolbox)
3. [Security Hardener](#3-security-hardener)
4. [Threat Intelligence Dashboard](#4-threat-intelligence-dashboard)
5. [Log Analysis & Anomaly Detection](#5-log-analysis--anomaly-detection)
6. [Automated Honeypot for Attack Detection](#6-automated-honeypot-for-attack-detection)

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

[Back to top](#security-tools)

---

## 1. ETL Pipeline for Logistics Data

### Overview
This project implements an ETL pipeline that automates the ingestion, processing, and storage of transportation and logistics data. The pipeline fetches data from an API, processes it using **Pandas and SQL**, and stores it in a SQLite database. Additionally, Apache Airflow is used for task scheduling and automation.

### Features
- **Extracts transportation data** from an external API or CSV source.
- **Transforms raw data** by cleaning, handling missing values, and calculating profit per mile.
- **Loads the processed data** into a SQLite database for further analysis.
- **Automated pipeline scheduling** with **Apache Airflow**.
- **Scalable and adaptable** for integration with other data sources.
  
#### Install Required Dependencies (*Optional - would need to add this file*)
```sh
pip install -r requirements.txt
```

#### Either start with Apache Airflow (*Optional*)
If you are using *Airflow*, initialize the db and start web server.
```sh
airflow db init
airflow webserver -p 8080
airflow scheduler
```

#### Or, run manually 
If you want to execute the ETL process **without** scheduling it in Apache Airflow:
```sh
python etl_pipeline.py
```


### Database Schema (SQLite Table Structure)
| Column Name     | Data Type |
|----------------|-----------|
| Load_ID        | INTEGER PRIMARY KEY |
| Revenue        | FLOAT |
| Total_Miles    | FLOAT |
| Profit_per_mile | FLOAT |
| Fuel_Cost      | FLOAT |
| Driver_Pay     | FLOAT |
| Tolls          | FLOAT |

### Future Enhancement Ideas
- Integrate with AWS S3 or Google BigQuery for cloud-based data storage.
- Deploy in Apache Spark for large-scale data processing.
- Develop a Power BI dashboard to visualize key trends.

[Back to top](#security-tools)

---

## 2. Security Automation Toolbox

### Overview
This toolset automates security data collection, enhances threat intelligence gathering, and helps security teams make data-driven decisions. This could be used for any small business hoping to enhance their security hygiene. 

1. **CVE Scanner** – Grabs and stores the latest vulnerabilities from the NVD API in an SQLite database.
2. **Log File Analyzer** – Extracts security events from firewall, syslog, and AWS CloudTrail logs using regex.
3. **Threat Intelligence Collector** – Pulls security data from **VirusTotal, AlienVault, Shodan etc, storing the results in a structured database.

#### Features
- Automated CVE scanning and risk reporting with structured data storage.
- Log analysis with regex-based security event extraction.
- Threat intelligence feed aggregation from multiple APIs.
- SQLite database storage for long-term analysis.
- Logging framework to enhance monitoring and debugging.

### Running Security Tools
1. CVE Scanner
Gets the latest vulnerabilities from NVD and stores them in an SQLite database.
```sh
python security_tools.py --fetch_cve
```

---

2. Log File Analyzer
Analyzes logs for failed login attempts, unauthorized access, and suspicious activity.
```sh
python security_tools.py --analyze_logs security_logs.txt
```

3. Threat Intelligence Collector
Grabs and stores threat intelligence data from VirusTotal, AlienVault, and Shodan.
```sh
python security_tools.py --fetch_threats
```

### **Database Schema (Formatted for GitHub)**
#### **CVE Data Table**
```plaintext
| Column Name      | Data Type  | Description                 |
|-----------------|-----------|-----------------------------|
| id             | INTEGER PRIMARY KEY | Unique identifier |
| cve_id         | TEXT      | CVE ID (e.g., CVE-2024-12345) |
| description    | TEXT      | CVE description |
| published_date | TEXT      | Date published |
```

#### **Security Logs Table**
```plaintext
| Column Name  | Data Type | Description                          |
|-------------|----------|--------------------------------------|
| id          | INTEGER PRIMARY KEY | Unique identifier       |
| timestamp   | TEXT     | Time of detected event              |
| event       | TEXT     | Log message containing security event |
```

#### **Threat Intelligence Table**
```plaintext
| Column Name | Data Type | Description                            |
|------------|----------|----------------------------------------|
| id         | INTEGER PRIMARY KEY | Unique identifier         |
| source     | TEXT     | Threat intelligence source (e.g., VirusTotal) |
| data       | TEXT     | JSON data of the intelligence feed   |
```

### Export 
All collected data can be exported into CSV format for further analysis.
```sh
python security_tools.py --export_csv
```

### Future Enhancements
- Integrate with ELK for advanced log monitoring.
- Automated alerts for critical vulnerabilities and detected security events.
- MLMs for anomaly detection in security logs.

[Back to top](#security-tools)

---

## 3. Security Hardener

### Overview
This is an automated script designed to enhance the security posture of Linux systems by enforcing hardening configurations and minimizing attack surfaces. Please note this tool is intended for system administrators, cybersecurity professionals, and small businesses looking for an accessible security solution without relying on expensive enterprise tools.

#### Features  
- **Key Configurations Backup** – Prevents accidental misconfigurations by creating backups of critical system files before making changes.  
- **SSH Hardening** – Disables root login over SSH to prevent unauthorized access.  
- **Password Policy Enforcement** – Implements strong password policies including expiration limits and minimum password age.  
- **Firewall Configuration** – Configures UFW to block unnecessary traffic and allow only essential services.  
- **Service Hardening** – Disables insecure or unnecessary services like Telnet, FTP, and NFS.  
- **System Updates** – Ensures the latest security patches are applied.  
- **Security Auditing** – Enables audit logging to monitor failed logins and suspicious activity.  
- **Fail2Ban Protection** – Installs and configures Fail2Ban to block brute-force attacks on SSH.  
- **Sudo Access Restriction** – Restricts privilege escalation to authorized users only.  
- **USB Storage Block** – Prevents unauthorized use of USB storage devices.  
- **Kernel Security Enhancements** – Applies secure kernel parameters to harden network security.  

### Run
   ```sh
   sudo python3 security_hardening.py
   ```

#### Review logs for details
   ```sh
   cat security_hardening.log
   ```

#### Future Enhancements  
- Automated reporting with a security summary after execution.  
- Email notifications when security changes are applied.  
- Integration with cloud security tools for remote hardening.  

[Back to top](#security-tools)

---

## 4. Threat Intelligence Dashboard

### Overview
This tool provides real-time security insights by gathering data from VirusTotal, AlienVault, and Shodan, allowing users to search, analyze, and export** threat data, helping security teams and small businesses stay ahead of cyber threats.

### Features
- Gathers live threat intelligence from multiple sources.
- Stores threat intelligence data in an SQLite database.
- Interactive dashboard for real-time analysis (using Streamlit).
- Search Functionality for domains, IPs, and threat indicators.
- Exports threat data to CSV.
- Logging API requests and system errors.

### Run
   ```sh
   streamlit run threat_intelligence_dashboard.py
   ```

### Future Enhancements
- Automated alerting system for high-risk threats.
- Visualization charts to show top threats over time.
- API key authentication for external data sources.

[Back to top](#security-tools)

---

## 5. Log Analysis & Anomaly Detection

### Overview
This tool automates log file analysis, detecting failed logins, brute-force attempts, privilege escalation attempts, port scanning, and unauthorized access; aimed for security teams and small businesses to monitor security logs and respond to threats efficiently.

### Features
- Monitors system logs for failed logins, brute-force attacks, and suspicious activity.
- Anomaly detection for security threats (regex).
- Stores detections in a database (SQLite).
- Sends email alerts when high-risk activity is detected.
- Exports data to CSV.
- Tracking security events with configurable logging.

### Run
   ```sh
   python log_analysis_anomaly_detection.py
   ```

### Export Logs (to CSV)
   ```sh
   python log_analysis_anomaly_detection.py --export
   ```

[Back to top](#security-tools)

---

## 6. Automated Honeypot for Attack Detection

### Overview
This tool listens for unauthorized access attempts on common attack ports (SSH, HTTP, HTTPS, RDP, VNC), detects suspicious activity, classifies attack types, and stores attack data for forensic analysis.

### Features
- Monitors multiple ports for intrusion attempts.
- Identifies attack types (Brute Force, SQL Injection, Port Scanning, Malware Execution etc.).
- Stores attack data into database for forensic analysis (SQLite).
- Sends real-time email alerts when a critical attack is detected.
- Responds to attackers to engage them and collect intelligence.
- Logging for tracking attack trends.

### Run
   ```sh
   python automated_honeypot.py
   ```

### Review Logged Attacks
   ```sh
   sqlite3 honeypot_logs.db "SELECT * FROM honeypot;"
   ```

### Future Enhancements
- Auto-block repeat offenders via firewall rules.
- Real-time dashboard for attack visualizations (interactive, ideally).
- Integration with SIEM tools.

[Back to top](#security-tools)

---
