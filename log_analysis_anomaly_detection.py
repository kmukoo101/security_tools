import re
import pandas as pd
import logging
import sqlite3
import smtplib
import socket
from datetime import datetime
from email.mime.text import MIMEText

# Logging configs
logging.basicConfig(
    filename='log_analysis.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Setup db
def setup_database():
    """Creates an SQLite database and table for storing log analysis results."""
    conn = sqlite3.connect("log_analysis.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS log_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        event TEXT,
        ip_address TEXT,
        log_entry TEXT
    )
    """)
    conn.commit()
    conn.close()
    logging.info("Database initialized.")

# Send email alerts for critical detections
def send_alert(event, ip_address, log_entry):
    """Sends email alerts when critical security events detected."""
    sender_email = "alerts@email.com"  # TODO: Replace with a valid email address
    recipient_email = "security_team@email.com"  # TODO: Replace with valid recipient
    subject = f"Security Alert: {event} Detected"
    body = f"A potential security threat was detected.\n\nEvent: {event}\nIP Address: {ip_address}\nDetails: {log_entry}\nTimestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient_email
    
    try:
        server = smtplib.SMTP("smtp.example.com", 587)  # TODO: Replace with actual SMTP server
        server.starttls()
        server.login("your_username", "your_password")  # TODO: Replace with valid credentials
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()
        logging.info(f"Alert sent for {event} from {ip_address}")
    except Exception as e:
        logging.error(f"ERROR: Failed to send alert email: {str(e)}")

# Parse log files
def analyze_logs(log_file):
    """Parses system logs for suspicious activity."""
    patterns = {
        'Failed Login': r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)',
        'Successful Root Login': r'Accepted password for root from (\d+\.\d+\.\d+\.\d+)',
        'Multiple Failed Attempts': r'authentication failure; .* rhost=(\d+\.\d+\.\d+\.\d+)',
        'Port Scanning': r'DROP IN=.* SRC=(\d+\.\d+\.\d+\.\d+) DST=.*',
        'Unauthorized Access': r'Illegal user .* from (\d+\.\d+\.\d+\.\d+)',
        'Brute Force Attack': r'Failed password for invalid user .* from (\d+\.\d+\.\d+\.\d+)',
        'Unexpected Service Access': r'Accepted password for .* from (\d+\.\d+\.\d+\.\d+) port \d+ ssh2',
        'Malicious File Execution': r'CMD=.*wget .*http',
        'Privilege Escalation Attempt': r'COMMAND=.*sudo su',
        'Database Attack': r'Failed login for user .* from (\d+\.\d+\.\d+\.\d+) to database'
    }
    
    results = []
    try:
        with open(log_file, 'r') as file:
            for line in file:
                for event, pattern in patterns.items():
                    match = re.search(pattern, line)
                    if match:
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        ip_address = match.group(1) if match.groups() else "Unknown"
                        results.append((timestamp, event, ip_address, line.strip()))
                        logging.info(f"Detected {event}: {ip_address}")
                        if event in ["Successful Root Login", "Multiple Failed Attempts", "Unauthorized Access", "Privilege Escalation Attempt", "Database Attack"]:
                            send_alert(event, ip_address, line.strip())
    except Exception as e:
        logging.error(f"ERROR: There was an issue reading log file: {str(e)}")
    
    # Store results in db
    conn = sqlite3.connect("log_analysis.db")
    cursor = conn.cursor()
    cursor.executemany("INSERT INTO log_data (timestamp, event, ip_address, log_entry) VALUES (?, ?, ?, ?)", results)
    conn.commit()
    conn.close()
    logging.info("Log analysis results stored in database.")

# Load log data from db
def load_log_data():
    """Grabs analyzed log data from database."""
    conn = sqlite3.connect("log_analysis.db")
    df = pd.read_sql("SELECT * FROM log_data", conn)
    conn.close()
    return df

# Export data (analyzed)
def export_data():
    """Exports log analysis results to CSV."""
    df = load_log_data()
    if not df.empty:
        df.to_csv("log_analysis_export.csv", index=False)
        logging.info("Log analysis data exported to CSV.")
        return "log_analysis_export.csv"
    logging.warning("WARNING: No log data available for export.")
    return None

if __name__ == "__main__":
    setup_database()
    log_file = "/var/log/auth.log"  # TODO: Allow user input for log file selection
    analyze_logs(log_file)
    logging.info("Log analysis process completed.")
