import socket
import threading
import logging
import sqlite3
import json
import smtplib
from datetime import datetime
from email.mime.text import MIMEText

# Logging configs
logging.basicConfig(
    filename='honeypot.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Setup db
def setup_database():
    """Creates database (SQLite) and table for storing honeypot logs."""
    conn = sqlite3.connect("honeypot_logs.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS honeypot (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip_address TEXT,
        port INTEGER,
        request_data TEXT,
        attack_type TEXT
    )
    """)
    conn.commit()
    conn.close()
    logging.info("Database initialized.")

# Ssend email alerts
def send_alert(ip_address, port, attack_type, request_data):
    """Sends email alerts when critical attacks detected."""
    sender_email = "alerts@sender_email.com"  # TODO: Replace with valid email
    recipient_email = "security@some_email.com"  # TODO: Replace with actual recipient
    subject = f"Honeypot Alert: {attack_type} Detected from {ip_address}"
    body = (
        f"Potential attack detected.\n\n"
        f"Attack Type: {attack_type}\n"
        f"IP Address: {ip_address}\n"
        f"Port: {port}\n"
        f"Request Data: {request_data}\n"
        f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    )
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient_email
    
    try:
        server = smtplib.SMTP("smtp.some_email.com", 587)  # TODO: Replace with SMTP server
        server.starttls()
        server.login("your_username", "your_password")  # TODO: Replace with credentials
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()
        logging.info(f"Alert sent for {attack_type} from {ip_address}")
    except Exception as e:
        logging.error(f"ERROR: Failed to send alert email: {str(e)}")

# Analyze requests
def detect_attack_patterns(request):
    """Analyzes request data to determine attack types."""
    attack_patterns = {
        "Brute Force": "password|login|admin|root",
        "SQL Injection": "union select|drop table|insert into|xp_cmdshell",
        "Port Scanning": "Nmap scan|Masscan|Zmap",
        "Malware Command": "wget http|curl http"
    }
    
    for attack_type, pattern in attack_patterns.items():
        if re.search(pattern, request, re.IGNORECASE):
            return attack_type
    return "Unknown"

# Incoming connections
def handle_connection(client_socket, client_address, port):
    """Handles incoming connections and logs attack details."""
    try:
        request = client_socket.recv(1024).decode(errors='ignore')
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip_address = client_address[0]
        attack_type = detect_attack_patterns(request)
        
        logging.info(f"{attack_type} attack attempt from {ip_address} on port {port}: {request.strip()}")
        
        conn = sqlite3.connect("honeypot_logs.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO honeypot (timestamp, ip_address, port, request_data, attack_type) VALUES (?, ?, ?, ?, ?)",
                       (timestamp, ip_address, port, request, attack_type))
        conn.commit()
        conn.close()
        
        if attack_type != "Unknown":
            send_alert(ip_address, port, attack_type, request)
        
        client_socket.send(b"Unauthorized access attempt detected. Your IP has been logged.\n")
    except Exception as e:
        logging.error(f"ERROR: There was an issue handling the connection from {client_address}: {str(e)}")
    finally:
        client_socket.close()

# Start honeypot
def start_honeypot(bind_ip="0.0.0.0", ports=[22, 80, 443, 3389, 5900]):
    """Starts honeypot."""
    logging.info("Starting honeypot...")
    setup_database()
    
    def listen_on_port(port):
        """Creates socket listener for selected port."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((bind_ip, port))
        server.listen(5)
        logging.info(f"Honeypot listening on port {port}")
        
        while True:
            try:
                client_socket, client_address = server.accept()
                logging.info(f"Connection received from {client_address[0]} on port {port}")
                client_handler = threading.Thread(target=handle_connection, args=(client_socket, client_address, port))
                client_handler.start()
            except Exception as e:
                logging.error(f"ERROR: There was a disruption accepting connection on port {port}: {str(e)}")
                break
    
    for port in ports:
        thread = threading.Thread(target=listen_on_port, args=(port,))
        thread.daemon = True
        thread.start()

if __name__ == "__main__":
    start_honeypot()
