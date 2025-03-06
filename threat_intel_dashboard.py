import streamlit as st
import pandas as pd
import requests
import logging
import sqlite3
from datetime import datetime

# Logging configs 
logging.basicConfig(
    filename='threat_intel_dashboard.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Setup db
def setup_database():
    """
    Initializes SQLite database and creates table (if it doesn't already exist).
    This table stores threat intelligence data retrieved from external APIs.
    """
    conn = sqlite3.connect("threat_intel.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT,
        data TEXT,
        timestamp TEXT
    )
    """)
    conn.commit()
    conn.close()
    logging.info("Database initialized.")

# Get threat intelligence data
def fetch_threat_intel():
    """
    Retrieves threat intelligence data from multiple external APIs.
    If successful, it stores the retrieved data in the database.
    """
    apis = {
        "VirusTotal": "https://www.virustotal.com/api/v3/domains/some_example.com", # TODO: Allow dynamic domain input
        "AlienVault": "https://otx.alienvault.com/api/v1/indicators/domain/some_example.com/general", # TODO: Add user input 
        "Shodan": "https://api.shodan.io/shodan/host/search?query=some_example", # TODO: Add API key 
      # TODO: Add more
    }
    
    intel_data = []
    for source, url in apis.items():
        try:
            response = requests.get(url)
            if response.status_code == 200:
                intel_data.append((source, response.json(), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                logging.info(f"Successfully grabbed data from {source}.")
            else:
                logging.warning(f"ERROR: Failed to get data from {source}. Status code: {response.status_code}")
        except Exception as e:
            logging.error(f"ERROR: There was a problem fetching data from {source}: {str(e)}")
    
    # Store data in db
    conn = sqlite3.connect("threat_intel.db")
    cursor = conn.cursor()
    cursor.executemany("INSERT INTO threat_data (source, data, timestamp) VALUES (?, ?, ?)", intel_data)
    conn.commit()
    conn.close()
    logging.info("Threat intelligence data stored in database.")

# Load data to db
def load_threat_data():
    """
    Retrieves all stored threat intelligence data from database (SQLite).
    Returns Pandas dataframe for manipulation in dashboard.
    """
    conn = sqlite3.connect("threat_intel.db")
    df = pd.read_sql("SELECT * FROM threat_data", conn)
    conn.close()
    return df

# Export data
def export_data():
    """
    Exports threat intelligence data to CSV for analysis.
    If data is available, it returns filename, otherwise returns None.
    """
    df = load_threat_data()
    if not df.empty:
        df.to_csv("threat_intel_export.csv", index=False)
        logging.info("Threat intelligence data exported to CSV.")
        return "threat_intel_export.csv"
    logging.warning("ERROR: No data available to export.")
    return None

# UI for dashboard
def main():
    """
    Runs app, providing an interactive dashboard for
    viewing, fetching, searching, exporting threat intelligence data etc.
    """
    st.title("Threat Intelligence Dashboard")
    st.sidebar.header("Threat Intelligence Feeds")
    
    if st.sidebar.button("Fetch Latest Threat Data"):
        fetch_threat_intel()
        st.sidebar.success("Threat intelligence data updated.")
    
    df = load_threat_data()
    if not df.empty:
        st.subheader("Threat Intelligence Data")
        st.dataframe(df[['source', 'timestamp']])
    else:
        st.write("ERROR: No threat data available. Update to latest data using the sidebar.")

    # Search 
    st.sidebar.header("Search Threat Data")
    search_term = st.sidebar.text_input("Enter domain or IP")
    if st.sidebar.button("Search"):
        search_results = df[df['data'].str.contains(search_term, na=False, case=False)]
        if not search_results.empty:
            st.subheader(f"Search Results for '{search_term}'")
            st.dataframe(search_results)
        else:
            st.write("ERROR: No matching threat data found.")

    # Export Data
    if st.sidebar.button("Export Data"):
        file_path = export_data()
        if file_path:
            st.sidebar.success(f"Data exported successfully: {file_path}")
        else:
            st.sidebar.error("ERROR: No data to export.")

if __name__ == "__main__":
    setup_database()
    main()
