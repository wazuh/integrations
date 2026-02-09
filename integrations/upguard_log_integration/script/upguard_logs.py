import requests
import json
import os
from datetime import datetime


# === Config ===
UPGUARD_API_KEY = "<Upguard API Key>"  # Replace with your actual API key
UPGUARD_API_URL = "https://cyber-risk.upguard.com/api/public/risks" # Upguard public api url, for more reference visit here: https://cyber-risk.upguard.com/api/docs#tag/risks/operation/risk
LOG_FILE = "/var/ossec/logs/upguard_logs.log"  # Wazuh reads logs from here

# === Fetch Risks from UpGuard ===
def fetch_upguard_risks():
     headers = {
         "Authorization": UPGUARD_API_KEY,
         "Content-Type": "application/json"
     }
     response = requests.get(UPGUARD_API_URL, headers=headers)
     response.raise_for_status()
     return response.json().get("risks", [])

 # === Write Logs to File for Wazuh to Pick Up ===
def write_to_log_file(risks):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as log_file:
        for risk in risks:
            event = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "integration": "upguard",
                "risk_id": risk.get("id"),
                "severity": risk.get("severity"),
                "vendor": risk.get("vendor", {}).get("name"),
                "finding": risk.get("finding"),
                "category": risk.get("category"),
                "source": risk
            }
            log_file.write(json.dumps(event) + "\n")
            print(f"Wrote risk ID {risk.get('id')} to log")

# === Main ===
if __name__ == "__main__":
    try:
        risks = fetch_upguard_risks()
        if risks:
            write_to_log_file(risks)
        else:
            print("No risks found.")
    except Exception as e:
        print(f"Error: {e}")
