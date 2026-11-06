import subprocess
from wazuh_api import check_api

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()
    except:
        return "error"

def get_system_data():
    return {
        "manager": run("systemctl status wazuh-manager"),
        "indexer": run("systemctl status wazuh-indexer"),
        "dashboard": run("systemctl status wazuh-dashboard"),
        "logs": run("tail -n 20 /var/ossec/logs/ossec.log"),
        "disk": run("df -h"),
        "memory": run("free -h"),
        "api": check_api()
    }
