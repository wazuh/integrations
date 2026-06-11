def analyze(data):

    # ----------------------------
    # API AUTH FAILURE
    # ----------------------------
    if "API AUTH FAILED" in data["api"]:
        return {
            "problem": "Wazuh API authentication failed",
            "fix": "Check API credentials in config.py",
            "command": None
        }

    # ----------------------------
    # API CONNECTION FAILURE
    # ----------------------------
    if "API CONNECTION FAILED" in data["api"]:
        return {
            "problem": "Wazuh API not reachable",
            "fix": "Manager service might be down",
            "command": "sudo systemctl restart wazuh-manager"
        }

    # ----------------------------
    # INDEXER DOWN
    # ----------------------------
    if "inactive" in data["indexer"] or "failed" in data["indexer"]:
        return {
            "problem": "Wazuh Indexer is DOWN",
            "fix": "Restart Wazuh Indexer",
            "command": "sudo systemctl restart wazuh-indexer"
        }

    # ----------------------------
    # MANAGER DOWN
    # ----------------------------
    if "inactive" in data["manager"] or "failed" in data["manager"]:
        return {
            "problem": "Wazuh Manager is DOWN",
            "fix": "Restart Wazuh Manager",
            "command": "sudo systemctl restart wazuh-manager"
        }

    # ----------------------------
    # DASHBOARD DOWN
    # ----------------------------
    if "inactive" in data["dashboard"] or "failed" in data["dashboard"]:
        return {
            "problem": "Wazuh Dashboard is DOWN",
            "fix": "Restart Wazuh Dashboard",
            "command": "sudo systemctl restart wazuh-dashboard"
        }

    # ----------------------------
    # ERROR3099
    # ----------------------------
    if "ERROR3099" in data["logs"]:
        return {
            "problem": "Wazuh modules failure (ERROR3099)",
            "fix": "Restart Wazuh Manager",
            "command": "sudo systemctl restart wazuh-manager"
        }

    # ----------------------------
    # DISK FULL
    # ----------------------------
    if "100%" in data["disk"] or "95%" in data["disk"]:
        return {
            "problem": "Disk usage too high",
            "fix": "Clean disk or increase storage",
            "command": None
        }

    # ----------------------------
    # MEMORY LOW
    # ----------------------------
    if "available" in data["memory"] and "Mi" in data["memory"]:
        return {
            "problem": "Memory might be low",
            "fix": "Consider increasing RAM",
            "command": None
        }

    return {
        "problem": "System OK",
        "fix": "No action needed",
        "command": None
    }
