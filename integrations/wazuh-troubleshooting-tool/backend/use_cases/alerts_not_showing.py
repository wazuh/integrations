from executor import run_command
import time
from config import INDEXER_USERNAME, INDEXER_PASSWORD, INDEXER_URL

def alerts_not_showing_flow(user_choice=None, context=None):
    if context is None:
        context = {}

    response = {
        "display": "",
        "ask":     [],
        "done":    False,
        "context": context,
    }

    # START
    if not context:
        response["display"] = (
            "Let's troubleshoot 'Alerts Not Showing on Dashboard'.\n"
            "This can happen due to:\n"
            "  - wazuh-agent service stopped on target endpoints\n"
            "  - Filebeat service inactive or unable to connect to the indexer\n"
            "  - Rule/decoder configurations discarding the events\n\n"
            "Checking wazuh-agent connection status..."
        )
        agent_out = run_command(f"curl -k -s -u {INDEXER_USERNAME}:'{INDEXER_PASSWORD}' {INDEXER_URL}/_cat/indices | grep wazuh-alerts") or ""
        response["display"] += f"\n\nActive Alert Indices:\n{agent_out if agent_out else '(No alert indices found)'}"
        response["ask"] = ["Check Filebeat status? (yes / no)"]
        context["stage"] = "check_filebeat"
        return response

    stage = context.get("stage")

    if stage == "check_filebeat":
        if user_choice and "yes" in user_choice.lower():
            fb_status = (run_command("systemctl is-active filebeat") or "").strip()
            response["display"] = f"Filebeat status: {fb_status.upper()}"
            if fb_status != "active":
                response["display"] += "\n\n[WARNING] Filebeat is NOT running. Let's try starting it."
                response["ask"] = ["Start Filebeat? (yes / no)"]
                context["stage"] = "start_filebeat"
                return response
            else:
                response["display"] += "\n\n[OK] Filebeat is running. Let's run a connection test."
                response["ask"] = ["Run Filebeat output test? (yes / no)"]
                context["stage"] = "test_filebeat_output"
                return response
        else:
            response["display"] = "Skipped Filebeat check. Let's check wazuh-manager active agents."
            response["ask"] = ["Check active agents? (yes / no)"]
            context["stage"] = "check_agents"
            return response

    if stage == "start_filebeat":
        if user_choice and "yes" in user_choice.lower():
            run_command("systemctl start filebeat")
            time.sleep(2)
            fb_status = (run_command("systemctl is-active filebeat") or "").strip()
            response["display"] = f"Filebeat status after starting: {fb_status.upper()}"
            if fb_status == "active":
                response["display"] += "\n\nFilebeat started successfully. Running connection test."
                response["ask"] = ["Run Filebeat output test? (yes / no)"]
                context["stage"] = "test_filebeat_output"
                return response
            else:
                response["display"] += "\n\nFailed to start Filebeat. Please check `/var/log/filebeat/filebeat` logs."
                response["done"] = True
                return response
        else:
            response["display"] = "Skipping Filebeat startup. Verification complete."
            response["done"] = True
            return response

    if stage == "test_filebeat_output":
        if user_choice and "yes" in user_choice.lower():
            fb_test = run_command("filebeat test output") or ""
            response["display"] = f"Filebeat output test result:\n\n{fb_test}\n\n"
            if "talk to server... OK" in fb_test or "OK" in fb_test:
                response["display"] += "[SUCCESS] Filebeat can connect to indexer successfully."
            else:
                response["display"] += (
                    "[ERROR] Filebeat output test failed. Check SSL certificates configuration in `/etc/filebeat/filebeat.yml`."
                )
        else:
            response["display"] = "Skipped Filebeat connection test."
        
        response["done"] = True
        return response

    if stage == "check_agents":
        if user_choice and "yes" in user_choice.lower():
            agents_status = run_command("/var/ossec/bin/agent_control -l") or ""
            response["display"] = f"Active Agents:\n\n{agents_status}\n\n"
            response["display"] += "Make sure your agents are in 'Active' state."
        else:
            response["display"] = "Skipped active agent check."
        
        response["done"] = True
        return response

    response["display"] = "Invalid stage."
    response["done"] = True
    return response
