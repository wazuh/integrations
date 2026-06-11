from executor import run_command
import time
from config import INDEXER_USERNAME, INDEXER_PASSWORD, INDEXER_URL

def indexing_error_flow(user_choice=None, context=None):
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
            "Let's troubleshoot Wazuh indexing errors. This typically occurs when the "
            "wazuh-indexer service is down, certificates are invalid, or disk watermark is exceeded.\n\n"
            "Checking wazuh-indexer status..."
        )
        status = (run_command("systemctl is-active wazuh-indexer") or "").strip()
        context["indexer_status"] = status
        
        if status != "active":
            response["display"] += f"\n\n[WARNING] wazuh-indexer is {status.upper()}.\nWould you like me to restart it?"
            response["ask"] = ["Restart indexer? (yes / no)"]
            context["stage"] = "restart_indexer"
            return response
        else:
            response["display"] += "\n\n[OK] wazuh-indexer is active.\nLet's check the disk space usage."
            response["ask"] = ["Check disk space? (auto / manual)"]
            context["stage"] = "disk_check"
            return response

    stage = context.get("stage")

    if stage == "restart_indexer":
        if user_choice and "yes" in user_choice.lower():
            response["display"] = "Restarting wazuh-indexer service..."
            run_command("systemctl restart wazuh-indexer")
            time.sleep(3)
            status = (run_command("systemctl is-active wazuh-indexer") or "").strip()
            response["display"] += f"\n\nStatus after restart: {status.upper()}"
            if status == "active":
                response["display"] += "\n\nIndexer restarted successfully. Checking disk space now."
                response["ask"] = ["Check disk space? (auto / manual)"]
                context["stage"] = "disk_check"
                return response
            else:
                response["display"] += "\n\nFailed to restart indexer. Please check system logs for issues."
                response["done"] = True
                return response
        else:
            response["display"] = "Skipped indexer restart. Checking disk space."
            response["ask"] = ["Check disk space? (auto / manual)"]
            context["stage"] = "disk_check"
            return response

    if stage == "disk_check":
        if user_choice and "auto" in user_choice.lower():
            df_out = run_command("df -h /var/lib/wazuh-indexer") or ""
            response["display"] = f"Disk Space check output:\n\n{df_out}\n\n"
            if "90%" in df_out or "95%" in df_out or "98%" in df_out or "99%" in df_out:
                response["display"] += (
                    "[WARNING] Disk usage is critically high! Wazuh indexer blocks indexing if "
                    "disk watermark exceeds 90%.\n"
                    "Please delete old indices or expand storage."
                )
            else:
                response["display"] += "[OK] Disk space looks acceptable."
            
            response["ask"] = ["Run cluster health check? (yes / no)"]
            context["stage"] = "cluster_health_check"
            return response
        else:
            response["display"] = (
                "Please run `df -h` on the indexer server and verify disk usage for /var/lib/wazuh-indexer/.\n"
                "If usage is above 90%, clear indices or free up disk space."
            )
            response["ask"] = ["Is disk space sufficient? (yes / no)"]
            context["stage"] = "disk_check_manual"
            return response

    if stage == "disk_check_manual":
        if user_choice and "no" in user_choice.lower():
            response["display"] = "Please free up disk space and try again."
            response["done"] = True
            return response
        else:
            response["display"] = "Disk space verified. Moving to cluster health check."
            response["ask"] = ["Run cluster health check? (yes / no)"]
            context["stage"] = "cluster_health_check"
            return response

    if stage == "cluster_health_check":
        if user_choice and "yes" in user_choice.lower():
            cluster_out = run_command(f"curl -k -s -u {INDEXER_USERNAME}:'{INDEXER_PASSWORD}' {INDEXER_URL}/_cluster/health") or ""
            response["display"] = f"Cluster Health Status:\n\n{cluster_out}\n\n"
            if "red" in cluster_out.lower():
                response["display"] += "The cluster health status is RED. This indicates that some primary shards are unassigned."
            elif "yellow" in cluster_out.lower():
                response["display"] += "The cluster health status is YELLOW. This indicates that replica shards are unassigned."
            else:
                response["display"] += "[OK] Cluster status is GREEN."
        else:
            response["display"] = "Skipped cluster check."

        response["display"] += "\n\nTroubleshooting complete."
        response["done"] = True
        return response

    response["display"] = "Invalid stage."
    response["done"] = True
    return response
