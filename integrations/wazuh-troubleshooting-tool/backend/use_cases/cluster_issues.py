from executor import run_command
import json
from config import INDEXER_USERNAME, INDEXER_PASSWORD, INDEXER_URL

def cluster_issues_flow(user_choice=None, context=None):
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
            "Let's troubleshoot Wazuh Indexer Cluster Issues.\n"
            "This problem generally manifests as yellow/red cluster health, missing nodes, or unassigned shards.\n\n"
            "Querying cluster health status..."
        )
        health_raw = run_command(f"curl -s -k -u {INDEXER_USERNAME}:'{INDEXER_PASSWORD}' {INDEXER_URL}/_cluster/health") or ""
        try:
            health = json.loads(health_raw)
            status = health.get("status", "unknown")
            nodes = health.get("number_of_nodes", 0)
            shards = health.get("active_shards", 0)
            unassigned = health.get("unassigned_shards", 0)

            response["display"] += (
                f"\n\nCluster Health Snapshot:\n"
                f"  Status:             {status.upper()}\n"
                f"  Nodes:              {nodes}\n"
                f"  Active Shards:      {shards}\n"
                f"  Unassigned Shards:  {unassigned}\n"
            )
            
            if status != "green":
                response["display"] += f"\n[WARNING] Cluster status is {status.upper()}.\nLet's check for unassigned shards and why they exist."
                response["ask"] = ["Explain unassigned shards? (yes / no)"]
                context["stage"] = "explain_shards"
                return response
            else:
                response["display"] += "\n[OK] Cluster status is GREEN."
                response["done"] = True
                return response
        except Exception as e:
            response["display"] += f"\n\n[ERROR] Failed to query cluster health. Is the indexer running?\nResponse: {health_raw}"
            response["ask"] = ["Run indexer status check? (yes / no)"]
            context["stage"] = "indexer_status"
            return response

    stage = context.get("stage")

    if stage == "indexer_status":
        if user_choice and "yes" in user_choice.lower():
            status = (run_command("systemctl is-active wazuh-indexer") or "").strip()
            response["display"] = f"Indexer service status: {status.upper()}"
            if status != "active":
                response["display"] += "\n\nwazuh-indexer is not active. Would you like me to restart it?"
                response["ask"] = ["Restart indexer? (yes / no)"]
                context["stage"] = "restart_indexer"
                return response
        else:
            response["display"] = "Skipping service check."
        
        response["done"] = True
        return response

    if stage == "restart_indexer":
        if user_choice and "yes" in user_choice.lower():
            run_command("systemctl restart wazuh-indexer")
            response["display"] = "Restart command sent. Please run full health check later."
        else:
            response["display"] = "Cancelled."
        response["done"] = True
        return response

    if stage == "explain_shards":
        if user_choice and "yes" in user_choice.lower():
            shards_raw = run_command(f"curl -s -k -u {INDEXER_USERNAME}:'{INDEXER_PASSWORD}' {INDEXER_URL}/_cat/shards?h=index,shard,state,unassigned.reason | grep UNASSIGNED") or ""
            response["display"] = f"Unassigned Shards details (first 10 lines):\n\n"
            lines = shards_raw.splitlines()[:10]
            if lines:
                response["display"] += "\n".join(lines) + "\n\n"
                response["display"] += "Common reasons for unassigned shards:\n"
                response["display"] += "  - ALLOCATOR_ON_OUT_OF_DISK_WATERMARK: Disk is full (exceeded 90%).\n"
                response["display"] += "  - CLUSTER_RECOVERED: Shards are recovering from a restart.\n"
                response["display"] += "  - INDEX_CREATED: Primary or replica shards are still initializing.\n"
            else:
                response["display"] += "No unassigned shards found in the check."
        else:
            response["display"] = "Skipped shard analysis."
        
        response["done"] = True
        return response

    response["display"] = "Invalid stage."
    response["done"] = True
    return response
