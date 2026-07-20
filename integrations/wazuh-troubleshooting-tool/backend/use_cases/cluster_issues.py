"""
Use case: 'Cluster Health Issues'.

Checks cluster health and, if it isn't green, drills down into the actual
root cause instead of just listing unassigned shards and generic reason
codes (CLUSTER_RECOVERED, INDEX_CREATED, disk watermark, ...):

    write blocks -> node topology / data nodes -> disk watermark ->
    shard limits -> per-shard _cluster/allocation/explain -> targeted fix

Reuses the same utils/ helpers as use_cases/no_alerts_are_showing.py (cluster
health/shards, replica count, reindex, disk/log checks) rather than
re-implementing any of them here.
"""

import json

from utils.service_utils import get_service_status, restart_service_and_wait
from utils.cluster_utils import get_cluster_status, get_cluster_health, get_write_blocks, clear_write_blocks
from utils.shard_utils import (
    get_node_count, get_unassigned_shards, explain_allocation,
    get_shard_capacity_percent, is_near_shard_limit,
)
from utils.replica_utils import recommend_replica_count, set_replica_count
from utils.reindex_utils import reindex_for_mapping_conflict
from utils.fix_engine import FixEngine
from utils.log_handler import LogHandler
from utils.log_analyzer import LogAnalyzer
from utils.ai_utils import ai_explain
from config import INDEXER_URL

UNCLEAR_ALLOCATION_SYSTEM_PROMPT = (
    "You are a Wazuh Indexer (OpenSearch) troubleshooting expert. You'll be given the raw "
    "_cluster/allocation/explain response for an unassigned shard that doesn't match any of "
    "the known causes (disk watermark, single-node replica, missing data node, shard limit). "
    "In 3-4 short sentences: state the most likely root cause and the single most useful next "
    "command or config fix. Be specific to what's actually in the data - don't give generic advice."
)


def _stop(response, title, explanation, fix_text):
    response["display"] += f"\n\n[ROOT CAUSE FOUND] {title}\n\n{explanation}\n\nRecommended fix:\n{fix_text}"
    response["done"] = True
    return response


def cluster_issues_flow(user_choice=None, context=None):
    if context is None:
        context = {}

    response = {"display": "", "ask": [], "done": False, "context": context}
    choice = (user_choice or "").strip().lower()

    # START
    if not context:
        response["display"] = (
            "Let's troubleshoot Wazuh Indexer Cluster Issues.\n"
            "This problem generally manifests as yellow/red cluster health, missing nodes, or unassigned shards.\n\n"
            "Querying cluster health status..."
        )
        health, raw = get_cluster_health()
        if not health:
            response["display"] += f"\n\n[ERROR] Failed to query cluster health. Is the indexer running?\nResponse: {raw}"
            response["ask"] = ["Run indexer status check? (yes / no)"]
            context["stage"] = "indexer_status"
            return response

        status = health.get("status", "unknown")
        nodes = health.get("number_of_nodes", 0)
        active_shards = health.get("active_shards", 0)
        unassigned_count = health.get("unassigned_shards", 0)

        response["display"] += (
            f"\n\nCluster Health Snapshot:\n"
            f"  Status:             {status.upper()}\n"
            f"  Nodes:              {nodes}\n"
            f"  Active Shards:      {active_shards}\n"
            f"  Unassigned Shards:  {unassigned_count}\n"
        )

        if status == "green":
            response["display"] += "\n[OK] Cluster status is GREEN."
            response["done"] = True
            return response

        response["display"] += f"\n[WARNING] Cluster status is {status.upper()}. Investigating the root cause..."
        return _diagnose(response, context)

    stage = context.get("stage")

    if stage == "indexer_status":
        if "yes" in choice:
            status = get_service_status("wazuh-indexer")
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
        if "yes" in choice:
            status = restart_service_and_wait("wazuh-indexer")
            response["display"] = (
                f"Restart command sent - wazuh-indexer is now {status.upper()}. "
                "Please re-run this workflow to check cluster health."
            )
        else:
            response["display"] = "Cancelled."
        response["done"] = True
        return response

    if stage == "fix_write_blocks":
        block_names = context.get("write_blocks", [])
        if "auto" in choice:
            raw = clear_write_blocks(block_names)
            response["display"] = f"Cleared {len(block_names)} block(s):\n{', '.join(block_names)}\n{raw}"
            return _diagnose(response, context)
        if "manual" in choice:
            response["display"] = _manual_clear_blocks_instructions(block_names)
            response["ask"] = ["Done"]
            context["stage"] = "fix_write_blocks_manual_wait"
            return response
        response["ask"] = ["Auto", "Manual"]
        return response

    if stage == "fix_write_blocks_manual_wait":
        return _diagnose(response, context)

    if stage == "fix_replicas":
        indices = context.get("unassigned_indices", [])
        recommended = context.get("recommended_replicas", 0)
        if "auto" in choice:
            lines = []
            for index_name in indices:
                raw = set_replica_count(index_name, recommended)
                lines.append(f"  - {index_name}: {raw}")
            response["display"] = f"Set number_of_replicas={recommended} on:\n" + "\n".join(lines)
        elif "manual" in choice:
            response["display"] = _manual_replica_instructions(indices, recommended)
        else:
            response["ask"] = ["Auto", "Manual"]
            return response
        return _offer_reindex(response, context)

    if stage == "reindex_method":
        indices = context.get("unassigned_indices", [])
        if "skip" in choice:
            response["display"] = "Skipping the reindex."
            response["done"] = True
            return response
        if "manual" in choice:
            response["display"] = _manual_reindex_instructions(indices)
            response["ask"] = ["Done", "Skip"]
            context["stage"] = "reindex_manual_wait"
            return response
        if "auto" in choice:
            return _auto_reindex(response, context)
        response["ask"] = ["Auto (reindex, keeps data)", "Manual", "Skip"]
        return response

    if stage == "reindex_manual_wait":
        if "skip" in choice:
            response["display"] = "Skipping verification."
            response["done"] = True
            return response
        return _verify_after_reindex(response, context)

    response["display"] = "Invalid stage."
    response["done"] = True
    return response


# ---------------------------------------------------------------------------
# Root-cause diagnosis
# ---------------------------------------------------------------------------
def _diagnose(response, context):
    # Cluster may have already recovered on its own (e.g. right after a
    # block was cleared) - check that before running the rest of the chain.
    health, _ = get_cluster_health()
    if health and health.get("status") == "green":
        response["display"] += "\n\n[OK] Cluster status is now GREEN."
        response["done"] = True
        return response

    # 1) Cluster-wide write/index-creation blocks - these silently prevent
    # allocation regardless of anything else, so rule them out first.
    block_result = get_write_blocks()
    if block_result.get("error"):
        response["display"] += f"\n[WARNING] Could not check cluster write blocks: {str(block_result['error'])[:200]}"
    elif block_result.get("blocks"):
        return _offer_clear_write_blocks(response, context, block_result["blocks"])
    else:
        response["display"] += "\n[OK] No cluster-wide write/index-creation blocks found."

    # 2) Topology - single-node vs multi-node, and whether the expected
    # data-holding nodes are actually online.
    node_count, node_names = get_node_count()
    context["node_count"] = node_count
    number_of_nodes = health.get("number_of_nodes", node_count) if health else node_count
    number_of_data_nodes = health.get("number_of_data_nodes", number_of_nodes) if health else number_of_nodes
    topology = "single-node" if node_count <= 1 else f"multi-node ({node_count} nodes)"

    response["display"] += (
        f"\nDeployment topology: {topology}.\n"
        f"Online nodes: {', '.join(node_names) if node_names else '(none reachable)'}\n"
        f"Data-holding nodes: {number_of_data_nodes} of {number_of_nodes} total node(s)."
    )

    if number_of_data_nodes < 1:
        return _stop(
            response, "No data-holding indexer node online",
            f"The cluster reports {number_of_nodes} total node(s) but 0 of them are eligible to "
            "hold data (node.roles missing 'data', or the data node(s) are down) - shards have "
            "nowhere to be allocated.",
            "Check `systemctl status wazuh-indexer` on the node(s) that should hold data, confirm "
            "they can reach the rest of the cluster on the transport port (9300), and restart them.",
        )

    # 3) Disk usage / watermark - a full/near-full disk blocks allocation
    # cluster-wide even if the cluster otherwise looks fine.
    disk_output = FixEngine.check_disk()
    indexer_logs = LogHandler.get_indexer_logs(2)
    if "watermark" in LogAnalyzer.get_issues(indexer_logs):
        return _stop(
            response, "Disk watermark exceeded",
            f"The indexer log shows a disk watermark warning, which blocks shard allocation to "
            f"protect against running out of disk. Current disk usage:\n\n{disk_output}",
            "Free up disk space on the affected node (or temporarily raise "
            "cluster.routing.allocation.disk.watermark.*), then retry allocation with:\n"
            f"  curl -k -u admin:<password> -XPOST \"{INDEXER_URL}/_cluster/reroute?retry_failed=true\"",
        )

    # 4) Shard limits / allocation restrictions.
    capacity = get_shard_capacity_percent()
    if capacity is not None:
        response["display"] += f"\nShard capacity in use: {capacity}%"
    if is_near_shard_limit():
        return _stop(
            response, "Approaching cluster.max_shards_per_node limit",
            f"The cluster is using {capacity}% of its total shard capacity across {node_count} "
            "node(s) - new/unassigned shards can't be allocated once this limit is hit.",
            "Reduce the shard count (lower number_of_replicas, delete or roll over old indices), "
            "or raise cluster.max_shards_per_node if the hardware can support it.",
        )

    # 5) Per-shard root cause via the real allocation/explain API, instead of
    # the terse reason codes from _cat/shards.
    unassigned = get_unassigned_shards()
    if not unassigned:
        ai_text = ai_explain(UNCLEAR_ALLOCATION_SYSTEM_PROMPT, json.dumps(health or {})[:4000])
        response["display"] += (
            f"\n\n[WARNING] No unassigned shards and no known blocks/limits found, but cluster "
            f"status is not GREEN.\n\nAI analysis:\n{ai_text}"
        )
        response["done"] = True
        return response

    context["unassigned_indices"] = sorted({s["index"] for s in unassigned})
    sample = "\n".join(f"  - {s['index']} shard {s['shard']} ({s['prirep']}) - {s['reason']}" for s in unassigned[:5])
    response["display"] += f"\n\n[WARNING] {len(unassigned)} unassigned shard(s) found, e.g.:\n{sample}"

    first = unassigned[0]
    explain = explain_allocation(first["index"], first["shard"], primary=(first["prirep"] == "p"))
    allocation_explanation = explain.get("allocate_explanation") or explain.get("error") or "(no explanation returned)"
    response["display"] += (
        f"\n\nAllocation explanation for {first['index']} shard {first['shard']}:\n  {allocation_explanation}"
    )

    # Single-node cluster with an unassigned REPLICA - there's nowhere to
    # place a second copy, so the fix is to drop replicas to 0, not to wait
    # or reindex.
    is_replica_shard = first["prirep"] == "r"
    if node_count <= 1 and is_replica_shard:
        replica_unassigned = sum(1 for s in unassigned if s["prirep"] == "r")
        recommended = recommend_replica_count(node_count)
        context["recommended_replicas"] = recommended
        response["display"] += (
            f"\n\n[ROOT CAUSE FOUND] Single-node cluster with unassigned replica shard(s)\n\n"
            f"This is a single-node deployment, so OpenSearch has nowhere to place a replica "
            f"copy - {replica_unassigned} of the unassigned shard(s) are replicas for this reason.\n\n"
            f"Recommended fix: set number_of_replicas={recommended} on the affected index pattern(s)."
        )
        response["ask"] = ["Auto", "Manual"]
        context["stage"] = "fix_replicas"
        return response

    # The explain output itself points at disk space (may catch cases the
    # local log scan in step 3 missed, e.g. the watermark tripped on a
    # different node than the one this tool runs on).
    if "disk" in allocation_explanation.lower():
        return _stop(
            response, "Disk threshold blocking allocation",
            f"The allocation explain output points to disk space as the blocker:\n  {allocation_explanation}\n\n"
            f"Current disk usage:\n{disk_output}",
            "Free up disk space (or delete/reindex old indices) so OpenSearch drops back below "
            "the high/flood watermark, then retry allocation with _cluster/reroute?retry_failed=true.",
        )

    # No known scripted cause matched - use the AI on the actual explain
    # data (not a generic prompt), then offer reindexing as a general
    # recovery step for shards that are stuck rather than just misplaced.
    ai_text = ai_explain(UNCLEAR_ALLOCATION_SYSTEM_PROMPT, json.dumps(explain)[:4000])
    response["display"] += f"\n\nAI analysis of the allocation explanation:\n{ai_text}"
    return _offer_reindex(response, context)


def _offer_clear_write_blocks(response, context, blocks):
    listing = "\n".join(f"  - {name} = {value}" for name, value in blocks.items())
    response["display"] += (
        f"\n\n[ROOT CAUSE FOUND] Cluster-wide write/index-creation block(s)\n\n{listing}\n\n"
        "These silently prevent shards/indices from being allocated or written to, even while "
        "the rest of the cluster looks healthy.\n\n"
        "Would you like us to clear these, or will you clear them yourself?"
    )
    response["ask"] = ["Auto", "Manual"]
    context["stage"] = "fix_write_blocks"
    context["write_blocks"] = list(blocks.keys())
    return response


def _manual_clear_blocks_instructions(block_names):
    lines = ",\n".join(f'        "{name}": null' for name in block_names)
    return (
        "Run this against the indexer to clear the block(s):\n\n"
        f"    curl -XPUT -k -u admin:<password> \"{INDEXER_URL}/_cluster/settings\" "
        "-H 'Content-Type: application/json' -d'\n"
        "    {\n"
        "      \"persistent\": {\n"
        f"{lines}\n"
        "      },\n"
        "      \"transient\": {\n"
        f"{lines}\n"
        "      }\n"
        "    }'\n\n"
        "Once you've run it, let us know."
    )


def _manual_replica_instructions(indices, recommended):
    lines = "\n".join(
        f"    curl -k -u admin:<password> -XPUT \"{INDEXER_URL}/{index_name}/_settings\" "
        "-H 'Content-Type: application/json' -d"
        f"'{{\"index\":{{\"number_of_replicas\":{recommended}}}}}'"
        for index_name in indices
    ) or "  (none)"
    return f"Run the following against the indexer:\n\n{lines}"


def _offer_reindex(response, context):
    indices = context.get("unassigned_indices", [])
    listing = "\n".join(f"  - {i}" for i in indices) or "  (none)"
    response["display"] += (
        "\n\nIndices that were already stuck unassigned may still need to be reindexed to fully "
        f"recover:\n{listing}\n\n"
        "Reindexing keeps the data (backup, delete original, restore from backup, delete backup). "
        "Would you like us to reindex these now?"
    )
    response["ask"] = ["Auto (reindex, keeps data)", "Manual", "Skip"]
    context["stage"] = "reindex_method"
    return response


def _manual_reindex_instructions(indices):
    listing = "\n".join(f"  - {i}" for i in indices) or "  (none)"
    return (
        "Reindex the affected indices one at a time (not all at once). Replace <affected_index> "
        "with each index name below:\n\n"
        f"Affected indices:\n{listing}\n\n"
        "1. Back it up:\n\n"
        "    POST _reindex\n"
        "    {\n"
        "      \"source\": { \"index\": \"<affected_index>\" },\n"
        "      \"dest\": { \"index\": \"<affected_index>-backup\" }\n"
        "    }\n\n"
        "2. Delete the original index:\n\n"
        "    DELETE /<affected_index>\n\n"
        "3. Reindex from the backup:\n\n"
        "    POST _reindex\n"
        "    {\n"
        "      \"source\": { \"index\": \"<affected_index>-backup\" },\n"
        "      \"dest\": { \"index\": \"<affected_index>\" }\n"
        "    }\n\n"
        "4. Delete the backup index:\n\n"
        "    DELETE /<affected_index>-backup\n\n"
        "Once you've run it, let us know."
    )


def _auto_reindex(response, context):
    indices = context.get("unassigned_indices", [])
    results = []
    for index_name in indices:
        steps = reindex_for_mapping_conflict(index_name)
        results.append((index_name, steps))

    ok_count = sum(1 for _, steps in results if not steps.get("aborted_after"))
    lines = []
    for name, steps in results[:10]:
        aborted_after = steps.get("aborted_after")
        if not aborted_after:
            lines.append(f"  - {name}: OK")
        else:
            detail = (steps.get(aborted_after) or "(no response)")[:200]
            lines.append(f"  - {name}: stopped after '{aborted_after}' - nothing irreversible happened past that point. {detail}")
    more = f"\n  ... and {len(results) - 10} more" if len(results) > 10 else ""
    response["display"] += (
        f"\n\nReindexed {ok_count}/{len(results)} index(es) successfully, one at a time:\n"
        + "\n".join(lines) + more
    )
    return _verify_after_reindex(response, context)


def _verify_after_reindex(response, context):
    sep = "\n\n" if response["display"] else ""
    unassigned = get_unassigned_shards()
    if unassigned:
        response["display"] += f"{sep}[WARNING] {len(unassigned)} shard(s) are still unassigned after reindexing."
    else:
        response["display"] += f"{sep}[OK] No unassigned shards remain."
    response["done"] = True
    return response
