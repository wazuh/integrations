"""
Use case: 'Alerts Not Showing on Dashboard'.

Walks the full pipeline end to end and stops at the first failing part:
    Wazuh Agent -> Wazuh Manager -> alerts.json -> Filebeat -> Wazuh Indexer -> Dashboard

Single, self-contained troubleshooting script - built from small,
single-purpose functions in utils/, sequencing logic lives here since
this use case isn't shared with any other use case.

Interaction pattern (per product spec):
  - Every step explains WHY it's checking something before asking anything.
  - Permission is asked for HOW TO CHECK itself (auto vs manual), not just
    for fixes - "auto" means we run the checks/commands ourselves and
    self-heal if something's off; "manual" means we hand the user the
    exact commands/reference text to run themselves and wait for them to
    report back.
  - `ask` is ALWAYS a list of short, standalone options - never a single
    string with multiple comma/parenthetical alternatives jammed together
    (e.g. never "(ID/name, 'auto', or 'skip')"). Jamming options together
    like that is what caused the UI to mis-split/truncate the question
    into a garbled follow-up that then got echoed back as a literal,
    unmatchable "agent name" in an earlier version of this script.
"""

import random
import time

from utils.service_utils import get_service_status, restart_service_and_wait
from utils.agent_utils import list_active_agents, restart_agent
from utils.manager_config_utils import (
    get_log_alert_level, is_log_alert_level_ok, set_log_alert_level,
    get_jsonout_output_enabled, enable_jsonout_output,
)
from utils.alerts_log_utils import alerts_json_mentions
from utils.manager_log_utils import get_manager_log_errors, get_manager_disk_usage
from utils.cluster_utils import get_cluster_status, get_cluster_health, get_write_blocks, clear_write_blocks
from utils.shard_utils import get_node_count, get_unassigned_shards, explain_allocation
from utils.replica_utils import recommend_replica_count, set_replica_count
from utils.index_utils import index_has_todays_date, check_most_recent_index, check_index_name_freshness
from utils.reindex_utils import reindex_for_mapping_conflict
from utils.api_utils import indexer_api_delete
from utils.ai_utils import ai_explain
from utils.log_handler import LogHandler
from utils.log_analyzer import LogAnalyzer
from utils.fix_engine import FixEngine
from config import INDEXER_URL
from flows.filebeat_flow import (
    filebeat_flow, STAGES as FILEBEAT_STAGES, STEP4_ENTRY_STAGE,
    ENTRY_STAGE as FILEBEAT_ENTRY_STAGE, WHY_TEXT as FILEBEAT_WHY_TEXT,
)

MANAGER_LOG_SYSTEM_PROMPT = (
    "You are a Wazuh Manager troubleshooting expert. You'll be given recent "
    "ossec.log error/warning lines. In 3-4 short sentences: state the most "
    "likely root cause and the single most useful next command or config fix. "
    "Be specific to what's actually in the log - don't give generic advice."
)

UNCLEAR_CLUSTER_STATUS_SYSTEM_PROMPT = (
    "You are a Wazuh Indexer (OpenSearch) troubleshooting expert. You'll be given the raw "
    "_cluster/health response for a cluster whose status is yellow or red even though there "
    "are no unassigned shards and no known write blocks. In 3-4 short sentences: state the "
    "most likely explanation and the single most useful next command to investigate further. "
    "Be specific to what's actually in the data - don't give generic advice."
)

STEP1_MANUAL_TEXT = (
    "Please check whether the manager is active and paste the output of:\n\n"
    "    systemctl status wazuh-manager\n\n"
    "Next, check whether log_alert_level is configured correctly. On the "
    "Wazuh manager server, open:\n\n"
    "    /var/ossec/etc/ossec.conf\n\n"
    "Ensure it contains:\n\n"
    "    <log_alert_level>3</log_alert_level>\n\n"
    "If log_alert_level is set higher than 15, alerts with rule level 15 "
    "or below will not be written by the manager and therefore will not "
    "appear on the dashboard. See the Wazuh docs for details:\n"
    "https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/alerts.html#log-alert-level\n\n"
    "Also verify that the following setting is enabled:\n\n"
    "    <jsonout_output>yes</jsonout_output>\n\n"
    "https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/global.html#jsonout-output\n\n"
    "If jsonout_output is disabled, the manager will not write alerts to "
    "alerts.json, so Filebeat will have no alerts to send to the indexer."
)

STEP4_MANUAL_TEXT = (
    "Please check whether the indexer is active and paste the output of:\n\n"
    "    systemctl status wazuh-indexer\n\n"
    "Next, check that its configured IP matches the original install config:\n\n"
    "    grep network.host /etc/wazuh-indexer/opensearch.yml\n\n"
    "Also check that its certificate paths point to files that actually exist:\n\n"
    "    grep -E 'pemkey_filepath|pemcert_filepath|pemtrustedcas_filepath' /etc/wazuh-indexer/opensearch.yml\n"
    "    ls /etc/wazuh-indexer/certs\n\n"
    "Every path from the first command should exist in the second command's listing. If the "
    "IP or a cert path is wrong, the indexer can be 'active' while still rejecting or "
    "misplacing data."
)

RECENT_INDEX_MANUAL_TEXT = (
    "Run this against the indexer:\n\n"
    f"    curl -XGET -k -u admin:<password> \"{INDEXER_URL}/_cat/indices/wazuh-alerts-*?v&s=index\"\n\n"
    "Find the most recent wazuh-alerts-* index in the list (the one with the highest date "
    "suffix), then type or paste that index name below so we can compare its date to today."
)

STEP5_MANUAL_TEXT = (
    "Run this against the indexer:\n\n"
    f"    curl -XGET -k -u admin:<password> \"{INDEXER_URL}/_cluster/health?pretty\"\n\n"
    "Check the \"status\" field - it should be \"green\". If it's \"yellow\" or \"red\", there "
    "are unassigned shards, usually because the number of replicas doesn't fit the number of "
    "nodes in this cluster.\n\n"
    "For the actual reason a specific shard won't allocate (not just the terse reason code), run:\n\n"
    f"    curl -XGET -k -u admin:<password> \"{INDEXER_URL}/_cluster/allocation/explain?pretty\"\n\n"
    "With no body, this explains an arbitrary unassigned shard the indexer picks itself."
)

STEP6_MANUAL_TEXT = (
    "Check whether there's a wazuh-alerts-* index for today by running this against the indexer:\n\n"
    f"    curl -XGET -k -u admin:<password> \"{INDEXER_URL}/_cat/indices/wazuh-alerts-*?v\"\n\n"
    "Look for an index whose date suffix matches today. If there isn't one, alerts have "
    "stopped being indexed recently even though the rest of the pipeline checks out."
)

MANUAL_DELETE_UNASSIGNED_TEXT = (
    "WARNING - this permanently deletes every index that currently has an unassigned "
    "shard. There is no backup step here - only run this if you don't need the data in "
    "those indices. If you do need it, go back and use the reindex option instead.\n\n"
    "    curl -XGET -k -u admin:<password> \"https://<indexer_ip>:9200/_cat/shards\" "
    "| grep UNASSIGNED | awk '{print $1}' | sort -u "
    "| xargs -I{} curl -XDELETE -k -u admin:<password> \"https://<indexer_ip>:9200/{}\"\n\n"
    "Once you've run it (or decided not to), let us know."
)

SAMPLE_AGENT_STARTED_ALERT = (
    '{"timestamp":"2026-07-05T10:44:10.016+0000","rule":{"level":3,'
    '"description":"Wazuh agent started.","id":"503",...},'
    '"agent":{"id":"001","name":"windows","ip":"192.168.56.1"},'
    '"manager":{"name":"Server1"},...,'
    '"full_log":"ossec: Agent started: \'windows->any\'.",...}'
)


def _stop(response, title, explanation, manual_fix):
    response["display"] = f"[ROOT CAUSE FOUND] {title}\n\n{explanation}\n\nManual fix:\n{manual_fix}"
    response["done"] = True
    return response


def no_alerts_are_showing_flow(user_choice=None, context=None):
    if context is None:
        context = {}

    response = {"display": "", "ask": [], "done": False, "context": context}
    choice = (user_choice or "").strip().lower()

    # =====================================================================
    # STEP 1 - Manager service + ossec.conf config
    # =====================================================================
    if not context:
        response["display"] = (
            "Let's troubleshoot 'Alerts Not Showing on Dashboard'.\n\n"
            "Step 1 - Check the Wazuh Manager service and its configuration:\n\n"
            "We first need to verify that the Wazuh Manager is running "
            "correctly and is configured to generate alerts. If "
            "log_alert_level is set too high, or jsonout_output is "
            "disabled, alerts get silently dropped before they're ever "
            "written to alerts.json - so this has to be ruled out first.\n\n"
            "How would you like us to check this?\n\n"
            "  Auto   - We perform all checks automatically.\n"
            "  Manual - We provide the commands, and you run them and "
            "share the output."
        )
        response["ask"] = ["Auto", "Manual"]
        context["stage"] = "step1_method"
        return response

    stage = context.get("stage")

    # =====================================================================
    # STEP 3 - Filebeat (fully owned by flows/filebeat_flow.py)
    # =====================================================================
    if stage in FILEBEAT_STAGES:
        result = filebeat_flow(user_choice=choice, context=context)
        if result.get("handoff"):
            next_result = no_alerts_are_showing_flow(context=result["context"])
            next_display = next_result["display"].lstrip("\n")
            next_result["display"] = (
                f"{result['display']}\n\n{next_display}" if result.get("display") else next_display
            )
            return next_result
        return result

    if stage == STEP4_ENTRY_STAGE:
        return _start_step4(response, context)

    if stage == "step4_method":
        if "manual" in choice:
            response["display"] = STEP4_MANUAL_TEXT
            response["ask"] = ["Correct", "Needs fixing"]
            context["stage"] = "step4_manual_result"
            return response

        # AUTO - run the real checks ourselves.
        return _check_indexer(response, context)

    if stage == "step4_manual_result":
        # Independently verify regardless of what the user reported, same as Step 1.
        return _check_indexer(response, context)

    if stage == "recent_index_method":
        if "manual" in choice:
            response["display"] = RECENT_INDEX_MANUAL_TEXT
            response["ask"] = []
            context["stage"] = "recent_index_manual_wait"
            return response

        # AUTO - look the most recent index up ourselves.
        return _check_recent_index(response, context)

    if stage == "recent_index_manual_wait":
        # Whatever the user typed/pasted is the index name - parse its date
        # suffix ourselves rather than trusting a self-report, same spirit as
        # the other steps' independent re-verification.
        result = check_index_name_freshness(user_choice)
        response["display"] = _format_recent_index_result(result)
        return _start_step5(response, context)

    if stage == "step5_method":
        if "manual" in choice:
            response["display"] = STEP5_MANUAL_TEXT
            response["ask"] = ["Correct", "Needs fixing"]
            context["stage"] = "step5_manual_result"
            return response

        # AUTO - run the real check ourselves.
        return _check_cluster_and_shards(response, context)

    if stage == "step5_manual_result":
        # Independently verify regardless of what the user reported, same as Step 1.
        return _check_cluster_and_shards(response, context)

    if stage == "step6_method":
        if "manual" in choice:
            response["display"] = STEP6_MANUAL_TEXT
            response["ask"] = ["Correct", "Needs fixing"]
            context["stage"] = "step6_manual_result"
            return response

        # AUTO - run the real check ourselves.
        return _check_indices(response, context)

    if stage == "step6_manual_result":
        # Independently verify regardless of what the user reported, same as Step 1.
        return _check_indices(response, context)

    # =====================================================================
    # Post-pipeline: everything checked out, but the user still has the
    # complaint - narrow down whether this is a broken pipeline (all
    # alerts missing, already covered above) or a mapping/rule issue
    # specific to one alert (a different root cause entirely).
    # =====================================================================
    if stage == "step6_scope_check":
        if "particular" in choice:
            response["display"] = (
                "On the Wazuh Manager, check whether that specific alert reached alerts.json:\n\n"
                "    grep -i '<rule description or a keyword from the alert>' /var/ossec/logs/alerts/alerts.json\n\n"
                "Does it appear there?"
            )
            response["ask"] = ["Yes, it's in alerts.json", "No, it's not there"]
            context["stage"] = "step6_particular_check"
            return response

        if "all of today" in choice:
            response["display"] = (
                "If every step in this pipeline checked out but ALL of today's alerts are "
                "still missing, that points to the dashboard side rather than the indexing "
                "pipeline itself: double-check the dashboard's index pattern (should match "
                "wazuh-alerts-*) and its time range filter (set to include today). If those "
                "look correct, re-check the cluster health and Filebeat logs from the earlier "
                "steps for anything that changed right before this started."
            )
            response["done"] = True
            return response

        response["display"] = "Good - the full pipeline checks out end to end."
        response["done"] = True
        return response

    if stage == "step6_particular_check":
        if "yes" in choice:
            index_name = check_most_recent_index()["index"] or "wazuh-alerts-*"
            response["display"] = (
                "That alert is reaching alerts.json but not showing on the dashboard - this "
                "points to a field-mapping conflict on today's index, not a pipeline failure. "
                "Would you like us to fix this by reindexing that index (same backup/restore "
                "procedure used for unassigned shards earlier), or would you rather do it "
                "yourself?"
            )
            response["ask"] = ["Auto", "Manual"]
            context["stage"] = "step6_mapping_fix"
            context["mapping_conflict_index"] = index_name
            return response

        response["display"] = (
            "That alert never reached alerts.json, so this isn't an indexing/dashboard "
            "problem - the cause is further upstream. Go back to Step 1 (log_alert_level / "
            "jsonout_output) and check whether a rule is filtering it out, or whether the "
            "source log is reaching the manager at all."
        )
        response["done"] = True
        return response

    if stage == "step6_mapping_fix":
        index_name = context.get("mapping_conflict_index", "wazuh-alerts-*")
        if "manual" in choice:
            response["display"] = _manual_reindex_single_index_instructions(index_name)
            response["ask"] = ["Done"]
            context["stage"] = "step6_mapping_fix_manual_wait"
            return response

        if "auto" in choice:
            steps = reindex_for_mapping_conflict(index_name)
            aborted_after = steps.get("aborted_after")
            if aborted_after:
                detail = (steps.get(aborted_after) or "(no response)")[:200]
                response["display"] = (
                    f"Stopped after '{aborted_after}' - nothing irreversible happened past "
                    f"that point. {detail}"
                )
            else:
                response["display"] = f"Reindexed {index_name} - the mapping conflict should be resolved now."
            response["done"] = True
            return response

        response["ask"] = ["Auto", "Manual"]
        return response

    if stage == "step6_mapping_fix_manual_wait":
        response["display"] = "Done - the mapping conflict should be resolved now."
        response["done"] = True
        return response

    if stage == "step1_method":
        if "manual" in choice:
            response["display"] = STEP1_MANUAL_TEXT
            response["ask"] = ["Correct", "Needs fixing"]
            context["stage"] = "step1_manual_result"
            return response

        # AUTO - run it ourselves, self-heal if needed, report and move on.
        return _auto_check_step1(response, context)

    if stage == "step1_manual_result":
        # Independently verify regardless of what the user reported, so we
        # can move on with confidence either way.
        if is_log_alert_level_ok() and get_jsonout_output_enabled() and get_service_status("wazuh-manager") == "active":
            response["display"] = "[OK] Confirmed - the manager is active and configured correctly."
            return _start_step2(response, context)

        response["display"] = (
            "We're still seeing an issue with the manager service or its "
            "configuration. Would you like us to fix it automatically, or "
            "will you fix it yourself and let us know when done?"
        )
        response["ask"] = ["Auto", "I'll fix it myself"]
        context["stage"] = "step1_fix_choice"
        return response

    if stage == "step1_fix_choice":
        if "auto" in choice:
            return _auto_check_step1(response, context, already_explained=True)

        response["display"] = STEP1_MANUAL_TEXT + "\n\nOnce you've made the changes, let us know."
        response["ask"] = ["Done"]
        context["stage"] = "step1_manual_result"
        return response

    # =====================================================================
    # STEP 2 - Live agent-restart pipeline test
    # =====================================================================
    if stage == "step2_method":
        active = list_active_agents()
        context["active_agents"] = active

        if not active:
            return _stop(
                response, "No active agents",
                "There are no active agents connected to this manager (agent 000, the "
                "manager's own local agent, doesn't count), so there's nothing to "
                "generate an event for this test.",
                "Check agent connectivity/network from at least one endpoint, then re-run this workflow.",
            )

        if "manual" in choice:
            listing = "\n".join(f"  - {a['id']}: {a['name']}" for a in active[:10])
            response["display"] = (
                f"Active agents (excluding 000, the manager itself):\n{listing}\n\n"
                "1. Pick one agent ID from the list above.\n"
                "2. Restart it from the manager:\n"
                "     /var/ossec/bin/agent_control -R -u <agent_id>\n\n"
                "3. Wait a few seconds, then check alerts.json for a matching "
                "'Wazuh agent started' event, e.g.:\n"
                f"     {SAMPLE_AGENT_STARTED_ALERT}\n\n"
                "Did you see a matching alert in alerts.json?"
            )
            response["ask"] = ["Yes, I see it", "No, nothing there"]
            context["stage"] = "step2_manual_result"
            return response

        # AUTO - explain, pick a random active agent, restart it, and verify ourselves.
        target = random.choice(active)
        context["target_agent"] = target
        response["display"] = (
            f"We're restarting agent '{target['name']}' (ID {target['id']}) to generate "
            "a known alert. If this alert appears in alerts.json, it confirms that the "
            "Wazuh Manager is correctly receiving events, processing them, and generating "
            "alerts."
        )
        out = restart_agent(target["id"])
        time.sleep(5)
        found = alerts_json_mentions(target["id"]) or alerts_json_mentions(target["name"])

        response["display"] += f"\n\nRan: agent_control -R -u {target['id']}\n{out}\n"
        if found:
            response["display"] += (
                f"[OK] Found a matching entry in alerts.json for agent '{target['name']}' - "
                "the manager is receiving and logging agent events."
            )
            return _start_step3(response, context)

        return _step2_no_alert_found(response, context)

    if stage == "step2_manual_result":
        if "yes" in choice:
            response["display"] = "[OK] Good - that confirms the manager is receiving agent events."
            return _start_step3(response, context)
        return _step2_no_alert_found(response, context)

    # =====================================================================
    # STEP 4 fix gate - Indexer down
    # =====================================================================
    if stage == "fix_indexer_start":
        if "auto" in choice:
            status = restart_service_and_wait("wazuh-indexer")
        elif choice == "done":
            status = get_service_status("wazuh-indexer")
        elif "manual" in choice:
            response["display"] = "Run: systemctl restart wazuh-indexer"
            response["ask"] = ["Done"]
            context["stage"] = "fix_indexer_start"
            return response
        else:
            response["ask"] = ["Auto", "Manual"]
            return response

        if status == "active":
            response["display"] = "[OK] wazuh-indexer is now active."
            return _check_indexer_ip_and_certs(response, context)

        response["display"] = f"wazuh-indexer still shows {status.upper()}."
        return _diagnose_indexer_logs(response, context)

    # =====================================================================
    # STEP 5 fix gate - cluster-wide write/index-creation blocks
    # =====================================================================
    if stage == "fix_write_blocks":
        block_names = context.get("write_blocks", [])
        if "auto" in choice:
            raw = clear_write_blocks(block_names)
            response["display"] = f"Cleared {len(block_names)} block(s):\n{', '.join(block_names)}\n{raw}"
            return _check_cluster_and_shards(response, context)

        if "manual" in choice:
            response["display"] = _manual_clear_blocks_instructions(block_names)
            response["ask"] = ["Done"]
            context["stage"] = "fix_write_blocks_manual_wait"
            return response

        response["ask"] = ["Auto", "Manual"]
        return response

    if stage == "fix_write_blocks_manual_wait":
        return _check_cluster_and_shards(response, context)

    # =====================================================================
    # STEP 5 fix gate - unassigned shards / replicas
    # =====================================================================
    if stage == "fix_replicas":
        if "auto" in choice:
            raw = set_replica_count("wazuh-alerts-*", context["recommended_replicas"])
            response["display"] = f"Set number_of_replicas={context['recommended_replicas']} on wazuh-alerts-*.\n{raw}"
        elif "manual" in choice:
            response["display"] = (
                "Run against the indexer:\n\n"
                "    curl -k -u \"<INDEXER_USERNAME>:<INDEXER_PASSWORD>\" -XPUT "
                "\"https://<INDEXER_IP_ADDRESS>:9200/wazuh-alerts-*\" -H 'Content-Type: application/json' -d'\n"
                "    {\n"
                "      \"settings\": {\n"
                f"        \"index\": {{ \"number_of_replicas\": {context['recommended_replicas']} }}\n"
                "      }\n"
                "    }'"
            )
        else:
            response["ask"] = ["Auto", "Manual"]
            return response
        return _offer_reindex(response, context)

    if stage == "reindex_method":
        indices = context.get("unassigned_indices", [])
        if "skip" in choice:
            response["display"] = "Skipping the reindex."
            return _start_step6(response, context)

        if "delete" in choice:
            return _confirm_delete_unassigned(response, context)

        if "manual" in choice:
            response["display"] = _manual_reindex_instructions(indices)
            response["ask"] = ["Done", "Skip"]
            context["stage"] = "reindex_manual_wait"
            return response

        if "auto" in choice:
            return _auto_reindex(response, context)

        response["ask"] = ["Auto (reindex, keeps data)", "Manual", "Delete instead", "Skip"]
        return response

    if stage == "confirm_delete_unassigned":
        if "back" in choice or "no" in choice:
            return _offer_reindex(response, context)

        if "show" in choice or "command" in choice:
            response["display"] = MANUAL_DELETE_UNASSIGNED_TEXT
            response["ask"] = ["Done", "Skip"]
            context["stage"] = "delete_unassigned_manual_wait"
            return response

        if "yes" in choice:
            return _delete_unassigned_indices(response, context)

        response["ask"] = ["Yes, delete via Auto", "Yes, show me the command", "No, go back"]
        return response

    if stage == "delete_unassigned_manual_wait":
        if "skip" in choice:
            response["display"] = "Skipping the verification."
            return _start_step6(response, context)
        return _verify_and_start_step6(response, context)

    if stage == "reindex_manual_wait":
        if "skip" in choice:
            response["display"] = "Skipping the verification."
            return _start_step6(response, context)
        return _verify_and_start_step6(response, context)

    response["display"] = "Invalid stage."
    response["done"] = True
    return response


# ---------------------------------------------------------------------------
# Step 1 helpers
# ---------------------------------------------------------------------------
def _auto_check_step1(response, context, already_explained=False):
    if not already_explained:
        response["display"] = (
            "Automatically checking:\n"
            "  - whether the wazuh-manager service is active\n"
            "  - whether log_alert_level is configured correctly\n"
            "  - whether jsonout_output is enabled"
        )

    status = get_service_status("wazuh-manager")
    if status != "active":
        status = restart_service_and_wait("wazuh-manager")
        if status != "active":
            return _stop(
                response, "Wazuh Manager failed to start",
                "wazuh-manager did not come back up after a restart.",
                "Check `journalctl -u wazuh-manager` and `/var/ossec/logs/ossec.log` for startup errors.",
            )

    fixed_something = False
    if not is_log_alert_level_ok():
        set_log_alert_level(3)
        fixed_something = True
    if not get_jsonout_output_enabled():
        enable_jsonout_output()
        fixed_something = True

    if fixed_something:
        restart_service_and_wait("wazuh-manager")

    if is_log_alert_level_ok() and get_jsonout_output_enabled():
        if fixed_something:
            response["display"] += "\n[OK] Found and corrected a config issue, then restarted wazuh-manager."
        else:
            response["display"] += "\n[OK] The manager is active and already configured correctly."
        return _start_step2(response, context)

    errors = get_manager_log_errors()
    explanation = ai_explain(MANAGER_LOG_SYSTEM_PROMPT, errors) if errors.strip() else \
        "No error/warning lines found in ossec.log to analyze further."
    return _stop(
        response, "Manager configuration still not correct after auto-fix",
        f"Something beyond the two known settings appears to be wrong.\n\n"
        f"AI analysis of recent ossec.log errors:\n{explanation}",
        "Review ossec.conf and ossec.log manually using the analysis above as a starting point.",
    )


def _start_step2(response, context):
    response["display"] += (
        "\n\nStep 2 - Verify that the Manager is Receiving Alerts:\n\n"
        "The easiest way to confirm this is to restart an active agent and verify "
        "that the manager writes a Rule 503 - Wazuh agent started event into "
        "alerts.json.\n\n"
        "How would you like to do this?"
    )
    response["ask"] = ["Auto", "Manual"]
    context["stage"] = "step2_method"
    return response


def _step2_no_alert_found(response, context):
    disk = get_manager_disk_usage()
    errors = get_manager_log_errors()
    response["display"] += (
        "\n[WARNING] No matching entry found in alerts.json after restarting the agent.\n\n"
        f"Manager disk usage:\n{disk}\n\nRecent ossec.log errors/warnings:\n"
        f"{errors if errors else '(none found)'}"
    )
    response["done"] = True
    return response


# ---------------------------------------------------------------------------
# Steps 4-6 (unchanged logic from before, only the ask-list formatting differs)
# ---------------------------------------------------------------------------
def _start_step3(response, context):
    response["display"] += (
        "\n\nStep 3 - Check Filebeat:\n\n"
        f"{FILEBEAT_WHY_TEXT}\n\n"
        "How would you like to check this?\n\n"
        "  Auto   - We perform all checks automatically.\n"
        "  Manual - We provide the commands, and you run them and share the output."
    )
    response["ask"] = ["Auto", "Manual"]
    context["stage"] = FILEBEAT_ENTRY_STAGE
    return response


def _start_step4(response, context):
    response["display"] += (
        "\n\nStep 4 - Check the Wazuh Indexer:\n\n"
        "Filebeat can only ship alerts as far as the Wazuh Indexer is actually running "
        "and correctly configured to accept them. We need to confirm the service is "
        "active, and that its IP and certificate configuration are correct - the same "
        "checks used for the 'Wazuh dashboard is not ready yet' troubleshooting flow.\n\n"
        "How would you like to check this?\n\n"
        "  Auto   - We perform all checks automatically.\n"
        "  Manual - We provide the commands, and you run them and share the output."
    )
    response["ask"] = ["Auto", "Manual"]
    context["stage"] = "step4_method"
    return response


def _check_indexer(response, context):
    response["display"] += ("\n" if response["display"] else "") + "Checking Wazuh Indexer..."
    status = get_service_status("wazuh-indexer")
    if status != "active":
        response["display"] += "\n[WARNING] wazuh-indexer is not active."
        response["ask"] = ["Auto", "Manual"]
        context["stage"] = "fix_indexer_start"
        return response
    response["display"] += "\n[OK] wazuh-indexer is active."
    return _check_indexer_ip_and_certs(response, context)


def _check_indexer_ip_and_certs(response, context):
    ip_data = FixEngine.check_indexer_ip()
    fixed_ip = False
    if not ip_data["match"] and ip_data.get("c_ip"):
        FixEngine.fix_indexer_ip(ip_data["c_ip"])
        fixed_ip = True

    cert_data = FixEngine.check_indexer_cert_paths()
    fixed_cert = False
    cert_unfixable = False
    if cert_data["missing"]:
        result = FixEngine.fix_indexer_cert_paths()
        if result.get("success"):
            fixed_cert = True
        else:
            cert_unfixable = True

    if fixed_ip or fixed_cert:
        response["display"] += "\n[OK] Found and corrected indexer IP/certificate configuration issues."
    else:
        response["display"] += "\n[OK] Indexer IP and certificate configuration look correct."

    if cert_unfixable:
        response["display"] += (
            "\n[WARNING] Could not auto-identify the correct certificate files. Checking "
            "the indexer logs to help narrow this down..."
        )
        return _diagnose_indexer_logs(response, context)

    return _start_recent_index_check(response, context)


def _start_recent_index_check(response, context):
    response["display"] += (
        "\n\nCheck for a Recently Created Index:\n\n"
        "Before diving into cluster health, it's worth checking whether the indexer has "
        "actually created a new wazuh-alerts-* index recently. If the newest one is old, "
        "that's an early sign writes have stalled somewhere upstream, even though the "
        "service itself is up.\n\n"
        "How would you like to check this?\n\n"
        "  Auto   - We perform all checks automatically.\n"
        "  Manual - We provide the commands, and you run them and share the output."
    )
    response["ask"] = ["Auto", "Manual"]
    context["stage"] = "recent_index_method"
    return response


def _check_recent_index(response, context):
    text = _format_recent_index_result(check_most_recent_index())
    response["display"] += text if response["display"] else text.lstrip("\n")
    return _start_step5(response, context)


def _format_recent_index_result(result):
    if not result["index"]:
        return (
            "\n[WARNING] Could not find any wazuh-alerts-* index with a parseable date - "
            "moving on to check cluster health, which may explain why."
        )
    if result["is_today"]:
        return f"\n[OK] Most recent index is {result['index']} (today)."
    return (
        f"\n[WARNING] Most recent index is {result['index']} - {result['days_old']} day(s) old, "
        "not today. New alerts may have stopped being indexed recently. Continuing on to check "
        "cluster health, which may explain why."
    )


def _start_step5(response, context):
    response["display"] += (
        "\n\nStep 5 - Check Cluster Health:\n\n"
        "Now that the indexer is confirmed running and correctly configured, we check "
        "cluster health and shard allocation - a red/yellow cluster or unassigned shards "
        "will keep alerts from being indexed even though every earlier step passed.\n\n"
        "How would you like to check this?\n\n"
        "  Auto   - We perform all checks automatically.\n"
        "  Manual - We provide the commands, and you run them and share the output."
    )
    response["ask"] = ["Auto", "Manual"]
    context["stage"] = "step5_method"
    return response


def _offer_clear_write_blocks(response, context, blocks):
    listing = "\n".join(f"  - {name} = {value}" for name, value in blocks.items())
    response["display"] += (
        f"\n[ISSUE] Found cluster-wide write/index-creation block(s):\n{listing}\n\n"
        "These silently prevent new indices (including today's wazuh-alerts-*) from being "
        "created or written to, even while every other check looks healthy - this is exactly "
        "what caused an earlier data-loss incident during reindexing.\n\n"
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


def _diagnose_indexer_logs(response, context):
    logs = LogHandler.get_indexer_logs(2)
    clean = LogHandler.clean_logs(logs)
    issues = LogAnalyzer.get_issues(logs)

    response["display"] += f"\n\nRecent indexer logs:\n{clean}"
    if issues:
        response["display"] += "\n\nKnown issues detected:\n" + "\n".join(f"- {i}" for i in issues)
    else:
        response["display"] += "\n\nNo known issue pattern matched - manual review of the logs above is needed."

    response["done"] = True
    return response


def _check_cluster_and_shards(response, context):
    response["display"] += ("\n" if response["display"] else "") + "Checking cluster health and shards..."

    # Known cluster-wide write/index-creation blocks (e.g. a stale
    # cluster.blocks.create_index) are checked BEFORE cluster status/shards,
    # since a block can silently sit alongside an otherwise-green cluster -
    # this is exactly what caused the reindex data-loss incident, and a
    # plain _cluster/health check alone would never have surfaced it.
    block_result = get_write_blocks()
    if block_result.get("error"):
        response["display"] += f"\n[WARNING] Could not check cluster write blocks: {str(block_result['error'])[:200]}"
    elif block_result.get("blocks"):
        return _offer_clear_write_blocks(response, context, block_result["blocks"])
    else:
        response["display"] += "\n[OK] No cluster-wide write/index-creation blocks found."

    status = get_cluster_status()

    if status is None:
        return _stop(
            response, "Wazuh Indexer API is unreachable",
            "Could not query /_cluster/health.",
            "Verify INDEXER_URL/credentials and that port 9200 is reachable.",
        )

    response["display"] += f"\nCluster status: {status.upper()}"

    if status == "green":
        response["display"] += "\n[OK] Cluster is green."
        return _start_step6(response, context)

    unassigned = get_unassigned_shards()
    if not unassigned:
        # No known scripted cause (no write blocks, no unassigned shards) but
        # the cluster still isn't green - this is the one case we hand to the
        # AI rather than guess at more hardcoded rules, same fallback pattern
        # used for Filebeat's "unknown" failure category.
        _, raw_health = get_cluster_health()
        explanation = ai_explain(UNCLEAR_CLUSTER_STATUS_SYSTEM_PROMPT, raw_health or "(no response)")
        response["display"] += (
            f"\n[WARNING] No unassigned shards and no known write blocks, but status is still "
            f"{status.upper()}.\n\nAI analysis:\n{explanation}"
        )
        return _start_step6(response, context)

    node_count, _ = get_node_count()
    recommended = recommend_replica_count(node_count)
    context["recommended_replicas"] = recommended
    context["unassigned_indices"] = sorted({s["index"] for s in unassigned})

    sample = "\n".join(f"  - {s['index']} shard {s['shard']} ({s['reason']})" for s in unassigned[:5])

    # GET _cluster/allocation/explain on one representative shard - the reason
    # code from _cat/shards (e.g. CLUSTER_RECOVERED) is terse; this gives the
    # actual human-readable explanation of why the indexer won't allocate it.
    first = unassigned[0]
    explain = explain_allocation(first["index"], first["shard"], primary=(first.get("prirep") == "p"))
    allocation_explanation = explain.get("allocate_explanation") or explain.get("error") or "(no explanation returned)"

    response["display"] += (
        f"\n[WARNING] {len(unassigned)} unassigned shard(s) found, e.g.:\n{sample}\n\n"
        f"Allocation explanation for {first['index']} shard {first['shard']}:\n  {allocation_explanation}\n\n"
        f"With {node_count} node(s), recommended number_of_replicas is {recommended}."
    )
    response["ask"] = ["Auto", "Manual"]
    context["stage"] = "fix_replicas"
    return response


def _offer_reindex(response, context):
    indices = context.get("unassigned_indices", [])
    listing = "\n".join(f"  - {i}" for i in indices) or "  (none)"
    response["display"] += (
        "\n\nSetting the replica count only fixes shard placement going forward - the "
        "indices that were already stuck unassigned may still need to be reindexed to "
        "fully recover. Affected indices:\n"
        f"{listing}\n\n"
        "Reindexing keeps the data - back it up, delete the original, restore from the "
        "backup, then delete the backup, one index at a time. Deleting the affected "
        "indices outright is faster but permanently discards their data - only pick "
        "that if you don't need it.\n\n"
        "How would you like to do this?"
    )
    response["ask"] = ["Auto (reindex, keeps data)", "Manual", "Delete instead", "Skip"]
    context["stage"] = "reindex_method"
    return response


def _confirm_delete_unassigned(response, context):
    indices = context.get("unassigned_indices", [])
    listing = "\n".join(f"  - {i}" for i in indices) or "  (none)"
    response["display"] = (
        "WARNING - this permanently deletes each of the following indices in full. "
        "There is no backup step - any data in them will be gone for good:\n\n"
        f"{listing}\n\n"
        "Are you sure you want to delete these indices?"
    )
    response["ask"] = ["Yes, delete via Auto", "Yes, show me the command", "No, go back"]
    context["stage"] = "confirm_delete_unassigned"
    return response


def _delete_unassigned_indices(response, context):
    indices = context.get("unassigned_indices", [])
    results = [(name, indexer_api_delete(f"/{name}")) for name in indices]
    lines = "\n".join(f"  - {name}: {raw}" for name, raw in results[:10])
    more = f"\n  ... and {len(results) - 10} more" if len(results) > 10 else ""
    response["display"] = f"Deleted {len(results)} index(es):\n{lines}{more}"
    return _verify_and_start_step6(response, context)


def _manual_reindex_instructions(indices):
    listing = "\n".join(f"  - {i}" for i in indices) or "  (none)"
    return (
        "Reindex the affected indices one at a time (not all at once). Take a backup of "
        "the index, then run the following, replacing <affected_index> with the index "
        "name you want to reindex:\n\n"
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
        "Repeat for any other indices showing field conflicts or the same issue. See the "
        "Wazuh reindexing documentation for more details."
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
    return _verify_and_start_step6(response, context)


def _verify_and_start_step6(response, context):
    sep = "\n\n" if response["display"] else ""
    unassigned = get_unassigned_shards()
    if unassigned:
        response["display"] += f"{sep}[WARNING] {len(unassigned)} shard(s) are still unassigned after reindexing."
    else:
        response["display"] += f"{sep}[OK] No unassigned shards remain."
    return _start_step6(response, context)


def _start_step6(response, context):
    response["display"] += (
        "\n\nStep 6 - Check Today's wazuh-alerts-* Index:\n\n"
        "This is the last link in the chain - even with a healthy manager, Filebeat, "
        "indexer, and cluster, alerts still won't show up if today's wazuh-alerts-* "
        "index was never created or has stopped receiving new documents.\n\n"
        "How would you like to check this?\n\n"
        "  Auto   - We perform all checks automatically.\n"
        "  Manual - We provide the commands, and you run them and share the output."
    )
    response["ask"] = ["Auto", "Manual"]
    context["stage"] = "step6_method"
    return response


def _check_indices(response, context):
    response["display"] += ("\n" if response["display"] else "") + "Checking today's wazuh-alerts-* index..."
    if not index_has_todays_date():
        response["display"] += "\n[WARNING] No wazuh-alerts-* index for today was found - the pipeline may have stalled recently."
        response["done"] = True
        return response

    response["display"] += (
        "\n[OK] Today's wazuh-alerts-* index exists, and everything earlier in the pipeline "
        "checked out.\n\n"
        "If you're still not seeing alerts you expect: are you missing one particular alert "
        "(or alert type), or are ALL of today's alerts missing from the dashboard?"
    )
    response["ask"] = ["One particular alert", "All of today's alerts", "Nothing missing - all good"]
    context["stage"] = "step6_scope_check"
    return response


def _manual_reindex_single_index_instructions(index_name):
    return (
        f"Take a backup of {index_name}, then reindex it to clear the mapping conflict:\n\n"
        "1. Back it up:\n\n"
        "    POST _reindex\n"
        "    {\n"
        f"      \"source\": {{ \"index\": \"{index_name}\" }},\n"
        f"      \"dest\": {{ \"index\": \"{index_name}-backup\" }}\n"
        "    }\n\n"
        "2. Delete the original index:\n\n"
        f"    DELETE /{index_name}\n\n"
        "3. Reindex from the backup:\n\n"
        "    POST _reindex\n"
        "    {\n"
        f"      \"source\": {{ \"index\": \"{index_name}-backup\" }},\n"
        f"      \"dest\": {{ \"index\": \"{index_name}\" }}\n"
        "    }\n\n"
        "4. Delete the backup index:\n\n"
        f"    DELETE /{index_name}-backup\n\n"
        "Once you've run it, let us know."
    )
