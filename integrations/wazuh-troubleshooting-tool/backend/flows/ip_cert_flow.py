"""
Indexer IP / certificate paths / heap memory flow.

Order: IP address -> certificate paths -> heap memory -> (dashboard checks
if still ongoing after the last step).

This module only DEFINES what's specific to these checks - what to check,
how to fix them, what the manual instructions are. All flow-control (asking
permission, handling yes/manual, fixed/ongoing, moving between steps,
handoff) lives in the generic, reusable engine at utils/step_flow.py.

Per step (IP -> cert -> heap), the interaction pattern is always:

  1. ASK:    "Should I check the <thing>? (yes / manual)"
       yes    -> run the real check and report the real result.
       manual -> give exact commands to check it, then ask "good to go /
                 incorrect".

  2. If there's an issue:
       ASK: "Do you want me to fix this? (yes / manually)"
         yes      -> apply the fix, restart the indexer, ask "fixed/ongoing".
         manually -> give fix steps, wait for confirmation, THEN restart the
                     indexer ourselves, then ask "fixed/ongoing".

  3. "fixed"   -> stop.
     "ongoing" -> move to the next step. After the last step (heap), still
                  ongoing hands off to the dashboard IP/cert flow.
"""

import re
from utils.fix_engine import FixEngine
from utils.service_utils import restart_service_and_wait
from utils.step_flow import stage_names, start_flow, run_step_flow

PREFIX = "ip_cert"
ENTRY_STAGE = "ip_check"                 # legacy-compatible entry point
NEXT_STAGE_AFTER_ONGOING = "dash_ip_check"  # hands off to dashboard_ip_cert_flow


# ---------------------------------------------------------------------------
# STEP: IP address
# ---------------------------------------------------------------------------
def _check_ip(context):
    data = FixEngine.check_indexer_ip()
    context["c_ip"] = data["c_ip"]
    context["i_ip"] = data["i_ip"]
    details = (
        f"  config.yml IP:                {data['c_ip']}\n"
        f"  opensearch.yml network.host:  {data['i_ip']}"
    )
    return data["match"], details


def _manual_check_ip(context):
    return (
        "To check this yourself:\n\n"
        "1. Get the IP from the original install config:\n"
        "   tar -axf /home/vagrant/wazuh-install-files.tar wazuh-install-files/config.yml -O\n"
        "   (look under the 'indexer:' section for 'ip:')\n\n"
        "2. Get the IP the indexer is actually using:\n"
        "   grep network.host /etc/wazuh-indexer/opensearch.yml\n\n"
        "3. Compare the two — they should match."
    )


def _auto_fix_ip(context):
    c_ip = context.get("c_ip", "")
    status = FixEngine.fix_indexer_ip(c_ip)
    details = (
        f"Updated network.host to {c_ip} in opensearch.yml.\n"
        f"Restarted wazuh-indexer (status: {status.upper()})."
    )
    return status, details


def _manual_fix_ip(context):
    c_ip = context.get("c_ip", "<config.yml IP>")
    return (
        "Edit /etc/wazuh-indexer/opensearch.yml and set:\n\n"
        f"  network.host: {c_ip}\n\n"
        "Save the file."
    )


# ---------------------------------------------------------------------------
# STEP: certificate paths
# ---------------------------------------------------------------------------
def _check_cert(context):
    data = FixEngine.check_indexer_cert_paths()
    context["cert_missing"] = data["missing"]
    details = (
        "Configured cert paths (opensearch.yml):\n"
        f"{data['paths_raw']}\n\n"
        "Available cert files (/etc/wazuh-indexer/certs/):\n"
        f"{data['files_raw']}"
    )
    return (not data["missing"]), details


def _manual_check_cert(context):
    return (
        "To check this yourself:\n\n"
        "1. See the cert paths configured in opensearch.yml:\n"
        "   grep -E 'pemcert_filepath|pemkey_filepath|pemtrustedcas_filepath' "
        "/etc/wazuh-indexer/opensearch.yml\n\n"
        "2. See the cert files that actually exist:\n"
        "   ls /etc/wazuh-indexer/certs/\n\n"
        "3. Every path from step 1 should exist in step 2's listing."
    )


def _auto_fix_cert(context):
    result = FixEngine.fix_indexer_cert_paths()
    if result.get("success"):
        status = result["status"]
        details = (
            "Updated cert paths:\n"
            f"  cert: {result['cert']}\n  key: {result['key']}\n  CA: {result['ca']}\n"
            f"Restarted wazuh-indexer (status: {status.upper()})."
        )
    else:
        status = "unknown"
        details = "Could not auto-identify cert files. Please fix this one manually."
    return status, details


def _manual_fix_cert(context):
    return (
        "Update the cert paths in /etc/wazuh-indexer/opensearch.yml so each one "
        "points to a file that actually exists in /etc/wazuh-indexer/certs/."
    )


# ---------------------------------------------------------------------------
# STEP: heap memory
# ---------------------------------------------------------------------------
def _check_heap(context):
    data = FixEngine.check_jvm_heap()
    context["recommended_heap"] = data["recommended_heap"]
    details = (
        f"Current: {data['current']}\n"
        f"Total RAM: {data['total_gb']} GB\n"
        f"Recommended: -Xms{data['recommended_heap']}g / -Xmx{data['recommended_heap']}g"
    )
    m = re.search(r"-Xmx(\d+)g", data["current"] or "")
    current_gb = int(m.group(1)) if m else None
    ok = (current_gb == data["recommended_heap"])
    return ok, details


def _manual_check_heap(context):
    return (
        "To check this yourself:\n\n"
        "1. See the current heap settings:\n"
        "   grep -E '^-Xms|^-Xmx' /etc/wazuh-indexer/jvm.options\n\n"
        "2. See total RAM:\n"
        "   free -h\n\n"
        "3. Heap (-Xms/-Xmx) should be about 50% of total RAM, not more."
    )


def _auto_fix_heap(context):
    heap_gb = context.get("recommended_heap", 2)
    result = FixEngine.fix_jvm_heap(heap_gb)
    status = result["status"]
    details = (
        "Edited jvm.options.\n"
        f"Current heap settings:\n{result['updated']}\n"
        f"Restarted wazuh-indexer (status: {status.upper()})."
    )
    return status, details


def _manual_fix_heap(context):
    return FixEngine.heap_steps()


def _restart_indexer(context):
    return restart_service_and_wait("wazuh-indexer")


STEPS = [
    {
        "key": "ip",
        "title": "indexer IP address",
        "check_fn": _check_ip,
        "manual_check_instructions_fn": _manual_check_ip,
        "auto_fix_fn": _auto_fix_ip,
        "manual_fix_instructions_fn": _manual_fix_ip,
        "restart_fn": _restart_indexer,
    },
    {
        "key": "cert",
        "title": "certificate paths",
        "check_fn": _check_cert,
        "manual_check_instructions_fn": _manual_check_cert,
        "auto_fix_fn": _auto_fix_cert,
        "manual_fix_instructions_fn": _manual_fix_cert,
        "restart_fn": _restart_indexer,
    },
    {
        "key": "heap",
        "title": "heap memory configuration",
        "check_fn": _check_heap,
        "manual_check_instructions_fn": _manual_check_heap,
        "auto_fix_fn": _auto_fix_heap,
        "manual_fix_instructions_fn": _manual_fix_heap,
        "restart_fn": _restart_indexer,
    },
]

# All stages this module owns, plus the legacy entry stage.
STAGES = stage_names(PREFIX, STEPS) | {ENTRY_STAGE}


def ip_cert_flow(user_choice=None, context=None):
    if context is None:
        context = {}

    if context.get("stage") == ENTRY_STAGE:
        return start_flow(PREFIX, STEPS, context)

    return run_step_flow(
        PREFIX, STEPS, NEXT_STAGE_AFTER_ONGOING,
        user_choice=user_choice, context=context,
    )
