"""
Dashboard IP / certificate paths flow.

Order: dashboard IP -> dashboard certificate paths -> (log analysis if still
ongoing after the last step).

Same pattern as flows/ip_cert_flow.py, just for the dashboard side. This
module only DEFINES what's specific to these checks; all flow-control lives
in utils/step_flow.py.
"""

from utils.fix_engine import FixEngine
from utils.service_utils import restart_service_and_wait
from utils.step_flow import stage_names, start_flow, run_step_flow

PREFIX = "dash_ip_cert"
ENTRY_STAGE = "dash_ip_check"          # legacy-compatible entry point
NEXT_STAGE_AFTER_ONGOING = "fetch_logs"


# ---------------------------------------------------------------------------
# STEP: dashboard IP
# ---------------------------------------------------------------------------
def _check_dash_ip(context):
    data = FixEngine.check_dashboard_ip()
    context["d_ip"] = data["d_ip"]
    context["c_ip"] = data["c_ip"]
    details = (
        f"  opensearch_dashboards.yml opensearch.hosts:  {data['d_ip']}\n"
        f"  Expected (verified indexer IP):               {data['c_ip']}"
    )
    return data["match"], details


def _manual_check_dash_ip(context):
    c_ip = context.get("c_ip", "<indexer IP>")
    return (
        "To check this yourself:\n\n"
        "1. See the dashboard's configured indexer host:\n"
        "   grep opensearch.hosts /etc/wazuh-dashboard/opensearch_dashboards.yml\n\n"
        f"2. It should point to the indexer IP: {c_ip}"
    )


def _auto_fix_dash_ip(context):
    c_ip = context.get("c_ip", "")
    status = FixEngine.fix_dashboard_ip(c_ip)
    details = (
        f"Updated opensearch.hosts to https://{c_ip}:9200 in opensearch_dashboards.yml.\n"
        f"Restarted wazuh-dashboard (status: {status.upper()})."
    )
    return status, details


def _manual_fix_dash_ip(context):
    c_ip = context.get("c_ip", "<indexer IP>")
    return (
        "Edit /etc/wazuh-dashboard/opensearch_dashboards.yml and set:\n\n"
        f"  opensearch.hosts: [\"https://{c_ip}:9200\"]\n\n"
        "Save the file."
    )


# ---------------------------------------------------------------------------
# STEP: dashboard certificate paths
# ---------------------------------------------------------------------------
def _check_dash_cert(context):
    data = FixEngine.check_dashboard_cert_paths()
    context["dash_cert_missing"] = data["missing"]
    details = (
        "Configured cert paths (opensearch_dashboards.yml):\n"
        f"{data['paths_raw']}\n\n"
        "Available cert files (/etc/wazuh-dashboard/certs/):\n"
        f"{data['files_raw']}"
    )
    return (not data["missing"]), details


def _manual_check_dash_cert(context):
    return (
        "To check this yourself:\n\n"
        "1. See the cert paths configured in opensearch_dashboards.yml:\n"
        "   grep -E 'ssl.certificate|ssl.key|certificateAuthorities' "
        "/etc/wazuh-dashboard/opensearch_dashboards.yml\n\n"
        "2. See the cert files that actually exist:\n"
        "   ls /etc/wazuh-dashboard/certs/\n\n"
        "3. Every path from step 1 should exist in step 2's listing."
    )


def _auto_fix_dash_cert(context):
    result = FixEngine.fix_dashboard_cert_paths()
    if result.get("success"):
        status = result["status"]
        details = (
            "Updated cert paths:\n"
            f"  cert: {result['cert']}\n  key: {result['key']}\n  CA: {result['ca']}\n"
            f"Restarted wazuh-dashboard (status: {status.upper()})."
        )
    else:
        status = "unknown"
        details = "Could not auto-identify dashboard cert files. Please fix this one manually."
    return status, details


def _manual_fix_dash_cert(context):
    return FixEngine.dashboard_cert_path_steps()


def _restart_dashboard(context):
    return restart_service_and_wait("wazuh-dashboard")


STEPS = [
    {
        "key": "ip",
        "title": "dashboard IP configuration",
        "check_fn": _check_dash_ip,
        "manual_check_instructions_fn": _manual_check_dash_ip,
        "auto_fix_fn": _auto_fix_dash_ip,
        "manual_fix_instructions_fn": _manual_fix_dash_ip,
        "restart_fn": _restart_dashboard,
    },
    {
        "key": "cert",
        "title": "dashboard certificate paths",
        "check_fn": _check_dash_cert,
        "manual_check_instructions_fn": _manual_check_dash_cert,
        "auto_fix_fn": _auto_fix_dash_cert,
        "manual_fix_instructions_fn": _manual_fix_dash_cert,
        "restart_fn": _restart_dashboard,
    },
]

# All stages this module owns, plus the legacy entry stage.
STAGES = stage_names(PREFIX, STEPS) | {ENTRY_STAGE}


def dashboard_ip_cert_flow(user_choice=None, context=None):
    if context is None:
        context = {}

    if context.get("stage") == ENTRY_STAGE:
        return start_flow(PREFIX, STEPS, context)

    return run_step_flow(
        PREFIX, STEPS, NEXT_STAGE_AFTER_ONGOING,
        user_choice=user_choice, context=context,
    )
