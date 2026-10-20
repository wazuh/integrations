"""
Dashboard default route flow — dedicated to the "Application Not Found" card.

New, self-contained flow: it only reuses the generic, use-case-agnostic
step engine (utils/step_flow.py). It does not touch flows/ip_cert_flow.py
or flows/dashboard_ip_cert_flow.py.

Checks a single thing: whether opensearch_dashboards.yml has
uiSettings.overrides.defaultRoute set to /app/wz-home. This is the most
common cause of "Application Not Found" - it happens when the dashboard
config is left over from before an upgrade and is missing (or has a stale)
default route setting for the new version.
"""

from utils.default_route_utils import (
    DASHBOARD_CONFIG_PATH,
    EXPECTED_DEFAULT_ROUTE,
    get_default_route,
    is_default_route_ok,
    set_default_route,
)
from utils.service_utils import restart_service_and_wait
from utils.step_flow import stage_names, start_flow, run_step_flow

PREFIX = "default_route"
ENTRY_STAGE = "default_route_check"
NEXT_STAGE_AFTER_ONGOING = "app_not_found_broader_diagnostics"


# ---------------------------------------------------------------------------
# STEP: dashboard default route
# ---------------------------------------------------------------------------
def _check_default_route(context):
    raw = get_default_route()
    details = (
        f"  Configured: {raw.strip() or '(not set)'}\n"
        f"  Expected:   uiSettings.overrides.defaultRoute: {EXPECTED_DEFAULT_ROUTE}"
    )
    return is_default_route_ok(raw), details


def _manual_check_default_route(context):
    return (
        "To check this yourself:\n\n"
        "1. Look for the default route setting:\n"
        f"   grep uiSettings.overrides.defaultRoute {DASHBOARD_CONFIG_PATH}\n\n"
        "2. It should be set to:\n"
        f"   uiSettings.overrides.defaultRoute: {EXPECTED_DEFAULT_ROUTE}"
    )


def _auto_fix_default_route(context):
    updated = set_default_route()
    status = restart_service_and_wait("wazuh-dashboard")
    details = (
        f"Set uiSettings.overrides.defaultRoute: {EXPECTED_DEFAULT_ROUTE} in "
        "opensearch_dashboards.yml.\n"
        f"  {updated.strip()}\n\n"
        f"Restarted wazuh-dashboard (status: {status.upper()}).\n\n"
        "Please open your browser and verify the dashboard is accessible."
    )
    return status, details


def _manual_fix_default_route(context):
    return (
        f"Edit {DASHBOARD_CONFIG_PATH} and set:\n\n"
        f"  uiSettings.overrides.defaultRoute: {EXPECTED_DEFAULT_ROUTE}\n\n"
        "Save the file, then restart the dashboard:\n"
        "  systemctl restart wazuh-dashboard"
    )


def _restart_dashboard(context):
    return restart_service_and_wait("wazuh-dashboard")


STEPS = [
    {
        "key": "route",
        "title": "dashboard default route configuration",
        "check_fn": _check_default_route,
        "manual_check_instructions_fn": _manual_check_default_route,
        "auto_fix_fn": _auto_fix_default_route,
        "manual_fix_instructions_fn": _manual_fix_default_route,
        "restart_fn": _restart_dashboard,
    },
]

STAGES = stage_names(PREFIX, STEPS) | {ENTRY_STAGE}


def default_route_flow(user_choice=None, context=None):
    if context is None:
        context = {}

    if context.get("stage") == ENTRY_STAGE:
        return start_flow(PREFIX, STEPS, context)

    return run_step_flow(
        PREFIX, STEPS, NEXT_STAGE_AFTER_ONGOING,
        user_choice=user_choice, context=context,
    )
