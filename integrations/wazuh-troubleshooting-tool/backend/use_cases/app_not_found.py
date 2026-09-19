"""
"Application Not Found" use case.

New, dedicated flow - does not modify use_cases/dashboard_error.py (still
used by the separate "Wazuh Dashboard Not Ready Yet" card), nor any of the
flow modules it relies on.

After an upgrade, "Application Not Found" is most commonly caused by
opensearch_dashboards.yml missing (or keeping a stale)
uiSettings.overrides.defaultRoute, not by indexer/certificate/IP problems.
So this flow checks and fixes that FIRST.

If the issue is still ongoing, it moves on to dashboard-only diagnostics:
dashboard IP -> dashboard certificate paths (via the existing, unmodified
flows/dashboard_ip_cert_flow.py, called directly - NOT through
dashboard_error_flow, whose own internal state machine would otherwise
chain onward into indexer log analysis and indexer IP/cert checks).

If still unresolved after that, it checks the dashboard's own logs for the
last hour. If nothing relevant turns up, it points the user to the Wazuh
community instead of ever touching indexer IP/certs - this card stays
focused on the Wazuh dashboard end-to-end.
"""

from flows.default_route_flow import default_route_flow, STAGES as DEFAULT_ROUTE_STAGES
from flows.dashboard_ip_cert_flow import dashboard_ip_cert_flow, STAGES as DASH_IP_CERT_STAGES
from utils.log_handler import LogHandler
from utils.log_analyzer import LogAnalyzer
from utils.response_utils import make_response

DASHBOARD_LOGS_STAGE = "app_not_found_dashboard_logs"
COMMUNITY_URL = "https://wazuh.com/community/"


def app_not_found_flow(user_choice=None, context=None):
    if context is None:
        context = {}

    # -------------------------------------------------------------------------
    # START - check the dashboard default route configuration first.
    # -------------------------------------------------------------------------
    if not context:
        context["stage"] = "default_route_check"
        result = default_route_flow(context=context)
        result["display"] = (
            "The 'Application Not Found' error is most often caused, after an "
            "upgrade, by the Wazuh dashboard configuration still missing the "
            "default route setting.\n\n" + result["display"]
        )
        return result

    # -------------------------------------------------------------------------
    # Route to default_route_flow while we're in one of its own stages.
    # -------------------------------------------------------------------------
    if context.get("stage") in DEFAULT_ROUTE_STAGES:
        result = default_route_flow(user_choice=user_choice, context=context)

        if result.get("handoff"):
            # Default route checks out (or was fixed) but the issue is still
            # ongoing - move to the dashboard IP/cert checks (dashboard-only,
            # no indexer IP/cert checks).
            context["stage"] = "dash_ip_check"
            next_result = dashboard_ip_cert_flow(context=context)
            if result.get("display"):
                next_result["display"] = result["display"] + "\n\n" + next_result["display"]
            return next_result

        return result

    # -------------------------------------------------------------------------
    # Route to dashboard_ip_cert_flow while we're in one of its own stages.
    # -------------------------------------------------------------------------
    if context.get("stage") in DASH_IP_CERT_STAGES:
        result = dashboard_ip_cert_flow(user_choice=user_choice, context=context)

        if result.get("handoff"):
            # Dashboard IP/cert check out (or were fixed) but the issue is
            # still ongoing - check the dashboard's own logs, not the
            # indexer's, and don't chain back into indexer checks.
            return _check_dashboard_logs(result["context"], prefix_display=result.get("display"))

        return result

    # -------------------------------------------------------------------------
    # Dashboard logs follow-up (resolved / not resolved).
    # -------------------------------------------------------------------------
    if context.get("stage") == DASHBOARD_LOGS_STAGE:
        return _dashboard_logs_followup(user_choice, context)

    return make_response(
        display="Something went wrong with this workflow. Please relaunch it.",
        done=True,
        context=context,
    )


def _check_dashboard_logs(context, prefix_display=None):
    # journalctl -u wazuh-dashboard --since '1 hours ago' | grep -i -E 'error|warn'
    # - restricted to the last 1 hour.
    raw_logs = LogHandler.get_dashboard_logs(1)
    prefix = (prefix_display + "\n\n") if prefix_display else ""

    if not raw_logs.strip():
        display = (
            prefix
            + "No related dashboard logs found in the last hour.\n\n"
            + "If the issue still persists, please reach out to the Wazuh "
              "community for further support:\n"
            + f"  {COMMUNITY_URL}"
        )
        return make_response(display=display, done=True, context=context)

    clean = LogHandler.clean_logs(raw_logs)
    issues = LogAnalyzer.get_issues(raw_logs)
    header = prefix + f"Recent dashboard logs (last 1 hour):\n\n{clean}"

    context["stage"] = DASHBOARD_LOGS_STAGE

    if not issues:
        display = (
            header + "\n\n"
            "No known issue pattern was recognized in these logs.\n\n"
            "Is the issue resolved now?"
        )
        return make_response(
            display=display,
            ask=["Is the issue resolved? (resolved / not resolved)"],
            context=context,
        )

    found_lines = [_describe_issue(issue) for issue in issues]

    display = (
        header + "\n\n"
        f"Found {len(issues)} issue(s) in the logs:\n\n"
        + "\n\n".join(found_lines)
        + "\n\nIs the issue resolved now?"
    )
    return make_response(
        display=display,
        ask=["Is the issue resolved? (resolved / not resolved)"],
        context=context,
    )


def _describe_issue(issue):
    if issue == "auth":
        return (
            "[AUTH] Authentication failed for kibanaserver.\n\n"
            "  Reset the kibanaserver password:\n"
            "  /usr/share/wazuh-indexer/plugins/opensearch-security/tools/"
            "wazuh-passwords-tool.sh -u kibanaserver -p '<new_password>'\n\n"
            "  Then update the dashboard keystore:\n"
            "  echo <new_password> | "
            "/usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore "
            "--allow-root add -f --stdin opensearch.password\n\n"
            "  Restart:\n"
            "  systemctl restart wazuh-dashboard"
        )

    if issue == "dashboard_connection_refused":
        return (
            "[CONNECTION REFUSED] The dashboard could not reach the Wazuh "
            "indexer on port 9200.\n"
            "  Check that the indexer is running and reachable, and that "
            "the firewall allows port 9200."
        )

    if issue == "watermark":
        return (
            "[DISK] Disk watermark exceeded.\n"
            "  Free up disk space or expand storage.\n"
            "  Check: df -h"
        )

    if issue == "permission":
        return (
            "[PERMISSION] Insecure file permissions detected on the indexer "
            "configuration. Please flag this to your team."
        )

    if issue == "init":
        return (
            "[INIT] Indexer security not yet initialized. This is an "
            "indexer-side issue outside this dashboard workflow - please "
            "raise it separately."
        )

    if issue == "heap":
        return (
            "[HEAP] Indexer memory/heap issue detected. This is an "
            "indexer-side issue outside this dashboard workflow - please "
            "raise it separately."
        )

    return f"[UNKNOWN] {issue}"


def _dashboard_logs_followup(user_choice, context):
    choice = (user_choice or "").lower().strip()

    if "not" not in choice and "resolved" in choice:
        return make_response(display="Great! Glad the issue is resolved.", done=True, context=context)

    display = (
        "Understood.\n\n"
        "Please reach out to the Wazuh community for further support:\n"
        f"  {COMMUNITY_URL}"
    )
    return make_response(display=display, done=True, context=context)
