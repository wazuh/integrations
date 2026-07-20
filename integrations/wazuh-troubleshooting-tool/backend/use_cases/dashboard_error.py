from executor import run_command
from utils.fix_engine import FixEngine
from utils.log_handler import LogHandler
from utils.log_analyzer import LogAnalyzer
from flows.ip_cert_flow import ip_cert_flow, STAGES as IP_CERT_STAGES
from flows.dashboard_ip_cert_flow import dashboard_ip_cert_flow, STAGES as DASH_IP_CERT_STAGES


def dashboard_error_flow(user_choice=None, context=None):

    if context is None:
        context = {}

    response = {
        "display": "",
        "ask":     [],
        "done":    False,
        "context": context,
    }

    # -------------------------------------------------------------------------
    # START
    # -------------------------------------------------------------------------
    if not context:
        response["display"] = (
            "When you get 'Wazuh dashboard is not ready yet' error it normally "
            "indicates that the Wazuh dashboard cannot communicate with the "
            "indexer.\n\n"
            "How would you like to proceed?\n"
            "  auto   → we check and fix everything for you step by step\n"
            "  manual → we give you all the steps to follow yourself"
        )
        response["ask"]  = ["How would you like to proceed? (auto / manual)"]
        context["stage"] = "start_choice"
        return response

    # -------------------------------------------------------------------------
    # ROUTE TO ip_cert_flow (indexer checks: IP -> cert paths -> heap memory)
    # -------------------------------------------------------------------------
    if context.get("stage") in IP_CERT_STAGES:
        result = ip_cert_flow(user_choice=user_choice, context=context)

        # "handoff" fires when the last step (heap) is still "ongoing" -
        # control returns here so the dashboard IP/cert flow can continue.
        # We fold this step's own message into whatever comes next instead
        # of letting it get silently dropped at this boundary.
        if result.get("handoff"):
            next_result = dashboard_error_flow(context=result["context"])
            if result.get("display"):
                next_result["display"] = result["display"] + "\n\n" + next_result["display"]
            return next_result

        return result

    # -------------------------------------------------------------------------
    # ROUTE TO dashboard_ip_cert_flow (dashboard checks: IP -> cert paths)
    # -------------------------------------------------------------------------
    if context.get("stage") in DASH_IP_CERT_STAGES:
        result = dashboard_ip_cert_flow(user_choice=user_choice, context=context)

        # "handoff" fires when the last step (dashboard cert paths) is
        # still "ongoing" - hands off to log analysis (fetch_logs).
        if result.get("handoff"):
            next_result = dashboard_error_flow(context=result["context"])
            if result.get("display"):
                next_result["display"] = result["display"] + "\n\n" + next_result["display"]
            return next_result

        return result

    # -------------------------------------------------------------------------
    # START CHOICE
    # -------------------------------------------------------------------------
    if context.get("stage") == "start_choice":

        if user_choice and "manual" in user_choice.lower():
            response["display"] = (
                "Let's investigate the issue about the Wazuh Dashboard:\n\n"

                "Step 1 — Make sure the Wazuh indexer service is up and running:\n"
                "  systemctl status wazuh-indexer\n\n"

                "Step 2 — Check the dashboard configuration file:\n"
                "  /etc/wazuh-dashboard/opensearch_dashboards.yml\n\n"
                "  Make sure the indexer IP is correct:\n"
                "  opensearch.hosts: https://<Wazuh-IndexerIP>:9200\n\n"

                "  Run this to find the indexer IP:\n"
                "  head /etc/wazuh-indexer/opensearch.yml\n\n"

                "Step 3 — Check certificate names and paths:\n"
                "  ls -lrt /etc/wazuh-dashboard/certs/\n"
                "  Ensure the paths and filenames match what is in the config.\n\n"

                "Step 4 — Restart the dashboard service:\n"
                "  systemctl restart wazuh-dashboard\n"
                "  systemctl status wazuh-dashboard\n\n"

                "Step 5 — Verify the dashboard can communicate with the indexer.\n"
                "Run this from the dashboard server:\n"
                "  curl -XGET -k -u kibanaserver:<password> "
                "\"https://<Indexer_IP>:9200/_cluster/health\"\n\n"

                "  If you get connection refused -> check firewall on port 9200.\n"
                "  If you see no output or auth error -> reset kibanaserver "
                "password (Step 6).\n\n"

                "Step 6 — Reset kibanaserver password if needed.\n"
                "Password must be 8-64 chars, upper/lowercase, numbers, "
                "symbol from .*+?-\n\n"

                "  /usr/share/wazuh-indexer/plugins/opensearch-security/tools/"
                "wazuh-passwords-tool.sh -u kibanaserver -p '<new_password>'\n\n"

                "  Note: If using AIO, passwords are updated automatically.\n\n"

                "  Then update the dashboard keystore:\n"
                "  echo <new_password> | "
                "/usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore "
                "--allow-root add -f --stdin opensearch.password\n\n"

                "  Ref: https://documentation.wazuh.com/current/user-manual/"
                "user-administration/password-management.html\n\n"

                "Step 7 — If the issue still persists collect these logs:\n"
                "  journalctl -u wazuh-dashboard\n"
                "  cat /usr/share/wazuh-dashboard/data/wazuh/logs/wazuhapp.log "
                "| grep -i -E 'error|warn'\n"
                "  cat /var/log/wazuh-indexer/wazuh-cluster.log "
                "| grep -i -E 'error|warn'\n\n"

                "Let us know the update for further assistance."
            )

            response["ask"]  = ["Did this help? (resolved / need further assistance)"]
            context["stage"] = "manual_followup"
            return response

        # auto chosen — ask how to determine the indexer status before restarting
        response["display"] = (
            "Let's start with the Wazuh indexer service."
        )
        response["ask"]  = ["Restart Wazuh Indexer? (auto / inactive / active)"]
        context["stage"] = "restart_step"
        return response

    # -------------------------------------------------------------------------
    # RESTART STEP — determine indexer status, restart if needed
    # -------------------------------------------------------------------------
    if context.get("stage") == "restart_step":

        choice = (user_choice or "").lower().strip()

        if "auto" in choice:
            status = (run_command("systemctl is-active wazuh-indexer") or "").strip()
        elif "inactive" in choice:
            status = "inactive"
        elif "active" in choice:
            status = "active"
        else:
            response["display"] = "Please choose one: auto / inactive / active"
            response["ask"]  = ["Restart Wazuh Indexer? (auto / inactive / active)"]
            return response

        context["indexer_status"] = status
        response["display"] = f"Indexer status: {status}\n\n"

        if status != "active":
            response["display"] += "The Wazuh indexer is not running. Restarting it now..."
            new_status = FixEngine.restart_indexer_and_wait()
            context["indexer_status"] = new_status
            response["display"] += f"\n\nStatus after restart: {new_status.upper()}"

        response["display"] += (
            "\n\nLet's now go through the indexer checks: "
            "IP address, certificate paths, and heap memory."
        )
        context["stage"] = "ip_check"

        # Preserve this message — indexer_recovery_flow's own first
        # response (the Step 1 permission question) would otherwise
        # completely replace it here.
        restart_msg = response["display"]
        next_response = dashboard_error_flow(context=context)
        next_response["display"] = restart_msg + "\n\n" + next_response["display"]
        return next_response

    # -------------------------------------------------------------------------
    # MANUAL FOLLOW-UP
    # -------------------------------------------------------------------------
    if context.get("stage") == "manual_followup":

        if user_choice and "resolved" in user_choice.lower():
            response["display"] = "Great! Glad the issue is resolved."
            response["done"]    = True
            return response

        response["display"] = (
            "Let's dig deeper.\n\n"
            "Have you checked the indexer status yet?\n"
            "If not, I can check it for you right now."
        )

        response["ask"]  = ["Indexer status? (check / it's active / it's inactive)"]
        context["stage"] = "indexer_status_check"
        return response

    # -------------------------------------------------------------------------
    # INDEXER STATUS CHECK
    # -------------------------------------------------------------------------
    if context.get("stage") == "indexer_status_check":

        if user_choice and "check" in user_choice.lower():
            status = (run_command("systemctl is-active wazuh-indexer") or "").strip()
            context["indexer_status"] = status
            response["display"] = f"Indexer status: {status}"

        elif user_choice and "inactive" in user_choice.lower():
            status = "inactive"
            context["indexer_status"] = status
            response["display"] = "Understood — indexer is inactive."

        else:
            status = "active"
            context["indexer_status"] = status
            response["display"] = "Understood — indexer is active."

        if status != "active":
            response["display"] += "\n\nThe indexer is not running. Restarting wazuh-indexer now..."
            new_status = FixEngine.restart_indexer_and_wait()
            context["indexer_status"] = new_status
            response["display"] += f"\n\nStatus after restart: {new_status.upper()}"

        response["display"] += (
            "\n\nLet's now go through the indexer checks: "
            "IP address, certificate paths, and heap memory."
        )
        context["stage"] = "ip_check"

        restart_msg = response["display"]
        next_response = dashboard_error_flow(context=context)
        next_response["display"] = restart_msg + "\n\n" + next_response["display"]
        return next_response

    # -------------------------------------------------------------------------
    # FETCH LOGS
    # -------------------------------------------------------------------------
    if context.get("stage") == "fetch_logs":

        response["display"] = (
            "Would you like me to fetch the dashboard and indexer logs, "
            "or will you run the commands yourself?"
        )

        response["ask"]  = ["Fetch logs? (auto / manual / no)"]
        context["stage"] = "logs_action"
        return response

    # -------------------------------------------------------------------------
    # LOGS ACTION
    # -------------------------------------------------------------------------
    if context.get("stage") == "logs_action":

        chose_auto   = user_choice and "auto"   in user_choice.lower()
        chose_manual = user_choice and "manual" in user_choice.lower()

        if chose_auto:

            logs  = LogHandler.get_indexer_logs(1)
            clean = LogHandler.clean_logs(logs)

            context["logs"]     = logs
            response["display"] = f"Recent indexer logs:\n\n{clean}"
            context["stage"]    = "logs_analyze"

            return dashboard_error_flow(context=context)

        elif chose_manual:

            response["display"] = (
                "Run these and paste the output back:\n\n"

                "  journalctl -u wazuh-dashboard\n\n"

                "  cat /usr/share/wazuh-dashboard/data/wazuh/logs/wazuhapp.log "
                "| grep -i -E 'error|warn'\n\n"

                "  cat /var/log/wazuh-indexer/wazuh-cluster.log "
                "| grep -i -E 'error|warn'"
            )

            response["ask"]  = ["Paste the log output here"]
            context["stage"] = "logs_paste"

            return response

        else:
            response["display"] = "Skipping log check."
            context["stage"]    = "jvm_check"

            return dashboard_error_flow(context=context)

    # -------------------------------------------------------------------------
    # LOGS PASTE
    # -------------------------------------------------------------------------
    if context.get("stage") == "logs_paste":

        context["logs"]  = user_choice or ""
        context["stage"] = "logs_analyze"

        return dashboard_error_flow(context=context)

    # -------------------------------------------------------------------------
    # ANALYZE LOGS
    # -------------------------------------------------------------------------
    if context.get("stage") == "logs_analyze":

        logs   = context.get("logs") or ""
        issues = LogAnalyzer.get_issues(logs)

        context["issues"] = issues

        if not issues:
            response["display"] = "No known issues found in the logs."
            context["stage"]    = "jvm_check"

            return dashboard_error_flow(context=context)

        found_lines = []

        for issue in issues:

            if issue == "init":
                found_lines.append(
                    "[INIT] Indexer security not yet initialized."
                )

            elif issue == "heap":
                found_lines.append(
                    "[HEAP] Memory/heap issue detected."
                )

            elif issue == "auth":
                found_lines.append(
                    "[AUTH] Authentication failed for kibanaserver. "
                    "Please flag this to your team for a password reset."
                )

            elif issue == "watermark":
                found_lines.append(
                    "[DISK] Disk watermark exceeded. "
                    "Free up disk space or expand storage manually.\n"
                    "Check: df -h"
                )

            elif issue == "permission":
                found_lines.append(
                    "[PERMISSION] Insecure file permissions on indexer config. "
                    "Please flag this to your team."
                )

            elif issue == "dashboard_connection_refused":
                found_lines.append(
                    "[CONNECTION REFUSED] Connection to :9200 was refused. "
                    "Please check whether the Wazuh indexer service is running."
                )

        response["display"] = (
            f"Found {len(issues)} issue(s) in the logs:\n\n"
            + "\n\n".join(found_lines)
        )

        if "init" in issues:
            context["stage"] = "init_check"

        elif "heap" in issues:
            context["stage"] = "jvm_check"

        elif "dashboard_connection_refused" in issues:
            context["stage"] = "connection_refused_indexer_check"

        else:
            context["stage"] = "dashboard_status"

        return dashboard_error_flow(context=context)

    # -------------------------------------------------------------------------
    # INIT CHECK
    # -------------------------------------------------------------------------
    if context.get("stage") == "init_check":

        response["display"] = (
            "The logs show the indexer security is not yet initialized.\n\n"
            "Is this a new or existing installation?"
        )

        response["ask"]  = ["New or existing? (new / existing)"]
        context["stage"] = "init_action"

        return response

    # -------------------------------------------------------------------------
    # INIT ACTION
    # -------------------------------------------------------------------------
    if context.get("stage") == "init_action":

        if user_choice and "new" in user_choice.lower():

            response["display"] = (
                "Since this is a new installation the indexer security "
                "needs to be initialized. Would you like me to run it?"
            )

            response["ask"]  = ["Run security init? (auto / manual)"]
            context["stage"] = "init_run"

            return response

        else:

            response["display"] = (
                "Since this is an existing installation, "
                "the initialization issue is unexpected.\n\n"
                "Let me check step by step starting with the IP configuration."
            )

            context["stage"] = "ip_check"

            return dashboard_error_flow(context=context)

    # -------------------------------------------------------------------------
    # RUN SECURITY INIT
    # -------------------------------------------------------------------------
    if context.get("stage") == "init_run":

        if user_choice and "auto" in user_choice.lower():

            out = run_command(FixEngine.init_command()) or ""
            response["display"] = f"Security init output:\n{out}"

        else:

            response["display"] = (
                "Run:\n\n"
                f"  {FixEngine.init_command()}\n\n"
                "Then restart:\n"
                "  systemctl restart wazuh-indexer"
            )

        context["stage"] = "jvm_check"

        return dashboard_error_flow(context=context)

    # -------------------------------------------------------------------------
    # JVM HEAP CHECK (legacy — triggered from log analysis path)
    # -------------------------------------------------------------------------
    if context.get("stage") == "jvm_check":

        current = run_command(
            "grep -E '^-Xms|^-Xmx' /etc/wazuh-indexer/jvm.options"
        ) or "(could not read)"

        total_kb = run_command(
            "grep MemTotal /proc/meminfo | awk '{print $2}'"
        ) or ""

        total_gb = round(int(total_kb.strip()) / 1024 / 1024)
        heap_gb  = max(1, total_gb // 2)

        response["display"] = (
            f"Current JVM heap settings:\n"
            f"{current}\n\n"
            f"Total RAM: {total_gb} GB\n\n"
            f"Recommended (50% of RAM):\n"
            f"  -Xms{heap_gb}g\n"
            f"  -Xmx{heap_gb}g\n\n"
            f"{FixEngine.heap_steps()}\n\n"
            "Would you like to fix the heap settings?"
        )

        response["ask"]             = ["Fix heap? (auto / manual / no)"]
        context["recommended_heap"] = heap_gb
        context["stage"]            = "jvm_fix"

        return response

    # -------------------------------------------------------------------------
    # JVM FIX (legacy — triggered from log analysis path)
    # -------------------------------------------------------------------------
    if context.get("stage") == "jvm_fix":

        if user_choice and "auto" in user_choice.lower():

            heap_gb = context.get("recommended_heap", 2)
            result = FixEngine.fix_jvm_heap(heap_gb)

            response["display"] = (
                "Edited /etc/wazuh-indexer/jvm.options\n\n"
                f"Restarted wazuh-indexer (status: {result['status'].upper()}).\n\n"
                "Current JVM heap settings:\n"
                f"{result['updated']}"
            )

            response["ask"]  = ["Is the dashboard issue fixed? (fixed / ongoing)"]
            context["stage"] = "post_heap_check"

            return response

        elif user_choice and "manual" in user_choice.lower():

            response["display"] = FixEngine.heap_steps()
            response["ask"]     = ["Is the dashboard issue fixed? (fixed / ongoing)"]
            context["stage"]    = "post_heap_check"

            return response

        else:

            response["display"] = "Skipped heap fix."
            context["stage"]    = "dashboard_status"

            return dashboard_error_flow(context=context)

    # -------------------------------------------------------------------------
    # POST HEAP CHECK (legacy — triggered from log analysis path)
    # -------------------------------------------------------------------------
    if context.get("stage") == "post_heap_check":

        if user_choice.lower().strip() == "fixed":

            response["display"] = "Great! The issue is resolved."
            response["done"]    = True

            return response

        elif user_choice.lower().strip() == "ongoing":

            response["display"] = (
                "The issue is still ongoing.\n"
                "Let's fetch the logs for deeper analysis."
            )

            context["stage"] = "fetch_logs"

            return dashboard_error_flow(context=context)

    # -------------------------------------------------------------------------
    # DASHBOARD STATUS + LOGS
    # -------------------------------------------------------------------------
    if context.get("stage") == "dashboard_status":

        status = FixEngine.status_dashboard().strip()
        response["display"] = f"Dashboard status: {status}\n\n"

        if status == "active":

            response["display"] += (
                "The Wazuh dashboard is running.\n"
                "Please open your browser and check the UI."
            )

            response["ask"]  = ["Is the issue resolved? (resolved / not resolved)"]
            context["stage"] = "final_status_check"

            return response

        indexer_logs    = LogHandler.get_indexer_logs(1)
        dashboard_logs  = LogHandler.get_dashboard_logs(1)

        clean_indexer   = LogHandler.clean_logs(indexer_logs)
        clean_dashboard = LogHandler.clean_logs(dashboard_logs)

        response["display"] += (
            "The dashboard is still not active.\n\n"

            "--- Connectivity check ---\n"

            "Run from the dashboard server:\n"

            "  curl -XGET -k -u kibanaserver:<password> "
            "\"https://<Indexer_IP>:9200/_cluster/health\"\n\n"

            "  Connection refused → check firewall on port 9200.\n"

            "  Auth error → reset kibanaserver password:\n"

            "  /usr/share/wazuh-indexer/plugins/opensearch-security/tools/"
            "wazuh-passwords-tool.sh -u kibanaserver -p '<new_password>'\n\n"

            "  Then update keystore:\n"

            "  echo <new_password> | "
            "/usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore "
            "--allow-root add -f --stdin opensearch.password\n\n"

            "  Ref: https://documentation.wazuh.com/current/user-manual/"
            "user-administration/password-management.html\n\n"

            "--- Recent indexer logs ---\n"
            f"{clean_indexer}\n\n"

            "--- Recent dashboard logs ---\n"
            f"{clean_dashboard}\n\n"

            "If the issue still persists share the above on:\n"
            "  https://wazuh.com/community/"
        )

        response["done"] = True
        return response


   # -------------------------------------------------------------------------
    # DASHBOARD STATUS + LOGS
    # -------------------------------------------------------------------------
    if context.get("stage") == "dashboard_status_logs":

        status = (FixEngine.status_dashboard() or "").strip()
        context["dashboard_status"] = status

        response["display"] = f"Dashboard status: {status or 'unknown'}\n\n"

        if status == "active":
            response["display"] += (
                "The Wazuh dashboard is running.\n"
                "Please open your browser and check the UI."
            )

            response["ask"] = [
                "Is the issue resolved? (resolved / not resolved)"
            ]

            context["stage"] = "logs_action_dashboard"
            response["context"] = context

            return response

        response["display"] += (
            "The Wazuh dashboard is not active.\n\n"
            "Let's check the dashboard logs."
        )

        logs = LogHandler.get_dashboard_logs(1)
        clean = LogHandler.clean_logs(logs)

        context["logs"] = logs
        context["stage"] = "logs_analyze_dashboard"

        response["display"] += (
            f"\n\nRecent dashboard logs:\n\n{clean}"
        )
        response["ask"]    = ["Continue to log analysis? (yes)"]
        response["context"] = context
        return response


    # -------------------------------------------------------------------------
    # DASHBOARD RESOLUTION CHECK
    # -------------------------------------------------------------------------
    if context.get("stage") == "logs_action_dashboard":

        choice = (user_choice or "").lower().strip()

        if choice == "resolved":
            response["display"] = "Glad to know the issue is resolved."
            response["done"] = True
            response["context"] = context

            return response

        if choice == "not resolved":
            logs = LogHandler.get_dashboard_logs(1)
            clean = LogHandler.clean_logs(logs)

            context["logs"] = logs
            context["stage"] = "logs_analyze_dashboard"

            response["display"] = (
                "The issue is still not resolved.\n\n"
                f"Recent dashboard logs:\n\n{clean}"
            )
            response["ask"]    = ["Continue? (yes)"]
            response["context"] = context
            return response

        response["display"] = "Please choose: resolved / not resolved"
        response["ask"] = [
            "Is the issue resolved? (resolved / not resolved)"
        ]

        response["context"] = context
        return response


    # -------------------------------------------------------------------------
    # ANALYZE DASHBOARD LOGS
    # -------------------------------------------------------------------------
    if context.get("stage") == "logs_analyze_dashboard":

        logs = context.get("logs") or ""
        issues = LogAnalyzer.get_issues(logs)

        context["issues"] = issues

        if not issues:
            # Logs are clean but issue persists — move to connectivity/password check
            response["display"] = (
                "No known issues found in the dashboard logs.\n\n"
                "Since the dashboard is running but the issue persists, "
                "let's check the connectivity between the dashboard and the indexer."
            )
            response["ask"]    = ["Check connectivity? (yes)"]
            context["stage"]   = "dashboard_status"
            response["context"] = context
            return response

        found_lines = []

        for issue in issues:

            if issue == "init":
                found_lines.append(
                    "[INIT] Indexer security not yet initialized."
                )

            elif issue == "heap":
                found_lines.append(
                    "[HEAP] Memory/heap issue detected."
                )

            elif issue == "auth":
                found_lines.append(
                    "[AUTH] Authentication failed for kibanaserver. "
                    "Please flag this to your team for a password reset."
                )

            elif issue == "watermark":
                found_lines.append(
                    "[DISK] Disk watermark exceeded. "
                    "Free up disk space or expand storage manually.\n"
                    "Check: df -h"
                )

            elif issue == "permission":
                found_lines.append(
                    "[PERMISSION] Insecure file permissions on indexer config. "
                    "Please flag this to your team."
                )

            elif issue == "dashboard_connection_refused":
                found_lines.append(
                    "[CONNECTION REFUSED] Connection to :9200 was refused. "
                    "Please check whether the Wazuh indexer service is running."
                )

        response["display"] = (
            f"Found {len(issues)} issue(s) in the logs:\n\n"
            + "\n\n".join(found_lines)
        )

        if "init" in issues:
            context["stage"] = "init_check"
            response["ask"]  = ["Continue to initialization check? (yes)"]

        elif "heap" in issues:
            context["stage"] = "jvm_check"
            response["ask"]  = ["Continue to heap check? (yes)"]

        elif "dashboard_connection_refused" in issues:
            context["stage"] = "connection_refused_indexer_check"
            response["ask"]  = ["Continue? (yes)"]

        else:
            response["display"] += (
                "\n\nThese issues need manual review.\n\n"
                "If the issue still persists, please contact the Wazuh community:\n"
                "https://wazuh.com/community/"
            )
            response["done"] = True

        response["context"] = context
        return response

    # -------------------------------------------------------------------------
    # CONNECTION REFUSED: INDEXER CHECK
    # -------------------------------------------------------------------------
    if context.get("stage") == "connection_refused_indexer_check":

        response["display"] = (
            "The dashboard logs show that connection to the Wazuh indexer on port 9200 was refused.\n\n"
            "This usually means the Wazuh indexer service is stopped, unhealthy, or not reachable."
        )

        response["ask"] = [
            "We have already checked the status. Should we do that again? "
            "(check / it's active / it's inactive / no)"
        ]

        context["stage"] = "connection_refused_indexer_status"
        response["context"] = context

        return response


    # -------------------------------------------------------------------------
    # CONNECTION REFUSED: INDEXER STATUS
    # -------------------------------------------------------------------------
    if context.get("stage") == "connection_refused_indexer_status":

        choice = (user_choice or "").lower().strip()

        if "check" in choice:
            status = (
                run_command("systemctl is-active wazuh-indexer") or ""
            ).strip()

        elif "inactive" in choice:
            status = "inactive"

        elif "active" in choice:
            status = "active"

        elif choice == "no":
            response["display"] = (
                "Okay.\n\n"
                "Please check the Wazuh indexer and dashboard logs for newer errors.\n\n"
                "If there are no newer errors and the issue still persists, "
                "I recommend taking help from the Wazuh community:\n"
                "https://wazuh.com/community/"
            )

            response["context"] = context
            return response

        else:
            response["display"] = (
                "Please choose one option: check / it's active / it's inactive / no"
            )

            response["ask"] = [
                "Should we check the indexer status again? "
                "(check / it's active / it's inactive / no)"
            ]

            response["context"] = context
            return response

        context["indexer_status"] = status

        if status != "active":
            response["display"] = (
                f"Indexer status: {status or 'unknown'}\n\n"
                "The Wazuh indexer service is inactive. Restarting it now..."
            )
            new_status = FixEngine.restart_indexer_and_wait()
            context["indexer_status"] = new_status
            response["display"] += (
                f"\n\nStatus after restart: {new_status.upper()}\n\n"
                "Let's now go through the indexer checks: "
                "IP address, certificate paths, and heap memory."
            )
            context["stage"] = "ip_check"

            restart_msg = response["display"]
            next_response = dashboard_error_flow(context=context)
            next_response["display"] = restart_msg + "\n\n" + next_response["display"]
            return next_response

        # indexer is active but dashboard still can't connect
        response["display"] = (
            f"Indexer status: {status}\n\n"
            "The Wazuh indexer is active but the dashboard still cannot reach it "
            "on port 9200.\n\n"
            "Please check: firewall rules on port 9200, the dashboard's "
            "opensearch.hosts IP, and network connectivity between dashboard "
            "and indexer.\n\n"
            "If everything looks correct and the issue still persists:\n"
            "  https://wazuh.com/community/"
        )
        response["done"]    = True
        response["context"] = context
        return response

    # -------------------------------------------------------------------------
    # FINAL STATUS CHECK
    # -------------------------------------------------------------------------
    if context.get("stage") == "final_status_check":
        choice = (user_choice or "").lower().strip()

        if choice == "resolved":

            response["display"] = "Great! Glad the issue is resolved."
            response["done"]    = True
            return response

        # not resolved — fetch and analyse logs
        dashboard_logs  = LogHandler.get_dashboard_logs(1)
        clean_dashboard = LogHandler.clean_logs(dashboard_logs)

        issues = LogAnalyzer.get_issues(dashboard_logs or "")
        context["issues"] = issues

        response["display"] = (
            "Let's dig into the logs.\n\n"
            "--- Recent dashboard logs ---\n"
            f"{clean_dashboard}\n\n"
        )

        if issues:
            found_lines = []

            for issue in issues:

                if issue == "init":
                    found_lines.append(
                        "[INIT] Indexer security not yet initialized."
                    )
                elif issue == "heap":
                    found_lines.append(
                        "[HEAP] Memory/heap issue detected."
                    )
                elif issue == "auth":
                    found_lines.append(
                        "[AUTH] Authentication failed for kibanaserver — "
                        "password reset required.\n\n"

                        "  /usr/share/wazuh-indexer/plugins/opensearch-security/tools/"
                        "wazuh-passwords-tool.sh -u kibanaserver -p '<new_password>'\n\n"

                        "  Then update the dashboard keystore:\n"

                        "  echo <new_password> | "
                        "/usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore "
                        "--allow-root add -f --stdin opensearch.password\n\n"

                        "  Restart:\n"
                        "  systemctl restart wazuh-dashboard"
                    )
                elif issue == "watermark":
                    found_lines.append(
                        "[DISK] Disk watermark exceeded — "
                        "free up disk space or expand storage.\n"
                        "  Check: df -h"
                    )
                elif issue == "permission":
                    found_lines.append(
                        "[PERMISSION] Insecure file permissions on indexer config."
                    )

            response["display"] += (
                f"Issues detected ({len(issues)}):\n\n"
                + "\n\n".join(found_lines)
            )

        else:
            response["display"] += (
                "No known issues detected in the logs.\n\n"

                "If the issue still persists share the above on:\n"
                "  https://wazuh.com/community/"
            )

        response["ask"]  = ["Still not resolved? (resolved / need more help)"]
        context["stage"] = "final_escalate"
        return response

    # -------------------------------------------------------------------------
    # FINAL ESCALATE
    # -------------------------------------------------------------------------
    if context.get("stage") == "final_escalate":

        if user_choice and "resolved" in user_choice.lower():

            response["display"] = "Great! Glad the issue is resolved."
            response["done"]    = True
            return response

        response["display"] = (
            "The issue needs further investigation.\n\n"
            "Please reach out to the Wazuh community for deeper support:\n"
            "  https://wazuh.com/community/"
        )
        response["done"] = True
        return response
