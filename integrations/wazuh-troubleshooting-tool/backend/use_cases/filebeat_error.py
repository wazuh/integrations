"""
Use case: 'Filebeat Not Working' - having an issue in `filebeat test output`.

Standalone Filebeat-only troubleshooting card. Unlike
use_cases/no_alerts_are_showing.py's Step 3, this does NOT run as a fixed
"Step 1 / Step 2" script - each failure category needs a different sequence
(an unsupported-version fix loops back through the output test, a TLS/cert
fix does the same, a mapping issue hands off elsewhere entirely), so each
branch narrates only what it actually did.

Sequence:
    1. `filebeat test output` (after confirming the service is up).
    2. If it fails, classify why (utils/filebeat_utils.classify_filebeat_failure)
       and offer the matching auto/manual fix.
    3. If it succeeds, still check the Filebeat log - a clean connectivity
       test doesn't rule out something like a field-mapping error that only
       shows up there (or as a dashboard shard-failure).
    4. If a mapping/template signature is found (either in the failed test
       output or in the log), hand off to the dedicated "Filebeat Mapping
       Issue" card (use_cases/mapping_issue.py) instead of trying to fix
       templates here.
    5. If nothing is wrong on either check, point the user at the official
       Wazuh community for further help.

Reuses the same low-level Filebeat/cert helpers as flows/filebeat_flow.py
(utils/filebeat_utils.py, utils/cert_utils.py) - no Filebeat logic is
reimplemented here, only the narration/sequencing is different.
"""

from utils.service_utils import get_service_status, start_service_and_wait
from utils.filebeat_utils import (
    run_filebeat_output_test, get_filebeat_log_errors, classify_filebeat_failure,
    fix_unsupported_filebeat_version, manual_unsupported_version_instructions,
)
from utils.cert_utils import regenerate_and_redeploy_certs, manual_cert_redeploy_instructions
from utils.ai_utils import ai_explain

WAZUH_COMMUNITY_URL = "https://wazuh.com/community/"

MAPPING_ISSUE_KEYWORDS = [
    "illegal_argument_exception",
    "mapper_parsing_exception",
    "strict_dynamic_mapping_exception",
    "not optimised for operations that require per-document field data",
    "use a keyword field instead",
    "failed to parse field",
    "mapping conflict",
    "cannot be changed from type",
]

UNKNOWN_FAILURE_SYSTEM_PROMPT = (
    "You are a Wazuh Filebeat troubleshooting expert. You'll be given the output of "
    "'filebeat test output' plus recent Filebeat log error/warning lines. In 3-4 short "
    "sentences: state the most likely root cause and the single most useful next command or "
    "config fix. Be specific to what's actually in the output - don't give generic advice."
)


def _looks_like_mapping_issue(text):
    lowered = (text or "").lower()
    return any(kw in lowered for kw in MAPPING_ISSUE_KEYWORDS)


def _mapping_handoff(response):
    response["display"] += (
        "\n\n[LIKELY ROOT CAUSE] Field-mapping / index-template issue\n\n"
        "This looks like a mismatch between a field's data type and the Wazuh Indexer's "
        "index template rather than a Filebeat connectivity problem - fixing it means "
        "checking/reinstalling the Wazuh index template, not restarting Filebeat.\n\n"
        "Please continue with the \"Filebeat Mapping Issue\" card in the Troubleshooting "
        "Library - it checks the live index template, reinstalls the official one if it's "
        "missing or overridden, and reindexes any indices already affected."
    )
    response["done"] = True
    return response


def filebeat_error_flow(user_choice=None, context=None):
    if context is None:
        context = {}

    response = {"display": "", "ask": [], "done": False, "context": context}
    choice = (user_choice or "").strip().lower()

    # START
    if not context:
        response["display"] = (
            "Let's check the output of the command `filebeat test output` to see whether "
            "Filebeat can reach the Wazuh Indexer.\n\n"
            "How would you like to check this?\n\n"
            "  Auto   - We perform all checks automatically.\n"
            "  Manual - We provide the commands, and you run them and share the output."
        )
        response["ask"] = ["Auto", "Manual"]
        context["stage"] = "method"
        return response

    stage = context.get("stage")

    if stage == "method":
        if "manual" in choice:
            response["display"] = (
                "First, check whether the Filebeat service is running:\n\n"
                "    systemctl status filebeat\n\n"
                "If it's active, run the output test:\n\n"
                "    filebeat test output\n\n"
                "Did it succeed?"
            )
            response["ask"] = ["Yes, it succeeded", "No, it failed"]
            context["stage"] = "manual_result"
            return response
        return _check_service_and_test(response, context)

    if stage == "manual_result":
        if "yes" in choice or "succeeded" in choice:
            return _check_logs_after_success(response, context, prefix="[OK] Confirmed - the output test succeeded.")
        # Self-reported failure - get the real output/logs rather than trusting the report.
        return _check_service_and_test(response, context)

    if stage == "fix_service_start":
        if "auto" in choice:
            status = start_service_and_wait("filebeat")
        elif choice == "done":
            status = get_service_status("filebeat")
        elif "manual" in choice:
            response["display"] = "Run: systemctl start filebeat"
            response["ask"] = ["Done"]
            context["stage"] = "fix_service_start"
            return response
        else:
            response["ask"] = ["Auto", "Manual"]
            return response

        if status != "active":
            response["display"] = (
                "[ROOT CAUSE FOUND] Filebeat failed to start\n\n"
                "Filebeat did not come up, so it can't ship alerts to the indexer at all.\n\n"
                "Manual fix:\nCheck `journalctl -u filebeat` and /var/log/filebeat/filebeat for startup errors."
            )
            response["done"] = True
            return response
        return _run_test_and_branch(response, context, prefix="[OK] Filebeat is running.\n\n")

    if stage == "fix_version_choice":
        return _apply_fix(
            response, context, choice,
            auto_fn=fix_unsupported_filebeat_version,
            manual_instructions=manual_unsupported_version_instructions(),
            manual_wait_stage="fix_version_manual_wait",
            issue_label="unsupported Filebeat version",
        )

    if stage == "fix_version_manual_wait":
        return _run_test_and_branch(response, context, prefix="")

    if stage == "fix_tls_choice":
        return _apply_fix(
            response, context, choice,
            auto_fn=lambda: regenerate_and_redeploy_certs(),
            manual_instructions=manual_cert_redeploy_instructions(),
            manual_wait_stage="fix_tls_manual_wait",
            issue_label="TLS/certificate error",
        )

    if stage == "fix_tls_manual_wait":
        return _run_test_and_branch(response, context, prefix="")

    response["display"] = "Invalid stage."
    response["done"] = True
    return response


# ---------------------------------------------------------------------------
def _check_service_and_test(response, context):
    response["display"] += ("\n" if response["display"] else "") + "Checking whether the Filebeat service is running..."
    status = get_service_status("filebeat")
    if status != "active":
        response["display"] += "\n[WARNING] Filebeat is not running."
        response["ask"] = ["Auto", "Manual"]
        context["stage"] = "fix_service_start"
        return response
    response["display"] += "\n[OK] Filebeat is running."
    return _run_test_and_branch(response, context, prefix="")


def _run_test_and_branch(response, context, prefix=""):
    test = run_filebeat_output_test()
    response["display"] += f"\n{prefix}Running `filebeat test output`...\n{test['raw']}\n"

    if not test["ok"]:
        return _diagnose_failure(response, context, test["raw"])

    return _check_logs_after_success(response, context, prefix="[OK] The output test succeeded.")


def _check_logs_after_success(response, context, prefix=""):
    # A clean output test only proves connectivity - it doesn't rule out
    # something like a field-mapping error that only shows up in the log
    # (or as a dashboard shard-failure popup), so check the log even when
    # the test itself passed.
    response["display"] += f"\n{prefix}\n\nChecking the Filebeat log for anything the connectivity test wouldn't catch..."
    errors = get_filebeat_log_errors()

    if not errors.strip():
        response["display"] += (
            "\n[OK] No error/warning lines found in the Filebeat log either - there's no "
            "further automated diagnosis we can run from here. If you're still seeing an "
            f"issue, please reach out to the official Wazuh community:\n{WAZUH_COMMUNITY_URL}"
        )
        response["done"] = True
        return response

    if _looks_like_mapping_issue(errors):
        response["display"] += f"\n\nRecent Filebeat log errors:\n{errors}"
        return _mapping_handoff(response)

    explanation = ai_explain(UNKNOWN_FAILURE_SYSTEM_PROMPT, errors)
    response["display"] += (
        f"\n\n[WARNING] Found error/warning lines in the Filebeat log even though the "
        f"connectivity test passed:\n{errors}\n\nAI analysis:\n{explanation}\n\n"
        f"If this doesn't resolve it, please reach out to the official Wazuh community:\n{WAZUH_COMMUNITY_URL}"
    )
    response["done"] = True
    return response


def _diagnose_failure(response, context, test_raw):
    errors = get_filebeat_log_errors()
    combined = f"{test_raw}\n{errors}"

    if _looks_like_mapping_issue(combined):
        response["display"] += f"\nRecent Filebeat log errors:\n{errors if errors else '(none found)'}"
        return _mapping_handoff(response)

    category = classify_filebeat_failure(test_raw, errors)

    if category == "indexer_unreachable":
        response["display"] += (
            "\n[WARNING] Filebeat cannot reach the Wazuh Indexer. This isn't a Filebeat "
            "problem by itself - please use the \"Cluster Health Issues\" card to check the "
            "Wazuh Indexer directly."
        )
        response["done"] = True
        return response

    if category == "unsupported_version":
        context["stage"] = "fix_version_choice"
        response["display"] += (
            "\n[ISSUE] This looks like an unsupported Filebeat version. Wazuh is only "
            "compatible with Filebeat-OSS 7.10.2 - a newer version fails with errors like "
            "'invalid_index_name_exception' on the _license index.\n\n"
            "Would you like us to fix this automatically, or fix it yourself?"
        )
        response["ask"] = ["Auto", "Manual"]
        return response

    if category == "tls_cert_error":
        context["stage"] = "fix_tls_choice"
        response["display"] += (
            "\n[ISSUE] This looks like a TLS/certificate error. The fix is to regenerate the "
            "certificates and redeploy them to the Wazuh Indexer, Filebeat, and Wazuh Dashboard.\n\n"
            "Would you like us to fix this automatically, or fix it yourself?"
        )
        response["ask"] = ["Auto", "Manual"]
        return response

    # auth_failure / unknown - no scripted fix, surface what we know and stop.
    explanation = ai_explain(UNKNOWN_FAILURE_SYSTEM_PROMPT, combined) if errors.strip() else \
        "No additional error/warning lines found in the Filebeat log."
    label = "authentication failure" if category == "auth_failure" else "an unrecognized error"
    response["display"] += (
        f"\n[WARNING] The output test failed with what looks like {label}.\n\n"
        f"Recent Filebeat log errors:\n{errors if errors else '(none found)'}\n\n"
        f"AI analysis:\n{explanation}\n\n"
        f"If this doesn't resolve it, please reach out to the official Wazuh community:\n{WAZUH_COMMUNITY_URL}"
    )
    response["done"] = True
    return response


def _apply_fix(response, context, choice, auto_fn, manual_instructions, manual_wait_stage, issue_label):
    if "manual" in choice:
        context["stage"] = manual_wait_stage
        response["display"] = manual_instructions + "\n\nLet us know once you've made the change."
        response["ask"] = ["Done"]
        return response

    if "auto" not in choice:
        response["ask"] = ["Auto", "Manual"]
        return response

    result = auto_fn()
    if result.get("ok"):
        return _run_test_and_branch(
            response, context,
            prefix=f"Fixed the {issue_label} automatically.\n{result.get('log', '')}\n\n",
        )

    response["display"] = (
        f"[ROOT CAUSE FOUND] Could not auto-fix the {issue_label}\n\n"
        f"{result.get('log', '')}\n\n"
        "Manual fix:\n" + manual_instructions
    )
    response["done"] = True
    return response
