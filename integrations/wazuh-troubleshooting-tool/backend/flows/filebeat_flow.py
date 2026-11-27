"""
Step 3 of the alerts-not-showing pipeline: Filebeat.

Order: ask how to check -> (start Filebeat if it's down) -> run the output
test -> if it fails, classify WHY and offer an auto/manual fix for the
known causes -> hand off to Step 4 (Wazuh Indexer) once Filebeat can talk
to the indexer, or immediately if the failure itself says the indexer is
unreachable (no point iterating on Filebeat if the indexer is the problem).

This module owns everything specific to Filebeat: what to check, why we're
checking it, what the manual instructions are, how to fix each known
failure category. It hands off to the caller (use_cases/no_alerts_are_showing.py)
by setting context["stage"] = STEP4_ENTRY_STAGE and returning handoff=True,
the same pattern used by flows/ip_cert_flow.py and flows/dashboard_ip_cert_flow.py.

Also reused standalone by use_cases/filebeat_error.py, a Filebeat-only
troubleshooting card that stops on handoff instead of continuing into the
indexer/cluster steps.
"""

from utils.response_utils import make_response
from utils.service_utils import get_service_status, start_service_and_wait
from utils.filebeat_utils import (
    run_filebeat_output_test, get_filebeat_log_errors, classify_filebeat_failure,
    fix_unsupported_filebeat_version, manual_unsupported_version_instructions,
)
from utils.cert_utils import regenerate_and_redeploy_certs, manual_cert_redeploy_instructions
from utils.ai_utils import ai_explain

ENTRY_STAGE = "step3_method"
STEP4_ENTRY_STAGE = "step4_entry"

STAGES = {
    ENTRY_STAGE,
    "step3_manual_wait",
    "fix_filebeat_start",
    "step3_fix_version_choice",
    "step3_fix_version_manual_wait",
    "step3_fix_tls_choice",
    "step3_fix_tls_manual_wait",
}

WHY_TEXT = (
    "The Wazuh Manager is generating alerts correctly. The next step is to "
    "verify whether Filebeat is reading those alerts and forwarding them to "
    "the Wazuh Indexer. If Filebeat is not working, alerts will never reach "
    "the indexer or the dashboard."
)

MANUAL_CHECK_TEXT = (
    "First, check whether the Filebeat service is running:\n\n"
    "    systemctl status filebeat\n\n"
    "If Filebeat is active, test its connection to the Wazuh Indexer:\n\n"
    "    filebeat test output\n\n"
    "Did the output test succeed?"
)

UNKNOWN_FAILURE_SYSTEM_PROMPT = (
    "You are a Wazuh Filebeat troubleshooting expert. You'll be given the "
    "output of 'filebeat test output' plus recent filebeat log error/warning "
    "lines. In 3-4 short sentences: state the most likely root cause and the "
    "single most useful next command or config fix. Be specific to what's "
    "actually in the output - don't give generic advice."
)


def start_filebeat_flow(context):
    context["stage"] = ENTRY_STAGE
    return make_response(
        display=(
            "Step 3 - Check Filebeat:\n\n"
            f"{WHY_TEXT}\n\n"
            "How would you like to check this?\n\n"
            "  Auto   - We perform all checks automatically.\n"
            "  Manual - We provide the commands, and you run them and share the output."
        ),
        ask=["Auto", "Manual"],
        context=context,
    )


def filebeat_flow(user_choice=None, context=None):
    if context is None:
        context = {}
    choice = (user_choice or "").strip().lower()
    stage = context.get("stage")

    if stage == ENTRY_STAGE:
        if "manual" in choice:
            context["stage"] = "step3_manual_wait"
            return make_response(
                display=MANUAL_CHECK_TEXT,
                ask=["Yes, it succeeded", "No, it failed"],
                context=context,
            )
        return _auto_check(context)

    if stage == "step3_manual_wait":
        if "yes" in choice or "succeeded" in choice:
            return make_response(
                display="[OK] Good - Filebeat can reach the indexer.",
                context=_handoff_to_step4(context),
                handoff=True,
            )
        # Self-reported failure - we still need real data to know why, so
        # run the same diagnosis the auto path uses.
        return _auto_check(context)

    if stage == "fix_filebeat_start":
        if "auto" in choice:
            status = start_service_and_wait("filebeat")
        elif choice == "done":
            status = get_service_status("filebeat")
        elif "manual" in choice:
            return make_response(
                display="Run: systemctl start filebeat",
                ask=["Done"],
                context=context,
            )
        else:
            return make_response(display="How would you like to start it?", ask=["Auto", "Manual"], context=context)

        if status != "active":
            return make_response(
                display=(
                    "[ROOT CAUSE FOUND] Filebeat failed to start\n\n"
                    "Filebeat did not come up, so alerts.json can never be shipped to the indexer.\n\n"
                    "Manual fix:\nCheck `journalctl -u filebeat` and /var/log/filebeat/filebeat for startup errors."
                ),
                done=True,
                context=context,
            )
        return _run_test_and_branch(context, prefix="[OK] Filebeat is running.\n\n")

    if stage == "step3_fix_version_choice":
        return _apply_fix(
            context, choice,
            auto_fn=fix_unsupported_filebeat_version,
            manual_instructions=manual_unsupported_version_instructions(),
            manual_wait_stage="step3_fix_version_manual_wait",
            issue_label="unsupported Filebeat version",
        )

    if stage == "step3_fix_version_manual_wait":
        return _run_test_and_branch(context, prefix="")

    if stage == "step3_fix_tls_choice":
        return _apply_fix(
            context, choice,
            auto_fn=lambda: regenerate_and_redeploy_certs(),
            manual_instructions=manual_cert_redeploy_instructions(),
            manual_wait_stage="step3_fix_tls_manual_wait",
            issue_label="TLS/certificate error",
        )

    if stage == "step3_fix_tls_manual_wait":
        return _run_test_and_branch(context, prefix="")

    return make_response(display="Unexpected Filebeat step.", done=True, context=context)


# ---------------------------------------------------------------------------
# internal helpers
# ---------------------------------------------------------------------------
def _handoff_to_step4(context):
    context["stage"] = STEP4_ENTRY_STAGE
    return context


def _auto_check(context):
    status = get_service_status("filebeat")
    if status != "active":
        context["stage"] = "fix_filebeat_start"
        return make_response(
            display=(
                "Automatically checking Filebeat...\n\n"
                "[WARNING] Filebeat is not running.\n\n"
                "How would you like to start it?"
            ),
            ask=["Auto", "Manual"],
            context=context,
        )
    return _run_test_and_branch(context, prefix="Automatically checking Filebeat...\n\n[OK] Filebeat is running.\n\n")


def _run_test_and_branch(context, prefix=""):
    test = run_filebeat_output_test()
    display = f"{prefix}Running output test...\n{test['raw']}\n"

    if test["ok"]:
        display += (
            "\n[OK] Filebeat is running correctly and can successfully communicate with "
            "the Wazuh Indexer. We will now verify that the Wazuh Indexer is healthy."
        )
        return make_response(display=display, context=_handoff_to_step4(context), handoff=True)

    errors = get_filebeat_log_errors()
    category = classify_filebeat_failure(test["raw"], errors)

    if category == "indexer_unreachable":
        display += (
            "\n[WARNING] Filebeat cannot reach the Wazuh Indexer. This isn't a Filebeat "
            "problem by itself, so we're moving straight to checking the Wazuh Indexer "
            "instead of continuing to troubleshoot Filebeat."
        )
        return make_response(display=display, context=_handoff_to_step4(context), handoff=True)

    if category == "unsupported_version":
        context["stage"] = "step3_fix_version_choice"
        display += (
            "\n[ISSUE] This looks like an unsupported Filebeat version. Wazuh is only "
            "compatible with Filebeat-OSS 7.10.2 - a newer version will fail with errors "
            "like 'invalid_index_name_exception' on the _license index.\n\n"
            "Would you like us to fix this automatically, or fix it yourself?"
        )
        return make_response(display=display, ask=["Auto", "Manual"], context=context)

    if category == "tls_cert_error":
        context["stage"] = "step3_fix_tls_choice"
        display += (
            "\n[ISSUE] This looks like a TLS/certificate error. The fix is to regenerate "
            "the certificates and redeploy them to the Wazuh Indexer, Filebeat, and Wazuh "
            "Dashboard.\n\n"
            "Would you like us to fix this automatically, or fix it yourself?"
        )
        return make_response(display=display, ask=["Auto", "Manual"], context=context)

    # auth_failure / unknown - no scripted fix, surface what we know and stop.
    explanation = ai_explain(UNKNOWN_FAILURE_SYSTEM_PROMPT, f"{test['raw']}\n{errors}") if errors.strip() else \
        "No additional error/warning lines found in the Filebeat log."
    label = "authentication failure" if category == "auth_failure" else "an unrecognized error"
    display += (
        f"\n[WARNING] The output test failed with what looks like {label}.\n\n"
        f"Recent Filebeat log errors:\n{errors if errors else '(none found)'}\n\n"
        f"AI analysis:\n{explanation}"
    )
    return make_response(display=display, done=True, context=context)


def _apply_fix(context, choice, auto_fn, manual_instructions, manual_wait_stage, issue_label):
    if "manual" in choice:
        context["stage"] = manual_wait_stage
        return make_response(
            display=manual_instructions + "\n\nLet us know once you've made the change.",
            ask=["Done"],
            context=context,
        )

    result = auto_fn()
    if result.get("ok"):
        return _run_test_and_branch(
            context,
            prefix=f"Fixed the {issue_label} automatically.\n{result.get('log', '')}\n\n",
        )

    return make_response(
        display=(
            f"[ROOT CAUSE FOUND] Could not auto-fix the {issue_label}\n\n"
            f"{result.get('log', '')}\n\n"
            "Manual fix:\n" + manual_instructions
        ),
        done=True,
        context=context,
    )
