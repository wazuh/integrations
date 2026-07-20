"""
Generic, reusable, PERMISSION-GATED sequential check/fix engine.

Nothing here is specific to the Wazuh indexer, or to any one use case. Any
use case can define an ordered list of "steps" (e.g. IP address, cert
paths, heap memory - or, for a different use case, disk space, cluster
health, filebeat status, agent connectivity, whatever) and get the exact
same interaction pattern for free, instead of re-writing the same
ask/check/fix/restart state machine by hand every time.

THE PATTERN (identical for every step, in order):

  1. ASK:    "Should I check the <title>? (yes / manual)"
       yes    -> run the step's own check_fn() and report the real result.
       manual -> show manual_check_instructions_fn(), then ask the user to
                 self-report: "good to go" or "incorrect".

  2. If there's an issue (either from check_fn, or self-reported "incorrect"):
       ASK: "Do you want me to fix this? (yes / manually)"
         yes      -> run auto_fix_fn(), then ask "fixed or ongoing?"
         manually -> show manual_fix_instructions_fn(), wait for the user to
                     confirm they made the change, THEN restart (via
                     restart_fn, if provided), then ask "fixed or ongoing?"

  3. "fixed"   -> stop, done.
     "ongoing" -> move to the next step. If this was the last step, hand
                  off to whatever stage `next_stage_after_ongoing` points
                  at - the caller's own flow takes over from there.

Nothing runs silently or gets batched - every question is its own turn,
and only one check or fix action ever happens per turn.

HOW TO DEFINE A STEP
---------------------
Each step is a dict:

    {
        "key":   "ip",                          # short id, used in stage names
        "title": "indexer IP address",          # shown in questions to the user

        "check_fn": fn(context) -> (ok: bool, details: str)
            # Runs the real check. May read/write `context` to stash data
            # needed later (e.g. the correct IP, so auto_fix_fn can use it).

        "manual_check_instructions_fn": fn(context) -> str
            # Commands/steps the user can run themselves to check this.

        "auto_fix_fn": fn(context) -> (status: str, details: str)
            # Applies the fix. If the fix itself already restarts whatever
            # needs restarting (recommended - keeps status accurate), just
            # report that status here.

        "manual_fix_instructions_fn": fn(context) -> str
            # Steps the user can follow themselves to apply the fix.

        "restart_fn": fn(context) -> str,       # OPTIONAL
            # Called after the user confirms they made a manual fix, since
            # manual fixes don't restart anything themselves. Should
            # restart whatever's needed and return the resulting status
            # string. If omitted, no restart happens after a manual fix.
    }

USAGE
-----
    from utils.step_flow import stage_names, start_flow, run_step_flow

    MY_STEPS = [ {...}, {...} ]
    PREFIX = "myflow"
    MY_STAGES = stage_names(PREFIX, MY_STEPS)   # for routing in your use case

    def my_flow(user_choice=None, context=None):
        ...
        if context.get("stage") == "my_entry_stage":
            return start_flow(PREFIX, MY_STEPS, context)

        if context.get("stage") in MY_STAGES:
            return run_step_flow(PREFIX, MY_STEPS, "next_stage_name",
                                  user_choice=user_choice, context=context)
"""

from utils.response_utils import make_response


def stage_names(prefix, steps):
    """
    All stage names this engine will use for a given prefix + step list.
    Use this to build the routing set in the calling use-case flow, e.g.:

        SEQ_STAGES = stage_names("seq", STEPS)
        if context.get("stage") in SEQ_STAGES:
            return run_step_flow("seq", STEPS, "fetch_logs", ...)
    """
    names = set()
    for s in steps:
        key = s["key"]
        names.update({
            f"{prefix}_{key}_permission",
            f"{prefix}_{key}_manual_check",
            f"{prefix}_{key}_fix_permission",
            f"{prefix}_{key}_manual_fix_wait",
            f"{prefix}_{key}_fix_result",
        })
    return names


def start_flow(prefix, steps, context):
    """
    Kick off the flow at its first step. Call this once, from the calling
    use-case's own entry point, to begin the sequence.
    """
    return _start_step(prefix, steps, steps[0]["key"], context)


def run_step_flow(prefix, steps, next_stage_after_ongoing, user_choice=None, context=None):
    """
    Advance the flow by one turn based on context["stage"] and the user's
    answer. Returns a response built with make_response().
    """
    if context is None:
        context = {}

    choice = (user_choice or "").lower().strip()
    stage = context.get("stage")

    for step in steps:
        key = step["key"]
        title = step["title"]

        # -----------------------------------------------------------
        # "Should I check the <title>? (yes / manual)"
        # -----------------------------------------------------------
        if stage == f"{prefix}_{key}_permission":

            if "manual" in choice:
                context["stage"] = f"{prefix}_{key}_manual_check"
                instructions = step["manual_check_instructions_fn"](context)
                return make_response(
                    display=(
                        instructions
                        + "\n\nOnce you've checked, let me know: good to go, or incorrect?"
                    ),
                    ask=["Good to go, or incorrect? (good to go / incorrect)"],
                    context=context,
                )

            # "yes" (default) -> run the real check ourselves
            ok, details = step["check_fn"](context)
            header = f"Checking the {title}.\n\n{details}"

            if ok:
                return _advance_after_pass(prefix, steps, key, header, context, next_stage_after_ongoing)

            context["stage"] = f"{prefix}_{key}_fix_permission"
            return make_response(
                display=(
                    header + "\n\n[ISSUE] This doesn't look right.\n\n"
                    "Do you want me to fix this? (yes / manually)"
                ),
                ask=["Fix this? (yes / manually)"],
                context=context,
            )

        # -----------------------------------------------------------
        # "Good to go, or incorrect?" (after manual check instructions)
        # -----------------------------------------------------------
        if stage == f"{prefix}_{key}_manual_check":
            if "incorrect" in choice:
                context["stage"] = f"{prefix}_{key}_fix_permission"
                return make_response(
                    display="Do you want me to fix this? (yes / manually)",
                    ask=["Fix this? (yes / manually)"],
                    context=context,
                )

            # "good to go"
            return _advance_after_pass(prefix, steps, key, "", context, next_stage_after_ongoing)

        # -----------------------------------------------------------
        # "Do you want me to fix this? (yes / manually)"
        # -----------------------------------------------------------
        if stage == f"{prefix}_{key}_fix_permission":
            if "manual" in choice:
                context["stage"] = f"{prefix}_{key}_manual_fix_wait"
                instructions = step["manual_fix_instructions_fn"](context)
                return make_response(
                    display=instructions + "\n\nLet me know once you've made the change.",
                    ask=["Done making the change? (done)"],
                    context=context,
                )

            # "yes" -> apply the fix ourselves
            status, details = step["auto_fix_fn"](context)
            context["stage"] = f"{prefix}_{key}_fix_result"
            return make_response(
                display=details + "\n\nIs the issue fixed now, or still ongoing?",
                ask=["Fixed or ongoing? (fixed / ongoing)"],
                context=context,
            )

        # -----------------------------------------------------------
        # User confirmed they made the manual fix -> restart if configured
        # -----------------------------------------------------------
        if stage == f"{prefix}_{key}_manual_fix_wait":
            restart_fn = step.get("restart_fn")
            if restart_fn:
                status = restart_fn(context)
                restart_msg = f"Restarted (status: {status.upper()}).\n\n"
            else:
                restart_msg = ""

            context["stage"] = f"{prefix}_{key}_fix_result"
            return make_response(
                display=restart_msg + "Is the issue fixed now, or still ongoing?",
                ask=["Fixed or ongoing? (fixed / ongoing)"],
                context=context,
            )

        # -----------------------------------------------------------
        # "Fixed or ongoing?"
        # -----------------------------------------------------------
        if stage == f"{prefix}_{key}_fix_result":
            if "fixed" in choice:
                return make_response(display="Great! The issue is resolved.", done=True, context=context)

            # "ongoing" -> move to the next step
            return _advance(prefix, steps, key, "Understood, still ongoing.", context, next_stage_after_ongoing)

    return make_response(display="Unexpected step.", done=True, context=context)


# ---------------------------------------------------------------------------
# internal helpers
# ---------------------------------------------------------------------------
def _step_by_key(steps, key):
    for s in steps:
        if s["key"] == key:
            return s
    return None


def _next_step_key(steps, key):
    idx = [s["key"] for s in steps].index(key)
    return steps[idx + 1]["key"] if idx + 1 < len(steps) else None


def _start_step(prefix, steps, key, context):
    step = _step_by_key(steps, key)
    context["stage"] = f"{prefix}_{key}_permission"
    return make_response(
        display=f"Should I check the {step['title']}? (yes / manual)",
        ask=[f"Check the {step['title']}? (yes / manual)"],
        context=context,
    )


def _advance_after_pass(prefix, steps, key, header, context, next_stage_after_ongoing):
    """A check just passed (auto or self-reported) - move to the next step,
    or hand off to the caller's next stage if this was the last step."""
    nxt = _next_step_key(steps, key)
    if nxt:
        nxt_resp = _start_step(prefix, steps, nxt, context)
        prefix_msg = (header + "\n\n[OK] This looks correct.\n\n") if header else ""
        nxt_resp["display"] = prefix_msg + nxt_resp["display"]
        return nxt_resp

    # last step passed cleanly -> hand off to the caller's next stage
    # (e.g. the dashboard IP/cert flow), instead of just stopping here.
    tail = (header + "\n\n[OK] This looks correct. ") if header else ""
    context["stage"] = next_stage_after_ongoing
    return make_response(
        display=tail + "Everything checks out here! Let's move on to the next step.",
        context=context,
        handoff=True,
    )


def _advance(prefix, steps, key, prefix_msg, context, next_stage_after_ongoing):
    """A fix just happened and the issue is still ongoing - move to the next step."""
    nxt = _next_step_key(steps, key)
    if nxt:
        nxt_resp = _start_step(prefix, steps, nxt, context)
        nxt_resp["display"] = prefix_msg + "\n\n" + nxt_resp["display"]
        return nxt_resp

    # last step still ongoing -> hand off to the caller's next stage
    context["stage"] = next_stage_after_ongoing
    return make_response(
        display=prefix_msg + " Let's move on to the next step.",
        context=context,
        handoff=True,
    )
