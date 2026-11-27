"""
Shared "end of a troubleshooting flow" helper.

Every use-case flow eventually reaches a point where it either confirms
the user's problem is actually fixed, or runs out of automated steps
without confirming that. Call conclude() at that point instead of
building the final make_response(..., done=True) by hand, so both cases
are handled the same way everywhere: a clean success message on
resolution, or a best-effort suggestion (pulled from the local knowledge
base and a live public GitHub search) plus a pointer to the Wazuh
community when the automated steps didn't fix it.
"""

from utils.response_utils import make_response
from utils.lgtm_utils import find_relevant_issues, format_lgtm_context
from utils.public_repo_search import search_public_issues, search_public_discussions, format_public_context

COMMUNITY_POINTER = (
    "\n\nIf this didn't resolve your issue, you can also check the Wazuh community "
    "for similar reports and discussions: https://github.com/wazuh/wazuh/issues and "
    "https://github.com/wazuh/wazuh/discussions"
)


def _best_effort_suggestion(topic):
    """
    Look up related known issues (local knowledge base + live public GitHub
    search) for `topic` and format them into a short suggestion block.
    Never raises - a lookup failure just means no suggestion gets added.
    """
    try:
        lgtm_context = format_lgtm_context(find_relevant_issues(topic))
    except Exception:
        lgtm_context = ""

    try:
        public_context = format_public_context(
            search_public_issues(topic), search_public_discussions(topic)
        )
    except Exception:
        public_context = ""

    parts = [p for p in (lgtm_context, public_context) if p]
    if not parts:
        return ""
    return "\n\nHere's what I found from similar reports:\n\n" + "\n\n".join(parts)


def conclude(resolved, display, context, topic=None):
    """
    End a troubleshooting flow.

    resolved : bool - True only if a check actually confirmed the issue
               is gone, not just "we ran out of steps to try".
    display  : str  - the message built so far this turn.
    context  : dict - the flow's context, carried forward.
    topic    : str  - short description of the problem (e.g. "wazuh
               dashboard not loading"), used to search for related known
               issues when unresolved. Required when resolved is False.
    """
    if resolved:
        return make_response(display=display, done=True, context=context)

    suggestion = _best_effort_suggestion(topic or "")
    return make_response(
        display=display + suggestion + COMMUNITY_POINTER,
        done=True,
        context=context,
    )
