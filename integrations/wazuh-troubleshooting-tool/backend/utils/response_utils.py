"""
Generic response-dict builder.

Every use-case flow needs to return the same shape of dict back to the
frontend: {"display": ..., "ask": ..., "done": ..., "context": ...}. Without
a shared helper, every flow ends up hand-building this slightly differently
(missing a key, forgetting to default "ask" to a list, etc). Use this
instead of constructing the dict by hand.
"""


def make_response(display, ask=None, context=None, done=False, handoff=False):
    """
    Build a standard flow response.

    display : str  - the message to show the user.
    ask     : list  - the question(s) being asked (empty list if none).
    context : dict  - the flow's context/state, carried forward.
    done    : bool  - True if the troubleshooting flow is finished.
    handoff : bool  - True if control should be handed back to a parent
                       flow to continue at context["stage"] (used by
                       sub-flows like utils/step_flow.py).
    """
    return {
        "display": display,
        "ask":     ask or [],
        "done":    done,
        "context": context if context is not None else {},
        "handoff": handoff,
    }
