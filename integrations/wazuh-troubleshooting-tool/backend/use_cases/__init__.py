from rapidfuzz import fuzz

# -------------------------------------------------------------
# REGISTERED USE CASES
# -------------------------------------------------------------
USE_CASES = [
    {
        "name": "Dashboard Error",
        "phrases": [
            "dashboard server is not ready yet",
            "wazuh dashboard is not ready",
            "dashboard not ready",
            "dashboard cannot connect to indexer",
            "wazuh dashboard is not ready yet",
            "dashboard connectivity problems",
            "application not found"
        ],
        "handler": "dashboard_error"
    },
    {
        "name": "Alerts Not Showing",
        "phrases": [
            "alerts not showing on dashboard",
            "alerts not showing",
            "no alerts",
            "alerts missing"
        ],
        "handler": "alerts_not_showing"
    },
    {
        "name": "Alerts Not Indexing",
        "phrases": [
            "alerts not indexing",
            "indexing error",
            "not indexing"
        ],
        "handler": "indexing_error"
    },
    {
        "name": "Missing API Username",
        "phrases": [
            "could not connect to api - missing api username",
            "missing api username",
            "api username error",
            "api connectivity issues",
            "could not connect to api"
        ],
        "handler": "api_error"
    },
    {
        "name": "Cluster Health Issues",
        "phrases": [
            "cluster health issues",
            "cluster issues",
            "cluster status yellow",
            "cluster status red",
            "cluster error"
        ],
        "handler": "cluster_issues"
    },
    {
        "name": "Indexer Problems",
        "phrases": [
            "indexer problems",
            "indexer is not running",
            "wazuh-indexer not running",
            "indexer down"
        ],
        "handler": "indexing_error"
    }
]


# -------------------------------------------------------------
# FUZZY MATCHER
# -------------------------------------------------------------
def best_match(user_input: str):
    text       = user_input.lower()
    best       = None
    best_score = 0

    for uc in USE_CASES:
        for phrase in uc["phrases"]:
            score = fuzz.token_set_ratio(text, phrase)
            if score > best_score:
                best_score = score
                best       = uc

    return best, best_score


# -------------------------------------------------------------
# MAIN ROUTER
# -------------------------------------------------------------
def run_use_cases(user_input, context):

    # ---------------------------------------------------------
    # PRIORITY: if there is already an active flow in progress,
    # skip keyword matching entirely and continue that flow.
    # ---------------------------------------------------------
    if context and context.get("stage"):
        handler = context.get("handler", "dashboard_error")

        if handler == "dashboard_error":
            from .dashboard_error import dashboard_error_flow
            return dashboard_error_flow(user_input, context)
        elif handler == "indexing_error":
            from .indexing_error import indexing_error_flow
            return indexing_error_flow(user_input, context)
        elif handler == "api_error":
            from .api_error import api_error_flow
            return api_error_flow(user_input, context)
        elif handler == "alerts_not_showing":
            from .alerts_not_showing import alerts_not_showing_flow
            return alerts_not_showing_flow(user_input, context)
        elif handler == "cluster_issues":
            from .cluster_issues import cluster_issues_flow
            return cluster_issues_flow(user_input, context)

        return None

    # ---------------------------------------------------------
    # No active flow — try to match a new use case by keyword
    # ---------------------------------------------------------
    uc, score = best_match(user_input)

    if uc and score >= 65:
        handler = uc["handler"]
        
        if handler == "dashboard_error":
            from .dashboard_error import dashboard_error_flow
            result = dashboard_error_flow(None, {})
        elif handler == "indexing_error":
            from .indexing_error import indexing_error_flow
            result = indexing_error_flow(None, {})
        elif handler == "api_error":
            from .api_error import api_error_flow
            result = api_error_flow(None, {})
        elif handler == "alerts_not_showing":
            from .alerts_not_showing import alerts_not_showing_flow
            result = alerts_not_showing_flow(None, {})
        elif handler == "cluster_issues":
            from .cluster_issues import cluster_issues_flow
            result = cluster_issues_flow(None, {})
        else:
            return None

        # stamp the handler into context so follow-up messages know
        if result and result.get("context") is not None:
            result["context"]["handler"] = handler
        return result

    return None
