class LogAnalyzer:

    # -----------------------------------------
    # DETECT KNOWN ISSUES FROM LOG TEXT
    # Returns a list of issue keys found in the logs
    # e.g. ["heap", "auth"]
    # -----------------------------------------
    @staticmethod
    def get_issues(logs):
        if not logs:
            return []

        text   = logs.lower()
        issues = []

        # NOT INITIALIZED
        # Only relevant on fresh/new installations
        if "not yet initialized" in text:
            issues.append("init")

        # HEAP / MEMORY
        # Can be fixed auto or manual — handled in dashboard_error_flow
        if any(kw in text for kw in [
            "circuit_breaking_exception",
            "data too large",
            "high heap usage",
            "gc did bring memory usage down",
            "g1gc",
            "heap usage",
        ]):
            issues.append("heap")

        # AUTH FAILURE
        # Flag only — fix steps to be added later
        if "authentication finally failed for kibanaserver" in text:
            issues.append("auth")

        # DISK WATERMARK
        # Inform only — user must free up disk manually
        if any(kw in text for kw in [
            "low disk watermark",
            "high disk watermark",
            "flood stage disk watermark",
            "disk usage exceeded",
        ]):
            issues.append("watermark")

        # FILE PERMISSIONS
        # Flag only — fix steps to be added later
        if "insecure file permissions" in text:
            issues.append("permission")
        if any(kw in text for kw in [
            "econnrefused",
            "connectionerror",
            "connect econnrefused",
        ]):
            issues.append("dashboard_connection_refused")
        return issues
