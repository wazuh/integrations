"""Read 4.14 alerts (``alerts.json``, rotated ``ossec-alerts-DD.json`` and
their ``.json.gz``): one JSON object per line."""

import gzip
import json


class AlertsError(Exception):
    pass


def read_alerts(paths):
    """``(alerts, problems)``: every parseable alert of the files in order,
    and ``file:line: reason`` for lines that are not."""
    alerts, problems = [], []
    for path in paths:
        opener = gzip.open if path.endswith(".gz") else open
        try:
            with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            raise AlertsError("cannot read %s: %s" % (path, exc))
        stripped = text.lstrip()
        if stripped.startswith("["):
            try:
                data = json.loads(stripped)
                alerts.extend(a for a in data if isinstance(a, dict))
                continue
            except ValueError:
                pass
        for n, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                problems.append("%s:%d: not JSON" % (path, n))
                continue
            if isinstance(obj, dict):
                alerts.append(obj)
    return alerts, problems


def rule_id(alert):
    return str(((alert.get("rule") or {}).get("id")) or "")


def original_log(alert):
    """The line 4.14 received, or None with the reason: ``no_full_log``
    rules have no ``full_log``; syscheck replaces it with its own text."""
    if alert.get("syscheck") is not None:
        return None, "syscheck alert: full_log is the alert text, not the original event"
    log = alert.get("full_log")
    if not isinstance(log, str) or not log:
        return None, "the alert has no full_log (rule with no_full_log?)"
    return log, None


def sort_key(alert):
    return (str(alert.get("timestamp") or ""), str(alert.get("id") or ""))
