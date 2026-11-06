
import re
import datetime
from utils.api_utils import indexer_api_get, indexer_api_delete

_INDEX_DATE_RE = re.compile(r"(\d{4})\.(\d{2})\.(\d{2})")


def list_indices(pattern="wazuh-alerts-*"):
    raw = indexer_api_get(
        f"/_cat/indices/{pattern}?h=index,health,status,docs.count,store.size"
    ) or ""
    rows = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            rows.append({
                "index": parts[0], "health": parts[1], "status": parts[2],
                "docs_count": parts[3], "store_size": parts[4],
            })
    return rows


def index_has_todays_date(pattern="wazuh-alerts-*"):
    today = datetime.date.today().strftime("%Y.%m.%d")
    return any(today in row["index"] for row in list_indices(pattern))


def _index_date(index_name):
    m = _INDEX_DATE_RE.search(index_name)
    if not m:
        return None
    try:
        return datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def _freshness_result(index_name, index_date):
    if not index_name or not index_date:
        return {"index": index_name, "date": None, "days_old": None, "is_today": False}
    days_old = (datetime.date.today() - index_date).days
    return {"index": index_name, "date": index_date, "days_old": days_old, "is_today": days_old <= 0}


def check_most_recent_index(pattern="wazuh-alerts-*"):
    """
    Find the newest index matching `pattern` by its date suffix (not creation
    time - the suffix is what tells us whether TODAY's alerts are landing).
    Returns {"index", "date", "days_old", "is_today"} - all None/False if no
    index in the pattern has a parseable date suffix.
    """
    best_name, best_date = None, None
    for row in list_indices(pattern):
        d = _index_date(row["index"])
        if d and (best_date is None or d > best_date):
            best_name, best_date = row["index"], d
    return _freshness_result(best_name, best_date)


def check_index_name_freshness(index_name):
    """Same result shape as check_most_recent_index(), for a single index name
    a user typed/pasted in manually rather than one we looked up ourselves."""
    return _freshness_result(index_name, _index_date(index_name or ""))


def select_indices_by_age(pattern="wazuh-alerts-*", older_than_days=None, start_date=None, end_date=None):
    """
    Resolve a request like "older than 30 days" or "2026-01-01 to
    2026-01-07" into a concrete list of index rows, WITHOUT deleting
    anything. Callers must show this list to the user and get explicit
    confirmation before calling delete_indices().
    """
    indices = list_indices(pattern)
    today = datetime.date.today()
    cutoff = today - datetime.timedelta(days=older_than_days) if older_than_days else None

    matched = []
    for row in indices:
        d = _index_date(row["index"])
        if d is None:
            continue
        if cutoff and d >= cutoff:
            continue
        if start_date and d < start_date:
            continue
        if end_date and d > end_date:
            continue
        matched.append(row)
    return matched


def delete_indices(index_names):
    """Delete an explicit list of indices. Caller must have already shown & confirmed this exact list."""
    return {name: indexer_api_delete(f"/{name}") for name in index_names}
