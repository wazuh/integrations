"""
Generic helpers for calling the Wazuh indexer's REST API with auth already
applied, so use cases don't each re-type the same
`curl -k -s -u USER:PASS URL` boilerplate by hand.

Reusable by any use case that needs to hit the indexer API (cluster health,
cat indices, cat shards, allocation explain, settings changes, reindex,
deletes, etc.).
"""

import json
import tempfile

from executor import run_command
from config import INDEXER_USERNAME, INDEXER_PASSWORD, INDEXER_URL


def _write_temp_json(data):
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(data, tmp)
    tmp.close()
    return tmp.name


def indexer_api_get(endpoint, extra_args=""):
    """
    GET a path from the indexer's REST API.

    `endpoint` should start with "/", e.g. "/_cluster/health".
    `extra_args` lets callers pass extra curl flags/query params if needed.
    Returns the raw response text (empty string on failure).
    """
    url = f"{INDEXER_URL}{endpoint}"
    cmd = f"curl -k -s -u {INDEXER_USERNAME}:'{INDEXER_PASSWORD}' {extra_args} {url}"
    return run_command(cmd) or ""


def indexer_api_get_json(endpoint, extra_args=""):
    """
    Same as indexer_api_get, but parses the response as JSON.

    Returns (parsed_json, raw_text). If parsing fails, parsed_json is None
    and raw_text is preserved so the caller can still show it to the user
    for diagnosis (e.g. "the indexer isn't reachable, here's the raw error").
    """
    raw = indexer_api_get(endpoint, extra_args)
    try:
        return json.loads(raw), raw
    except (ValueError, TypeError):
        return None, raw


def indexer_api_put(endpoint, json_body=None, extra_args=""):
    """
    PUT to the indexer's REST API. `json_body`, if given, is written to a
    temp file and sent with --data @file (avoids shell-quoting issues that
    come from inlining JSON directly into a curl string).
    """
    url = f"{INDEXER_URL}{endpoint}"
    if json_body is not None:
        path = _write_temp_json(json_body)
        cmd = (
            f"curl -k -s -u {INDEXER_USERNAME}:'{INDEXER_PASSWORD}' "
            f"-X PUT -H 'Content-Type: application/json' --data @{path} {extra_args} {url}"
        )
        raw = run_command(cmd) or ""
        run_command(f"rm -f {path}")
        return raw

    cmd = f"curl -k -s -u {INDEXER_USERNAME}:'{INDEXER_PASSWORD}' -X PUT {extra_args} {url}"
    return run_command(cmd) or ""


def indexer_api_post(endpoint, json_body=None, extra_args=""):
    """Same as indexer_api_put but for POST (used for _reindex, _search, allocation/explain)."""
    url = f"{INDEXER_URL}{endpoint}"
    if json_body is not None:
        path = _write_temp_json(json_body)
        cmd = (
            f"curl -k -s -u {INDEXER_USERNAME}:'{INDEXER_PASSWORD}' "
            f"-X POST -H 'Content-Type: application/json' --data @{path} {extra_args} {url}"
        )
        raw = run_command(cmd) or ""
        run_command(f"rm -f {path}")
        return raw

    cmd = f"curl -k -s -u {INDEXER_USERNAME}:'{INDEXER_PASSWORD}' -X POST {extra_args} {url}"
    return run_command(cmd) or ""


def indexer_api_post_json(endpoint, json_body=None, extra_args=""):
    """Same as indexer_api_post, but parses the response as JSON."""
    raw = indexer_api_post(endpoint, json_body, extra_args)
    try:
        return json.loads(raw), raw
    except (ValueError, TypeError):
        return None, raw


def indexer_api_delete(endpoint, extra_args=""):
    """DELETE a path from the indexer's REST API (e.g. an index name)."""
    url = f"{INDEXER_URL}{endpoint}"
    cmd = f"curl -k -s -u {INDEXER_USERNAME}:'{INDEXER_PASSWORD}' -X DELETE {extra_args} {url}"
    return run_command(cmd) or ""
