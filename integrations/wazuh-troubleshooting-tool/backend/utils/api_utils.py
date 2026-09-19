"""
Generic helpers for calling the Wazuh indexer's REST API with auth already
applied, so use cases don't each re-implement request/auth/error handling.

Reusable by any use case that needs to hit the indexer API (cluster health,
cat indices, cat shards, allocation explain, settings changes, reindex,
deletes, etc.).
"""

import json

import requests
import urllib3

from config import INDEXER_USERNAME, INDEXER_PASSWORD, INDEXER_URL

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_AUTH = (INDEXER_USERNAME, INDEXER_PASSWORD)


def _request(method, endpoint, json_body=None):
    """
    `endpoint` should start with "/", e.g. "/_cluster/health".
    Returns the raw response text (empty string on failure).
    """
    try:
        resp = requests.request(
            method,
            f"{INDEXER_URL}{endpoint}",
            auth=_AUTH,
            json=json_body,
            verify=False,
            timeout=15,
        )
        return resp.text
    except requests.RequestException:
        return ""


def indexer_api_get(endpoint):
    """GET a path from the indexer's REST API (e.g. "/_cluster/health")."""
    return _request("GET", endpoint)


def indexer_api_get_json(endpoint):
    """
    Same as indexer_api_get, but parses the response as JSON.

    Returns (parsed_json, raw_text). If parsing fails, parsed_json is None
    and raw_text is preserved so the caller can still show it to the user
    for diagnosis (e.g. "the indexer isn't reachable, here's the raw error").
    """
    raw = indexer_api_get(endpoint)
    try:
        return json.loads(raw), raw
    except (ValueError, TypeError):
        return None, raw


def indexer_api_put(endpoint, json_body=None):
    """PUT to the indexer's REST API. `json_body`, if given, is sent as JSON."""
    return _request("PUT", endpoint, json_body)


def indexer_api_post(endpoint, json_body=None):
    """Same as indexer_api_put but for POST (used for _reindex, _search, allocation/explain)."""
    return _request("POST", endpoint, json_body)


def indexer_api_post_json(endpoint, json_body=None):
    """Same as indexer_api_post, but parses the response as JSON."""
    raw = indexer_api_post(endpoint, json_body)
    try:
        return json.loads(raw), raw
    except (ValueError, TypeError):
        return None, raw


def indexer_api_delete(endpoint):
    """DELETE a path from the indexer's REST API (e.g. an index name)."""
    return _request("DELETE", endpoint)
