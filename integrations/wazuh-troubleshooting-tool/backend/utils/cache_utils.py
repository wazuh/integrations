"""
Tiny generic in-memory TTL cache.

Reusable by any utility function that reads something slow or expensive but
relatively stable for the duration of a troubleshooting session (e.g.
reading a value out of a tar archive that lives on a slow filesystem, or
querying an API endpoint that doesn't need to be hit on every single check).

Not persistent, not distributed - just enough to stop re-doing the same
slow work repeatedly within one running process.
"""

import time

_cache = {}


def cached(key, compute_fn, ttl=300):
    """
    Return the cached value for `key` if it's younger than `ttl` seconds;
    otherwise call compute_fn(), cache the result, and return it.
    """
    now = time.time()
    entry = _cache.get(key)
    if entry and (now - entry[0]) < ttl:
        return entry[1]
    value = compute_fn()
    _cache[key] = (now, value)
    return value


def clear_cache(key=None):
    """Clear one cached key, or the whole cache if key is None."""
    if key is None:
        _cache.clear()
    else:
        _cache.pop(key, None)
