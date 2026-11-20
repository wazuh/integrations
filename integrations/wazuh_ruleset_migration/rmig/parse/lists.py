"""Parser of CDB list sources (``wazuh@4.14.13:src/analysisd/lists_make.c:61-140``)."""

import hashlib

from .. import model4 as m


def normalized_bytes(data):
    """Content used for the sha256 of a list: CRLF folded to LF."""
    return data.replace(b"\r\n", b"\n")


def list_sha256(data):
    return hashlib.sha256(normalized_bytes(data)).hexdigest()


def split_entry(line):
    """Split ``key:value``; key or value may be quoted. Returns (key, value) or
    None when the line has no separator."""
    if line.startswith('"'):
        end = line.find('"', 1)
        if end < 0:
            return None
        key = line[1:end]
        rest = line[end + 1:]
        if not rest.startswith(":"):
            return None
        value = rest[1:]
    else:
        pos = line.find(":")
        if pos < 0:
            return None
        key, value = line[:pos], line[pos + 1:]
    if value.startswith('"') and value.endswith('"') and len(value) >= 2:
        value = value[1:-1]
    return key, value


def parse_list_bytes(data, rel, name):
    text = normalized_bytes(data).decode("utf-8", "replace")
    entries = 0
    prefix = []
    keys = []
    for line in text.split("\n"):
        kv = split_entry(line)
        if kv is None:
            continue
        entries += 1
        key = kv[0]
        if len(keys) < 5:
            keys.append(key)
        if key.endswith("."):
            prefix.append(key)
    return {
        "kind": m.LIST,
        "file": rel,
        "line": 1,
        "name": name,
        "sha256": list_sha256(data),
        "entries": entries,
        "prefix_keys": sorted(prefix)[:20],
        "prefix_key_count": len(prefix),
        "sample_keys": keys,
    }
