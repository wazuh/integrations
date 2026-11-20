"""Deterministic JSON and text output: sorted keys, LF, UTF-8, final newline."""

import hashlib
import json
import os


def dumps(obj, sort_keys=True):
    return json.dumps(obj, sort_keys=sort_keys, indent=2, ensure_ascii=False) + "\n"


def write_json(path, obj, sort_keys=True):
    write_text(path, dumps(obj, sort_keys=sort_keys))


def write_text(path, text):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.replace(tmp, path)


def read_json(path, ordered=False):
    with open(path, "r", encoding="utf-8") as fh:
        if ordered:
            from collections import OrderedDict

            return json.load(fh, object_pairs_hook=OrderedDict)
        return json.load(fh)


def canonical_sha256(obj):
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()
