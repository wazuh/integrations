"""Index of the user's stock 4.x ruleset.

No 4.x ruleset data ships with the tool. The index is built at run time from the
``ruleset/`` directory of the user's own 4.x manager (``--stock-dir``, default
``/var/ossec/ruleset``) and cached in the working directory as
``work/stock-index.json``. The element hash (:func:`element_sha256`) is the one
``load_order`` uses to tell an unchanged copy of a stock element from a modified
one, so both sides share this module.
"""

import hashlib
import json
import os

from . import fsutil
from .jsonio import canonical_sha256
from .parse.decoders import parse_decoders_text
from .parse.lists import parse_list_bytes
from .parse.rules import parse_rules_text

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
EQUIVALENCE_PATH = os.path.join(DATA_DIR, "stock-equivalence-4.14.json")

DEFAULT_STOCK_DIR = "/var/ossec/ruleset"
CACHE_NAME = "stock-index.json"
INDEX_VERSION = 1  # raise when the parsers or the entry layout change: an older cache is then rebuilt
STOCK_LABEL = "Wazuh 4.x stock ruleset: ruleset/rules, ruleset/decoders, ruleset/lists"
_PARTS = ("rules", "decoders", "lists")


class StockMissing(Exception):
    """No stock ruleset is available (exit 2)."""


# Keys that describe where an element is, not what it is.
_LOCATION_KEYS = ("file", "line")


def _strip_location(obj):
    if isinstance(obj, dict):
        return {k: _strip_location(v) for k, v in obj.items() if k not in _LOCATION_KEYS}
    if isinstance(obj, list):
        return [_strip_location(v) for v in obj]
    return obj


def normalized_element(item):
    """The element without its location: what the sha256 covers."""
    return _strip_location(item)


def element_sha256(item):
    return canonical_sha256(normalized_element(item))


def _rule_entry(rule):
    return {
        "file": os.path.basename(rule["file"]),
        "line": rule["line"],
        "id": rule["id"],
        "level": rule["level"],
        "attrs": rule["attrs"],
        "parents": rule["parents"],
        "group_string": rule["group_string"],
        "groups": rule["groups"],
        "decoded_as": rule["decoded_as"],
        "category": rule["category"],
        "conditions": _strip_location(rule["conditions"]),
        "fields": _strip_location(rule["fields"]),
        "lists": _strip_location(rule["lists"]),
        "correlation": rule["correlation"],
        "flags": rule["flags"],
        "sha256": element_sha256(rule),
    }


def _decoder_entry(dec):
    return {
        "file": os.path.basename(dec["file"]),
        "line": dec["line"],
        "name": dec["name"],
        "parent": dec["parent"],
        "type": dec["type"],
        "program_name": _strip_location(dec["program_name"]),
        "prematch": _strip_location(dec["prematch"]),
        "regex": _strip_location(dec["regex"]),
        "order": dec["order"],
        "plugin_decoder": dec["plugin_decoder"],
        "sha256": element_sha256(dec),
    }


def ruleset_dir(path):
    """The directory that holds ``rules/`` and ``decoders/``: ``path`` itself
    (``/var/ossec/ruleset``) or its ``ruleset/`` child (a source checkout)."""
    for cand in (path, os.path.join(path, "ruleset")):
        if os.path.isdir(os.path.join(cand, "rules")) and os.path.isdir(os.path.join(cand, "decoders")):
            return cand
    return None


def fingerprint(rdir):
    """sha256 over the names and bytes of every file the index reads."""
    h = hashlib.sha256()
    for part in _PARTS:
        base = os.path.join(rdir, part)
        for rel in fsutil.walk_files(base) if os.path.isdir(base) else []:
            if part != "lists" and not rel.endswith(".xml"):
                continue
            with open(os.path.join(base, rel), "rb") as fh:
                data = fh.read()
            h.update(("%s/%s|%d|" % (part, rel, len(data))).encode("utf-8"))
            h.update(data)
    return h.hexdigest()


def build_index(root, source_label=STOCK_LABEL):
    """Build the index from ``root`` (see :func:`ruleset_dir`)."""
    rdir = ruleset_dir(root) or os.path.join(root, "ruleset")
    rules_dir = os.path.join(rdir, "rules")
    dec_dir = os.path.join(rdir, "decoders")
    lists_dir = os.path.join(rdir, "lists")
    rules, decoders, lists = [], [], []
    rule_files, decoder_files = [], []
    problems = []
    for name in fsutil.listdir_sorted(rules_dir):
        if not name.endswith(".xml"):
            continue
        rule_files.append(name)
        parsed, prob = parse_rules_text(fsutil.read_text(os.path.join(rules_dir, name)), "ruleset/rules/" + name)
        if prob["errors"] or prob["unknown"]:
            problems.append({"file": name, "problems": prob})
        rules.extend(_rule_entry(r) for r in parsed)
    for name in fsutil.listdir_sorted(dec_dir):
        if not name.endswith(".xml"):
            continue
        decoder_files.append(name)
        parsed, prob = parse_decoders_text(fsutil.read_text(os.path.join(dec_dir, name)), "ruleset/decoders/" + name)
        if prob["errors"] or prob["unknown"]:
            problems.append({"file": name, "problems": prob})
        decoders.extend(_decoder_entry(d) for d in parsed)
    for rel in fsutil.walk_files(lists_dir) if os.path.isdir(lists_dir) else []:
        if rel.endswith(".cdb"):
            continue
        with open(os.path.join(lists_dir, rel), "rb") as fh:
            data = fh.read()
        item = parse_list_bytes(data, "ruleset/lists/" + rel, rel)
        lists.append({"name": rel, "sha256": item["sha256"], "entries": item["entries"]})
    return {
        "version": INDEX_VERSION,
        "source": source_label,
        "counts": {"rules": len(rules), "rule_files": len(rule_files), "decoders": len(decoders),
                   "decoder_files": len(decoder_files), "lists": len(lists)},
        "parse_problems": problems,
        "rule_files": rule_files,
        "decoder_files": decoder_files,
        "rules": rules,
        "decoders": decoders,
        "lists": lists,
    }


def dump_index(index):
    """Serialize with one element per line, so two indexes compare line by line."""
    out = ["{"]
    keys = sorted(index)
    for n, key in enumerate(keys):
        value = index[key]
        sep = "," if n < len(keys) - 1 else ""
        if isinstance(value, list) and value and isinstance(value[0], dict):
            out.append("  %s: [" % json.dumps(key))
            for i, el in enumerate(value):
                comma = "," if i < len(value) - 1 else ""
                out.append("    " + json.dumps(el, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + comma)
            out.append("  ]" + sep)
        else:
            out.append("  %s: %s%s" % (json.dumps(key), json.dumps(value, sort_keys=True, ensure_ascii=False), sep))
    out.append("}")
    return "\n".join(out) + "\n"


class StockIndex:
    """Lookups over the stock index."""

    def __init__(self, data):
        self.data = data
        self.source = data.get("source")
        self.rules = data["rules"]
        self.decoders = data["decoders"]
        self.lists = data["lists"]
        self.rule_files = list(data["rule_files"])
        self.decoder_files = list(data["decoder_files"])
        self.rules_by_file = {}
        for r in self.rules:
            self.rules_by_file.setdefault(r["file"], []).append(r)
        self.decoders_by_file = {}
        for d in self.decoders:
            self.decoders_by_file.setdefault(d["file"], []).append(d)
        self.rules_by_id = {}
        for r in self.rules:
            self.rules_by_id.setdefault(r["id"], []).append(r)
        self.decoder_names = {}
        for d in self.decoders:
            self.decoder_names.setdefault(d["name"], []).append(d)
        self.decoder_sha = {}
        for d in self.decoders:
            self.decoder_sha.setdefault(d["sha256"], []).append(d)
        self.list_sha = {}
        for li in self.lists:
            self.list_sha.setdefault(li["sha256"], []).append(li)

    @staticmethod
    def rule_uid(entry):
        return "stock-rule:%s:%d" % (entry["file"], entry["line"])

    @staticmethod
    def decoder_uid(entry):
        return "stock-decoder:%s:%d" % (entry["file"], entry["line"])


_ACTIVE = {"index": None}


def set_active(index):
    """Make ``index`` (a :class:`StockIndex` or None) the one every lookup uses."""
    _ACTIVE["index"] = index
    return index


def active():
    return _ACTIVE["index"]


def cache_path(workdir):
    return os.path.join(workdir, "work", CACHE_NAME)


def use_stock_dir(stock_dir, workdir=None):
    """Index ``stock_dir`` (reusing the workdir cache when the files did not
    change) and make it the active index."""
    rdir = ruleset_dir(stock_dir)
    if rdir is None:
        raise StockMissing("no 4.x stock ruleset at %s (it needs rules/ and decoders/): pass --stock-dir with the "
                           "ruleset/ directory of the 4.x manager" % stock_dir)
    fp = fingerprint(rdir)
    cpath = cache_path(workdir) if workdir else None
    cached = _read_cache(cpath) if cpath else None
    if cached is not None and cached.data.get("fingerprint") == fp:
        return set_active(cached)
    data = build_index(rdir)
    if not data["rules"] and not data["decoders"]:
        raise StockMissing("the 4.x stock ruleset at %s has no rule and no decoder (*.xml in rules/ and decoders/): "
                           "without them every stock rule would look custom" % stock_dir)
    data["fingerprint"] = fp
    if cpath:
        os.makedirs(os.path.dirname(cpath), exist_ok=True)
        with open(cpath, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(dump_index(data))
    return set_active(StockIndex(data))


def _read_cache(cpath):
    """The index cached at ``cpath``, or None when there is none or it cannot be used (unreadable, cut short, or
    written by another version of the index)."""
    if not os.path.exists(cpath):
        return None
    try:
        with open(cpath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict) or data.get("version") != INDEX_VERSION:
            return None
        return StockIndex(data)
    except (OSError, ValueError, KeyError, TypeError):
        return None


def use_cached(workdir):
    """Activate the index cached in ``workdir``. False when there is none that can be used."""
    cached = _read_cache(cache_path(workdir))
    if cached is None:
        return False
    set_active(cached)
    return True


def load_stock_index(path=None):
    """The active index, or the index file at ``path``."""
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            return StockIndex(json.load(fh))
    if _ACTIVE["index"] is None:
        raise StockMissing("no 4.x stock ruleset loaded: pass --stock-dir with the ruleset/ directory of the 4.x "
                           "manager (%s on the manager)" % DEFAULT_STOCK_DIR)
    return _ACTIVE["index"]


def load_equivalence(path=None):
    path = path or EQUIVALENCE_PATH
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    for section in ("decoders", "rules", "groups"):
        data.setdefault(section, {})
    return data
