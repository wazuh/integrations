"""``decisions.json``: what the tool cannot decide.

Sections:

``fields``
    ``{"<4.x field>": {"action": null | "map" | "drop", "wcs": null | "<WCS field>",
    "used_by": [...], "seen_in": "<file:line>", "required": true | false}}``.
    ``map`` needs a ``wcs`` that exists in ``rmig/data/wcs-fields.csv``.
    ``required`` is informational: ``false`` when the generated decoders can
    check the field without a WCS destination (map it to keep the value).
    4.x field names ignore letter case: one entry covers every spelling.
``integrations``
    ``{"<decoder>": {"category": "<one of 8>", "category_source": "default" |
    "user", "used_by": [...], "seen_in": ...}}``; a JSON catch-all decoder also
    has ``"json_check": null | "<condition>"``.
``stock``
    ``{"rule:<id>" | "group:<name>" | "decoder:<name>": {"integration": null,
    "selection": null, "used_by": [...], "seen_in": ...}}`` (decoders have no
    ``selection``).
``feeds``
    ``{"<root rule id>": {"integration": "<name>", "category": "<one of 8>",
    "category_source": "default" | "user", "selector": null | "<decoder check>",
    "kind": "location" | "field" | "json", "default_selector": ..., "selector_needed": ...,
    "used_by": [...], "seen_in": ...}}``: a root rule tied to its events by
    ``<location>``, by ``<field>`` conditions or by the stock JSON decoder. A null
    ``selector`` uses ``default_selector``; ``selector_needed`` says that there is
    none and one must be written.
``lists``
    ``{"<list path>": {"action": null | "kvdb" | "ioc-feed", "class": "ioc", "default_action": "kvdb",
    "feed_types": [...], "used_by": [...], "seen_in": ...}}``: a list classified as threat intelligence. Null
    keeps the KVDB; ``ioc-feed`` rewrites the rules that use it onto the 5.x IoC enrichment
    (``wazuh.threat.enrichments.indicator.type``) and drops the KVDB.

Regenerating keeps every entry and every value already written, in the order
found, refreshes the informational ``used_by`` and ``seen_in``, and appends new
entries in alphabetical order. An invalid value stops the tool with exit
code 2 naming the entry.
"""

import os
import re
from collections import OrderedDict

from .fields import CATEGORIES, wcs_fields
from .jsonio import read_json, write_text, dumps

SECTIONS = ("fields", "integrations", "stock", "feeds", "lists")
OPTIONAL_SECTIONS = ("feeds", "lists")
INFO_KEYS = ("used_by", "seen_in", "required", "kind", "default_selector", "selector_needed", "class",
             "feed_types", "default_action")
LIST_ACTIONS = (None, "kvdb", "ioc-feed")
FIELD_ACTIONS = (None, "map", "drop")
_FEED_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")


class DecisionsError(Exception):
    pass


def empty():
    return OrderedDict([("version", 1), ("fields", OrderedDict()), ("integrations", OrderedDict()), ("stock", OrderedDict())])


def validate(data, wcs=None):
    """Raise DecisionsError on the first invalid entry."""
    wcs = wcs or wcs_fields()
    if not isinstance(data, dict):
        raise DecisionsError("decisions.json: the top level must be an object")
    if data.get("version", 1) != 1:
        raise DecisionsError("decisions.json: unsupported version %r" % data.get("version"))
    for section in SECTIONS:
        sec = data.get(section, {})
        if not isinstance(sec, dict):
            raise DecisionsError("decisions.json: '%s' must be an object" % section)
        for key, entry in sec.items():
            if not isinstance(entry, dict):
                raise DecisionsError("decisions.json: %s.%s must be an object" % (section, key))
    for name, entry in data.get("fields", {}).items():
        action = entry.get("action")
        if action not in FIELD_ACTIONS:
            raise DecisionsError("decisions.json: fields.%s: action must be null, \"map\" or \"drop\", not %r" % (name, action))
        target = entry.get("wcs")
        if action == "map":
            if not target:
                raise DecisionsError("decisions.json: fields.%s: action \"map\" needs a \"wcs\" field" % name)
            if not wcs.exists(target):
                raise DecisionsError("decisions.json: fields.%s: '%s' is not a WCS field" % (name, target))
        elif target is not None and not wcs.exists(target):
            raise DecisionsError("decisions.json: fields.%s: '%s' is not a WCS field" % (name, target))
    for name, entry in data.get("integrations", {}).items():
        cat = entry.get("category")
        if cat not in CATEGORIES:
            raise DecisionsError("decisions.json: integrations.%s: category '%s' is not one of %s" % (name, cat, ", ".join(CATEGORIES)))
    for key, entry in data.get("stock", {}).items():
        if not (key.startswith("rule:") or key.startswith("group:") or key.startswith("decoder:")):
            raise DecisionsError("decisions.json: stock.%s: key must start with rule:, group: or decoder:" % key)
    for key, entry in data.get("feeds", {}).items():
        integ = entry.get("integration")
        if not isinstance(integ, str) or not _FEED_NAME.match(integ):
            raise DecisionsError("decisions.json: feeds.%s: integration must be a name of [a-z0-9_.-], not %r" % (key, integ))
        cat = entry.get("category")
        if cat not in CATEGORIES:
            raise DecisionsError("decisions.json: feeds.%s: category '%s' is not one of %s" % (key, cat, ", ".join(CATEGORIES)))
        selector = entry.get("selector")
        if selector is not None and (not isinstance(selector, str) or not selector.strip()):
            raise DecisionsError("decisions.json: feeds.%s: selector must be null or a decoder check" % key)
    for key, entry in data.get("lists", {}).items():
        if entry.get("action") not in LIST_ACTIONS:
            raise DecisionsError("decisions.json: lists.%s: action must be null, \"kvdb\" or \"ioc-feed\", not %r"
                                 % (key, entry.get("action")))
    return data


def load(path, wcs=None):
    """Read and validate; an absent file is an empty decision set."""
    if not os.path.exists(path):
        return empty()
    try:
        data = read_json(path, ordered=True)
    except ValueError as exc:
        raise DecisionsError("decisions.json is not valid JSON: %s" % exc)
    validate(data, wcs)
    for section in SECTIONS:
        data.setdefault(section, OrderedDict())
    return data


def _entry_out(entry):
    return OrderedDict((k, entry[k]) for k in sorted(entry))


def merge(existing, wanted):
    """Merge the entries the plan needs (``wanted``: section -> key -> default
    entry with ``used_by``/``seen_in``) into ``existing`` without losing or
    reordering anything already written."""
    out = OrderedDict()
    out["version"] = existing.get("version", 1)
    for section in SECTIONS:
        cur = existing.get(section, OrderedDict())
        want = wanted.get(section, {})
        sec = OrderedDict()
        for key, entry in cur.items():
            new = OrderedDict(entry)
            if key in want:
                for info in INFO_KEYS:
                    if info in want[key]:
                        new[info] = want[key][info]
                for k, v in want[key].items():
                    if k not in new:
                        new[k] = v
            sec[key] = _entry_out(new)
        for key in sorted(k for k in want if k not in cur):
            sec[key] = _entry_out(want[key])
        if section in OPTIONAL_SECTIONS and not sec:
            continue  # written only when it has entries: older files stay byte-identical
        out[section] = sec
    for key in existing:
        if key not in out and key not in SECTIONS:
            out[key] = existing[key]
    return out


def save(path, data):
    write_text(path, dumps(data, sort_keys=False))


# --- queries used by classify ------------------------------------------------

def field_action(decisions, name):
    """(action, wcs) for a field; (None, None) when undecided."""
    fields = decisions.get("fields", {})
    entry = fields.get(name)
    if entry is None:
        # 4.x compares field names without case (FindField, strcasecmp)
        low = name.lower()
        entry = next((e for k, e in fields.items() if k.lower() == low), None)
    if not entry:
        return None, None
    return entry.get("action"), entry.get("wcs")


def stock_resolved(decisions, key):
    entry = decisions.get("stock", {}).get(key)
    if not entry or not entry.get("integration"):
        return False
    if not key.startswith("decoder:") and not entry.get("selection"):
        return False
    return True


def json_check(decisions, name):
    entry = decisions.get("integrations", {}).get(name)
    return bool(entry and entry.get("json_check"))


def list_action(decisions, name):
    """``kvdb`` (the default, also for null) or ``ioc-feed`` for a CDB list."""
    return (decisions.get("lists", {}).get(name) or {}).get("action") or "kvdb"


def feed_entry(decisions, root_id):
    return decisions.get("feeds", {}).get(root_id) or {}
