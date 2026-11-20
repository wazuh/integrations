"""Feeds: custom rule trees that 4.x ties to their events without a custom
decoder.

A feed root is a custom rule with no parent rule and one of:

* ``<decoded_as>json</decoded_as>`` (the stock JSON decoder): kind ``json``;
* a ``<location>`` condition and no ``decoded_as``: kind ``location``;
* ``<field>`` conditions and no ``decoded_as`` nor ``<location>``: kind
  ``field``. Fields of the stock Windows decoder (``win.``) are not a feed: those
  events come from ``windows_eventchannel``.

A root with only ``<match>``/``<regex>``, only static fields, or a correlation
parent (``if_matched_sid``) is not a feed: it keeps ``RM-R-NO-SOURCE``.

Every root is one entry of ``decisions.json`` (``feeds``, keyed by the root
rule id): the integration it goes to, its category and its selector. Roots
with the same integration share one generated decoder. Default:

* a ``location`` root goes to an integration named after the location and is
  selected by ``regex_match($wazuh.protocol.location, ...)``;
* ``json`` and ``field`` roots go to one shared integration, ``json-events``,
  with no selector of its own: it takes every JSON event, as the single stock
  JSON decoder of 4.x did, and the rules keep the conditions of their root.

The JSON feed with no selector of its own is tried last. Its decoder check
is the OR, over its roots, of ``exists($_wazuh4_json.<key>)`` for the first
``<field>`` of each root (in file order, negated or not): in 4.x a missing
field never matches, with or without negate (``rules.c``, ``FindField``), so
the root rule needs that key and no event its rules match is left out. When
one root has no ``<field>`` the feed has no check and takes every JSON event.
``decisions.json`` shows that probe as the root's ``default_selector``.

Only one integration can take every JSON event (it is tried last). A root put
in another integration without a selector needs one (``RM-R-FEED-NO-SELECTOR``).

A feed is ``json`` when its root is ``json`` or ``field``, or when one of its
rules reads a decoded field (``<field>``, a static field element such as
``<srcip>`` or ``<id>``, or a ``<list field=...>``): in 4.x such fields come
from a decoder, and the only decoder a location root can rely on is the JSON
decoder. JSON feeds hang
from ``decoder/wazuh4-json/0`` in ``wazuh4-base``, which repeats the stock 4.x
JSON decoder (``ruleset/decoders/0006-json_decoders.xml``): no program name,
``^{\\s*"`` on the message, and ``parse_json`` into ``_wazuh4_json``.
"""

import re

from .translate.meta import safe_name
from .translate.patterns import PatternError, helper_quote, to_re2

JSON = "json"
LOCATION = "location"
FIELD = "field"
DEFAULT_JSON_FEED = "json-events"
JSON_VAR = "_wazuh4_json"
JSON_GATE = "decoder/wazuh4-json/0"
RESERVED = ("json", "base", "predecoder", "core-wazuh-message")
# A segment of a 5.x field path, as the standard decoders write them.
_SEGMENT = re.compile(r"^[A-Za-z0-9_@-]+$")

# 4.x JSON keys that fill a static field (json_decoder.c fillData): rule
# element -> JSON key. The JSON key "user" fills dstuser when dstuser is not set
# (an alias); a rule's <user> reads dstuser, else srcuser (rules.c). The feed
# reads the key "user" into the WCS field of <user>, as a decoder <order> user.
STATIC_JSON_KEYS = {
    "user": "user",
    "srcip": "srcip", "dstip": "dstip", "srcport": "srcport", "dstport": "dstport",
    "protocol": "protocol", "action": "action", "srcuser": "srcuser", "dstuser": "dstuser",
    "id": "id", "status": "status", "url": "url", "data": "data", "extra_data": "extra_data",
    "system_name": "systemname",
}


def location_condition(item):
    for c in item.get("conditions", []):
        if c["elem"] == "location":
            return c
    return None


def root_kind(item, json_allowed):
    """Kind of feed root of a rule without parent rules, or None."""
    if item is None:
        return None
    dec = item.get("decoded_as")
    if dec:
        return JSON if dec == "json" and json_allowed else None
    if location_condition(item):
        return LOCATION
    if item.get("fields") and not any(f["name"].lower().startswith("win.") for f in item["fields"]):
        return FIELD
    return None


def default_integration(kind, item):
    if kind == LOCATION:
        # a plain slug (rmig.translate.meta.slug keeps it as is): the name becomes a key, a file and an index name
        name = re.sub(r"[^a-z0-9_-]+", "-", safe_name(location_condition(item)["value"].strip("^$ ")).lower()).strip("-_")[:64]
        return name or "location-%s" % item["id"]
    return DEFAULT_JSON_FEED


def location_selector(item):
    """(check, error): the decoder check of a location root."""
    c = location_condition(item)
    try:
        re2 = to_re2(c["engine"], c["value"]).pattern()
    except PatternError as exc:
        return None, "<location> %s %r: %s" % (c["engine"], c["value"], exc)
    check = "regex_match($wazuh.protocol.location, %s)" % helper_quote(re2)
    if c.get("negate"):
        check = "NOT " + check
    return check, None


def json_path(name):
    """``$_wazuh4_json.<a>.<b>`` for the 4.x key ``a.b``, or None when a
    segment cannot be written as a field path."""
    parts = name.split(".")
    if not all(_SEGMENT.match(p) for p in parts):
        return None
    return "$%s.%s" % (JSON_VAR, ".".join(parts))


def json_key_of(name):
    """4.x JSON key that fills field ``name`` (static or dynamic), or None."""
    if name in STATIC_JSON_KEYS:
        return STATIC_JSON_KEYS[name]
    from .fields import STATIC_TO_WCS
    if name in STATIC_TO_WCS:
        return None
    return name


# Rule elements that read a field of the decoder (not the text, not the event header).
_HEADER_ELEMENTS = ("program_name", "hostname", "location")


def reads_decoded_fields(item):
    """True when the rule reads a field that only a decoder fills: a
    ``<field>``, a static field element (``<srcip>``, ``<id>``, ``<url>``...)
    or a ``<list field=...>``."""
    from .fields import STATIC_TO_WCS
    if item is None:
        return False
    if item.get("fields"):
        return True
    if any(c["elem"] in STATIC_TO_WCS and c["elem"] not in _HEADER_ELEMENTS for c in item.get("conditions", [])):
        return True
    return any(li.get("field") for li in item.get("lists", []))


def root_probe(item):
    """``exists($_wazuh4_json.<key>)`` for the first ``<field>`` of a root
    rule (file order, negated or not) whose key is a field path, or None. In
    4.x a missing field never matches, negate included."""
    for f in item.get("fields", []):
        key = json_key_of(f["name"])
        path = json_path(key) if key else None
        if path:
            return "exists(%s)" % path
    return None
