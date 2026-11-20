"""Vocabulary of the 4.14 model (``Rule4``, ``Decoder4``, ``List4``, ``RulesetConfig4``).

The parsed elements are plain dictionaries so that the inventory is plain JSON.
This module fixes the names that the rest of the package reads.

``Rule4`` keys: ``kind`` ("rule"), ``file`` (relative path), ``line``, ``id``
(string as written), ``level`` (int or None), ``attrs`` (rule attributes other
than ``id``/``level``), ``group_string`` (file ``<group name>`` + own
``<group>``, as analysisd builds it), ``groups`` (the same split by comma),
``parents`` (``if_sid`` list, ``if_group``, ``if_level``, ``if_matched_sid``,
``if_matched_group``, ``if_matched_regex``), ``decoded_as``, ``category``,
``conditions`` (pattern elements, repeated ones concatenated), ``fields``
(``<field>`` entries, AND), ``lists``, ``correlation`` (``same_*``,
``different_*``, ``global_frequency``), ``flags`` (stateful or procedural
constructs), ``description``, ``mitre``, ``options``, ``info``, ``unknown``
(elements or attributes 4.14 does not know) and ``invalid`` (what 4.14 would
reject).

``Decoder4`` keys: ``kind`` ("decoder"), ``file``, ``line``, ``name``,
``parent``, ``program_name``, ``prematch``, ``regex`` (each ``{value, engine,
offset, negate}`` or None; repeated elements concatenated), ``order``, ``fts``,
``ftscomment``, ``plugin_decoder``, ``use_own_name``, ``json_null_field``,
``json_array_structure``, ``accumulate``, ``type``, ``unknown``, ``invalid``.

``List4`` keys: ``kind`` ("list"), ``file``, ``line`` (always 1), ``name`` (path
as written in ``<list>``, e.g. ``etc/lists/audit-keys``), ``sha256``,
``entries``, ``prefix_keys`` (keys ending in ``.``), ``sample_keys``.

``RulesetConfig4``: ``{"directives": [[element, value, {attrs}], ...],
"origin": "ossec.conf" | "default"}`` in document order.
"""

RULE = "rule"
DECODER = "decoder"
LIST = "list"

# Pattern elements of <rule> and their default engine (rules.c:3230).
RULE_PATTERN_ELEMENTS = {
    "match": "osmatch",
    "regex": "osregex",
    "srcport": "osmatch",
    "dstport": "osmatch",
    "srcgeoip": "osmatch",
    "dstgeoip": "osmatch",
    "user": "osmatch",
    "program_name": "osmatch",
    "hostname": "osmatch",
    "id": "osmatch",
    "url": "osmatch",
    "location": "osmatch",
    "action": "string",
    "status": "osmatch",
    "protocol": "osmatch",
    "system_name": "osmatch",
    "data": "osmatch",
    "extra_data": "osmatch",
}
RULE_IP_ELEMENTS = ("srcip", "dstip")

RULE_PARENT_ELEMENTS = (
    "if_sid", "if_group", "if_level", "if_matched_sid", "if_matched_group",
    "if_matched_regex",
)

RULE_FLAG_ELEMENTS = (
    "if_fts", "check_diff", "compiled_rule", "time", "weekday", "ignore",
    "check_if_ignored",
)

RULE_SAME_DIFFERENT = (
    "same_source_ip", "same_srcip", "same_src_port", "same_srcport", "same_dst_port",
    "same_dstport", "same_srcuser", "same_user", "same_location", "same_id",
    "same_field", "same_dstip", "same_agent", "same_url", "same_srcgeoip",
    "same_protocol", "same_action", "same_data", "same_extra_data", "same_status",
    "same_system_name", "same_dstgeoip", "different_url", "different_srcip",
    "different_srcgeoip", "different_dstip", "different_src_port",
    "different_srcport", "different_dst_port", "different_dstport",
    "different_location", "different_protocol", "different_action",
    "different_srcuser", "different_user", "different_id", "different_data",
    "different_extra_data", "different_status", "different_system_name",
    "different_dstgeoip", "different_field", "not_same_source_ip",
    "not_same_user", "not_same_agent", "not_same_id", "not_same_field",
    "global_frequency",
)

RULE_META_ELEMENTS = ("description", "group", "info", "cve", "mitre", "options")

RULE_OTHER_ELEMENTS = ("decoded_as", "category", "field", "list")

RULE_ATTRIBUTES = (
    "id", "level", "frequency", "timeframe", "ignore", "noalert", "maxsize",
    "overwrite", "accuracy",
)

RULE_OPTIONS = (
    "alert_by_email", "no_email_alert", "log_alert", "no_log", "no_ar",
    "no_full_log", "no_counter",
)

RULE_CATEGORIES = ("firewall", "ids", "syslog", "web-log", "squid", "windows", "ossec")

LIST_LOOKUPS = (
    "match_key", "not_match_key", "match_key_value", "address_match_key",
    "not_address_match_key", "address_match_key_value",
)

DECODER_ELEMENTS = (
    "parent", "program_name", "prematch", "regex", "order", "fts", "ftscomment",
    "plugin_decoder", "use_own_name", "json_null_field", "json_array_structure",
    "accumulate", "type", "var",
)

DECODER_TYPES = (
    "firewall", "ids", "web-log", "syslog", "squid", "windows",
    "host-information", "ossec",
)

DECODER_PLUGINS = (
    "JSON_Decoder", "PF_Decoder", "SymantecWS_Decoder", "SonicWall_Decoder",
    "OSSECAlert_Decoder",
)

# Static fields of 4.x (decode-xml.c:545-581). ``user`` is an alias of dstuser.
STATIC_ORDER_FIELDS = (
    "srcip", "dstip", "srcport", "dstport", "protocol", "action", "srcuser",
    "dstuser", "user", "id", "status", "url", "data", "extra_data",
    "system_name",
)

ENGINES = ("osmatch", "osregex", "pcre2")


def uid(item):
    """Unique key of an item in the inventory: ``<kind>:<file>:<line>``."""
    return "%s:%s:%d" % (item["kind"], item["file"], item["line"])


def ref(item):
    """Reference used in ``decisions.json`` ``used_by``: ``rule:<id>``,
    ``decoder:<name>``, ``list:<name>``."""
    if item["kind"] == RULE:
        return "rule:%s" % item["id"]
    if item["kind"] == DECODER:
        return "decoder:%s" % item["name"]
    return "list:%s" % item["name"]


def origin(item):
    return "%s:%d" % (item["file"], item["line"])
