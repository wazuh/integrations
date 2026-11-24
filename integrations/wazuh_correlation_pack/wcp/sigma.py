"""Load and validate the supported subset of Sigma rules and Sigma correlation rules.

Supported subset (anything else is rejected with an explicit error):

Base (detection) rules
    * ``detection`` with one or more named selections. A selection is a map
      (fields ANDed) or a list of maps (ORed). A list value means "any of".
    * Field modifiers: none (exact match), ``|startswith``, ``|endswith``,
      ``|contains``, ``|exists``, ``|cidr``, ``|all`` (combined with a list).
    * ``condition``: a boolean expression over selection names with ``and``,
      ``or``, ``not`` and parentheses. ``1 of``/``all of`` and aggregation
      conditions (``| count()``) are rejected.
    * ``taxonomy`` must be ``wcs``: field names are Wazuh Common Schema fields.

Correlation rules (Sigma correlation specification v2)
    * ``type``: ``event_count`` or ``value_count``. ``temporal``,
      ``temporal_ordered`` and the v2.1 metric types are rejected.
    * ``rules``: one or more base rules referenced by ``name`` or ``id``.
      Chained correlations (a correlation referencing a correlation) are rejected.
    * ``group-by``: one or more WCS fields (mandatory here).
    * ``timespan``: ``<int>s|m|h|d``.
    * ``condition``: exactly one of ``gt``/``gte`` (``value_count`` also needs
      ``field``). ``lt``/``lte``/``eq``/``neq`` are rejected because this
      backend evaluates the maximum over sliding windows.
    * ``aliases`` and ``generate: true`` are rejected.
"""

import os
import re
import uuid

import yaml

from . import identity as IDN

TIMESPAN_RE = re.compile(r"^([1-9][0-9]*)([smhd])$")
TIMESPAN_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
SUPPORTED_MODIFIERS = {"startswith", "endswith", "contains", "exists", "cidr", "all"}
SUPPORTED_CORRELATION_TYPES = {"event_count", "value_count"}
REJECTED_CORRELATION_TYPES = {
    "temporal": "temporal correlations (co-occurrence of different rules) are not implemented by this backend",
    "temporal_ordered": "ordered sequences are not implemented by this backend",
    "value_sum": "value_sum is not implemented by this backend",
    "value_avg": "value_avg is not implemented by this backend",
    "value_percentile": "value_percentile is not implemented by this backend",
}
SUPPORTED_CONDITION_OPS = {"gt", "gte"}
LEVELS = ("informational", "low", "medium", "high", "critical")
FIELD_RE = re.compile(r"^[a-z0-9_@][a-z0-9_.@]*$")
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")


class SigmaError(ValueError):
    """A rule uses something outside the supported subset or is malformed."""


def parse_timespan(value):
    """'2m' -> 120 (seconds)."""
    m = TIMESPAN_RE.match(str(value).strip())
    if not m:
        raise SigmaError("timespan %r is not <positive int><s|m|h|d>" % (value,))
    return int(m.group(1)) * TIMESPAN_UNITS[m.group(2)]


def _require(doc, key, where):
    if key not in doc or doc[key] in (None, "", [], {}):
        raise SigmaError("%s: missing mandatory key %r" % (where, key))
    return doc[key]


def _check_uuid(value, where):
    try:
        uuid.UUID(str(value))
    except ValueError:
        raise SigmaError("%s: id %r is not a UUID" % (where, value))


def _check_field(name, where):
    if not FIELD_RE.match(name):
        raise SigmaError("%s: %r is not a valid WCS field name" % (where, name))


# ---------------------------------------------------------------- conditions

_TOKEN_RE = re.compile(r"\s*(\(|\)|[A-Za-z_][A-Za-z0-9_]*|\S+)")


def _tokenize(text):
    pos, out = 0, []
    text = text.strip()
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            break
        tok = m.group(1)
        pos = m.end()
        out.append(tok)
    return out


def parse_condition(text, names, where):
    """Parse a Sigma condition into a tree: ('sel', name) | ('not', t) | ('and'|'or', [t...])."""
    if not isinstance(text, str):
        raise SigmaError("%s: condition must be a single string (lists of conditions are not supported)" % where)
    if "|" in text:
        raise SigmaError("%s: aggregation conditions ('| count()' etc.) are deprecated in Sigma and not supported; "
                         "use a correlation rule" % where)
    toks = _tokenize(text)
    for t in toks:
        if t.lower() in ("of", "all", "1") or "*" in t:
            raise SigmaError("%s: '1 of'/'all of'/wildcard selection references are not supported: %r" % (where, text))
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def take():
        t = peek()
        pos[0] += 1
        return t

    def p_or():
        items = [p_and()]
        while peek() is not None and peek().lower() == "or":
            take()
            items.append(p_and())
        return items[0] if len(items) == 1 else ("or", items)

    def p_and():
        items = [p_not()]
        while peek() is not None and peek().lower() == "and":
            take()
            items.append(p_not())
        return items[0] if len(items) == 1 else ("and", items)

    def p_not():
        if peek() is not None and peek().lower() == "not":
            take()
            return ("not", p_not())
        return p_atom()

    def p_atom():
        t = take()
        if t is None:
            raise SigmaError("%s: condition %r ends unexpectedly" % (where, text))
        if t == "(":
            node = p_or()
            if take() != ")":
                raise SigmaError("%s: unbalanced parentheses in %r" % (where, text))
            return node
        if t not in names:
            raise SigmaError("%s: condition references unknown selection %r" % (where, t))
        return ("sel", t)

    tree = p_or()
    if peek() is not None:
        raise SigmaError("%s: unexpected token %r in condition %r" % (where, peek(), text))
    return tree


# ---------------------------------------------------------------- base rules

def _parse_selection(name, body, where):
    """Return a list of alternatives; each alternative is a list of (field, modifiers, values)."""
    alts = body if isinstance(body, list) else [body]
    out = []
    for alt in alts:
        if not isinstance(alt, dict) or not alt:
            raise SigmaError("%s: selection %r must be a map or a list of maps (keyword lists are not supported)" % (where, name))
        items = []
        for key, value in alt.items():
            parts = str(key).split("|")
            field, mods = parts[0], parts[1:]
            _check_field(field, "%s selection %r" % (where, name))
            if IDN.is_virtual(field):
                raise SigmaError("%s: derived value %s can only be a correlation condition.field, not a selection field"
                                 % (where, field))
            for mod in mods:
                if mod not in SUPPORTED_MODIFIERS:
                    raise SigmaError("%s: modifier |%s on %s is not supported (supported: %s)"
                                     % (where, mod, field, ", ".join(sorted(SUPPORTED_MODIFIERS))))
            values = value if isinstance(value, list) else [value]
            if not values:
                raise SigmaError("%s: empty value list for %s" % (where, key))
            if "exists" in mods:
                if len(values) != 1 or not isinstance(values[0], bool):
                    raise SigmaError("%s: %s|exists takes true or false" % (where, field))
            for v in values:
                if v is None:
                    raise SigmaError("%s: null values are not supported (use |exists: false) in %s" % (where, key))
                if isinstance(v, (dict, list)):
                    raise SigmaError("%s: nested values are not supported in %s" % (where, key))
                if isinstance(v, str) and ("*" in v or "?" in v) and not mods:
                    raise SigmaError("%s: wildcards in plain values are not supported (%s: %r); use a modifier"
                                     % (where, key, v))
            items.append((field, tuple(mods), [v if isinstance(v, bool) else v for v in values]))
        out.append(items)
    return out


class BaseRule(object):
    def __init__(self, doc, path):
        where = os.path.basename(path)
        self.path = path
        self.title = _require(doc, "title", where)
        self.id = str(_require(doc, "id", where))
        _check_uuid(self.id, where)
        self.name = _require(doc, "name", where)
        if not NAME_RE.match(self.name):
            raise SigmaError("%s: name %r must match %s" % (where, self.name, NAME_RE.pattern))
        if doc.get("taxonomy") != "wcs":
            raise SigmaError("%s: taxonomy must be 'wcs' (field names are Wazuh Common Schema fields)" % where)
        self.level = doc.get("level", "informational")
        if self.level not in LEVELS:
            raise SigmaError("%s: level %r is not one of %s" % (where, self.level, LEVELS))
        self.logsource = doc.get("logsource") or {}
        self.description = doc.get("description", "")
        det = _require(doc, "detection", where)
        cond = _require(det, "condition", where + " detection")
        self.selections = {}
        for key, body in det.items():
            if key == "condition":
                continue
            if key == "timeframe":
                raise SigmaError("%s: detection.timeframe is not supported; use a correlation rule" % where)
            self.selections[key] = _parse_selection(key, body, where)
        if not self.selections:
            raise SigmaError("%s: detection has no selections" % where)
        self.condition_text = cond
        self.condition = parse_condition(cond, set(self.selections), where)
        self.raw = doc

    def fields(self):
        out = set()
        for alts in self.selections.values():
            for alt in alts:
                for field, _mods, _vals in alt:
                    out.add(field)
        return out


# ---------------------------------------------------------------- correlations

class Correlation(object):
    def __init__(self, doc, path):
        where = os.path.basename(path)
        self.path = path
        self.title = _require(doc, "title", where)
        if len(self.title) > 256:
            raise SigmaError("%s: title longer than 256 characters" % where)
        self.id = str(_require(doc, "id", where))
        _check_uuid(self.id, where)
        self.name = _require(doc, "name", where)
        if not NAME_RE.match(self.name):
            raise SigmaError("%s: name %r must match %s" % (where, self.name, NAME_RE.pattern))
        self.description = doc.get("description", "")
        self.level = doc.get("level", "medium")
        if self.level not in LEVELS:
            raise SigmaError("%s: level %r is not one of %s" % (where, self.level, LEVELS))
        if doc.get("taxonomy", "wcs") != "wcs":
            raise SigmaError("%s: taxonomy must be 'wcs'" % where)
        if doc.get("generate"):
            raise SigmaError("%s: generate: true is not supported (base rules are not deployed as stand-alone rules)" % where)
        corr = _require(doc, "correlation", where)
        ctype = _require(corr, "type", where + " correlation")
        if ctype in REJECTED_CORRELATION_TYPES:
            raise SigmaError("%s: correlation type %r rejected: %s" % (where, ctype, REJECTED_CORRELATION_TYPES[ctype]))
        if ctype not in SUPPORTED_CORRELATION_TYPES:
            raise SigmaError("%s: unknown correlation type %r" % (where, ctype))
        self.type = ctype
        if "aliases" in corr:
            raise SigmaError("%s: correlation aliases are not supported; use one WCS field name in every base rule" % where)
        rules = _require(corr, "rules", where + " correlation")
        self.rule_refs = [str(r) for r in (rules if isinstance(rules, list) else [rules])]
        group_by = _require(corr, "group-by", where + " correlation")
        self.group_by = [str(g) for g in (group_by if isinstance(group_by, list) else [group_by])]
        for g in self.group_by:
            _check_field(g, where + " group-by")
            if IDN.is_virtual(g):
                raise SigmaError("%s: derived value %s cannot be a group-by field" % (where, g))
        if len(set(self.group_by)) != len(self.group_by):
            raise SigmaError("%s: duplicate group-by field" % where)
        self.timespan_text = str(_require(corr, "timespan", where + " correlation"))
        self.timespan_s = parse_timespan(self.timespan_text)
        cond = _require(corr, "condition", where + " correlation")
        if not isinstance(cond, dict):
            raise SigmaError("%s: condition must be a map" % where)
        ops = [k for k in cond if k != "field"]
        if len(ops) != 1:
            raise SigmaError("%s: condition must have exactly one operator (got %s)" % (where, ops))
        op = ops[0]
        if op not in SUPPORTED_CONDITION_OPS:
            raise SigmaError("%s: condition operator %r not supported (supported: gt, gte); this backend alerts on "
                             "the maximum count over sliding windows, so 'fewer than' conditions cannot be expressed" % (where, op))
        threshold = cond[op]
        if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
            raise SigmaError("%s: condition threshold must be a positive integer" % where)
        self.op = op
        self.threshold = threshold
        self.min_count = threshold + 1 if op == "gt" else threshold
        self.value_field = cond.get("field")
        if ctype == "value_count":
            if not self.value_field:
                raise SigmaError("%s: value_count requires condition.field" % where)
            _check_field(self.value_field, where + " condition.field")
            if IDN.is_virtual(self.value_field) and IDN.get(self.value_field) is None:
                raise SigmaError("%s: unknown derived value %r (known: %s)" % (
                    where, self.value_field, ", ".join(sorted(IDN.IDENTITIES))))
            if self.value_field in self.group_by:
                raise SigmaError("%s: condition.field must not also be a group-by field" % where)
        elif self.value_field:
            raise SigmaError("%s: condition.field is only valid for value_count" % where)
        self.rules = []  # resolved BaseRule objects
        self.raw = doc


def load_yaml_documents(path):
    with open(path, "r", encoding="utf-8") as fh:
        docs = [d for d in yaml.safe_load_all(fh) if d is not None]
    return docs


def load_content(root):
    """Load base rules (``root/rules``) and correlations (``root/correlations``); resolve references."""
    rules_dir = os.path.join(root, "rules")
    corr_dir = os.path.join(root, "correlations")
    base_by_ref = {}
    base_rules = []
    for fn in sorted(os.listdir(rules_dir)):
        if not fn.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(rules_dir, fn)
        for doc in load_yaml_documents(path):
            if "correlation" in doc:
                raise SigmaError("%s: correlation rules belong in correlations/" % fn)
            rule = BaseRule(doc, path)
            for ref in (rule.name, rule.id):
                if ref in base_by_ref:
                    raise SigmaError("%s: duplicate rule reference %r" % (fn, ref))
                base_by_ref[ref] = rule
            base_rules.append(rule)
    correlations = []
    seen = set()
    for fn in sorted(os.listdir(corr_dir)):
        if not fn.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(corr_dir, fn)
        for doc in load_yaml_documents(path):
            if "correlation" not in doc:
                raise SigmaError("%s: not a correlation rule" % fn)
            corr = Correlation(doc, path)
            for ref in (corr.name, corr.id):
                if ref in seen or ref in base_by_ref:
                    raise SigmaError("%s: duplicate rule reference %r" % (fn, ref))
                seen.add(ref)
            for ref in corr.rule_refs:
                if ref in seen:
                    raise SigmaError("%s: chained correlations are not supported (%r is a correlation)" % (fn, ref))
                if ref not in base_by_ref:
                    raise SigmaError("%s: referenced rule %r not found in rules/" % (fn, ref))
                corr.rules.append(base_by_ref[ref])
            correlations.append(corr)
    return base_rules, correlations
