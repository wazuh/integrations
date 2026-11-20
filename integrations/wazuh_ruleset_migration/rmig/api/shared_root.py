"""Apply under a root decoder that the draft policy already has.

A 5.x policy has one root decoder. In the 5.x catalog only ``decoder/core-wazuh-message/0`` has no parent;
a fresh draft space has it as ``root_decoder``. ``build`` recreates that decoder as the tool's own root
(``decoder/wazuh4-core-wazuh-message/0``, ``rmig/data/wazuh4-base.json``): one map,
``_tmp_json = parse_json($event.original)``, no check, no parse stage. Only the 4.x predecoder hangs from it,
and it reads ``$event.original`` only.

When the draft policy root is that standard decoder and does the same processing (``compatibility``),
``apply`` keeps it: the tool's root is not created, the policy is never written, and every decoder that
listed the tool's root as parent lists the existing root instead (``share``). The state records the mode
(``state.json`` ``shared_root``), so rollback, activate and verify read ``out/`` the same way.

Under a shared root the tool's top-level decoders are siblings of the customer's decoders, and the 5.x engine
stops at the first sibling that accepts an event. A top-level decoder without a check would accept every event
first. The predecoder has none in ``out/``: its children select on ``$process.name`` and ``$message``, which it
computes itself. ``share`` gives it a check built from its children's checks (``gate``), each moved onto
``$event.original``: the program name and the message are substrings of ``$event.original``, so a regex that
matches one of them, with its anchors removed, matches ``$event.original`` too. The gate accepts every event a
child accepts, and an approximate superset of them. A child whose check keeps nothing that can be moved (no
check, or only tests that need the predecoder's fields) makes the gate accept every event: ``apply`` stops
with ``RM-P-ROOT-CATCHALL``.
"""

import copy
import re

from ..jsonio import canonical_sha256
from ..translate.patterns import helper_quote

STOCK_ROOT = "decoder/core-wazuh-message/0"
PREDECODER = "decoder/wazuh4-predecoder/0"  # rmig/data/wazuh4-base.json "predecoder"
# Fields the 4.x predecoder computes from $event.original (rmig/data/wazuh4-base.json): a test on them cannot be
# made before it runs. ``process.name`` and ``message`` are substrings of $event.original.
SUBSTRING_FIELDS = ("process.name", "message")
COMPUTED_PREFIXES = ("process.", "message", "observer.hostname", "_w4")
# the 5.x regex helper the translator writes in decoder checks: helper(field, 'regex')
REGEX_HELPERS = ("regex_match",)
# Keys of a decoder that take part in processing an event; the rest (metadata, id, dates) does not.
PROCESSING = ("check", "parents", "normalize", "definitions", "outputs")

_ATOM = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\(\$([A-Za-z0-9_.@-]+)\s*(?:,\s*(.*))?\)$", re.S)


class GateError(Exception):
    def __init__(self, items):
        super().__init__("; ".join(items))
        self.items = items


def _processing(res):
    """The processing keys of a decoder; an empty value (``parents: []``, ``check: ""``) counts as absent."""
    return {k: res[k] for k in res if (k in PROCESSING or k.startswith("parse")) and res[k] not in (None, "", [], {})}


def compatibility(doc, tool_root):
    """None when ``doc`` (the draft policy root decoder) does what the tool's root does, else why not.

    The rule: the name is the standard ``decoder/core-wazuh-message/0``, it is enabled, and its processing
    (check, parents, parse stages, normalize, definitions, outputs) equals that of the tool's root in ``out/``:
    no check and no parent (it takes every event), the same maps (the fields its children may read)."""
    if doc is None:
        return "its document is not in the draft space"
    if doc.get("name") != STOCK_ROOT:
        return "its name is %s, not the standard %s that the tool's decoders can hang from" % (
            doc.get("name") or "-", STOCK_ROOT)
    if doc.get("enabled") is False:
        return "it is disabled"
    mine = _processing(tool_root)
    theirs = _processing(doc)
    for k in sorted(set(mine) | set(theirs)):
        if mine.get(k) != theirs.get(k):
            return "its %s is %s, the standard one (recreated in out/) is %s" % (
                k, _short(theirs.get(k)), _short(mine.get(k)))
    return None


def _short(value):
    text = "absent" if value is None else canonical_json(value)
    return text if len(text) <= 160 else text[:157] + "..."


def canonical_json(value):
    import json
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


# -- the gate ------------------------------------------------------------------------------------------------
def _split_top(expr, word):
    """Split ``expr`` on `` word `` outside quotes and parentheses."""
    parts, depth, quote, start, i = [], 0, False, 0, 0
    sep = " %s " % word
    while i < len(expr):
        c = expr[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == "'":
                quote = False
        elif c == "'":
            quote = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif depth == 0 and expr.startswith(sep, i):
            parts.append(expr[start:i])
            i += len(sep)
            start = i
            continue
        i += 1
    parts.append(expr[start:])
    return [p.strip() for p in parts]


def _wrapped(expr):
    """True when the outer parentheses enclose the whole expression."""
    if not (expr.startswith("(") and expr.endswith(")")):
        return False
    depth, quote, i = 0, False, 0
    while i < len(expr):
        c = expr[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == "'":
                quote = False
        elif c == "'":
            quote = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0 and i < len(expr) - 1:
                return False
        i += 1
    return True


def unquote(literal):
    """The regex of a helper literal written by ``helper_quote``."""
    if len(literal) < 2 or literal[0] != "'" or literal[-1] != "'":
        return None
    inner = literal[1:-1]
    if "'" in inner:
        return None
    out, i = [], 0
    while i < len(inner):
        if inner[i] == "\\":
            if inner[i + 1:i + 2] != "\\":
                return None  # not the doubled form helper_quote writes
            out.append("\\")
            i += 2
            continue
        out.append(inner[i])
        i += 1
    return "".join(out)


def drop_anchors(regex):
    """``regex`` without its zero-width assertions outside classes (``^ $ \\A \\z \\b \\B``): it matches every
    text the original matches, and the substring it matched, wherever that substring sits in a longer text."""
    out, i, cls = [], 0, False
    n = len(regex)
    while i < n:
        c = regex[i]
        if c == "\\" and i + 1 < n:
            if not cls and regex[i + 1] in "AzbB":
                i += 2
                continue
            out.append(regex[i:i + 2])
            i += 2
            continue
        if cls:
            if regex.startswith("[:", i):
                end = regex.find(":]", i + 2)
                if end != -1:
                    out.append(regex[i:end + 2])
                    i = end + 2
                    continue
            if c == "]":
                cls = False
            out.append(c)
            i += 1
            continue
        if c == "[":
            cls = True
            out.append(c)
            i += 1
            if regex.startswith("^", i):
                out.append("^")
                i += 1
            if regex.startswith("]", i):
                out.append("]")
                i += 1
            continue
        if c in "^$":
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


_CLASS_ESCAPES = "dDsSwWpPhHvV"
_ZERO_WIDTH_ESCAPES = "AzZbBG"


def _quant(regex, i):
    """``(minimum repeat count, next index)`` of the quantifier at ``i`` (1 when there is none)."""
    n = len(regex)
    if i < n and regex[i] in "?*":
        lo, i = 0, i + 1
    elif i < n and regex[i] == "+":
        lo, i = 1, i + 1
    elif i < n and regex[i] == "{":
        m = re.match(r"\{([0-9]*)(,[0-9]*)?\}", regex[i:])
        if not m:
            return 1, i
        lo, i = int(m.group(1) or 0), i + m.end()
    else:
        return 1, i
    if i < n and regex[i] in "?+":  # lazy or possessive form
        i += 1
    return lo, i


def _min_literal(regex, i=0, depth=0):
    """``(fewest literal characters any match of the alternation at ``i`` must contain, next index)``.
    Whitespace does not count, classes (``.``, ``[...]``, ``\\d``, ``\\pL``) count 0, a group counts its own
    alternation, and an atom made optional (``?``, ``*``, ``{0,``) counts 0."""
    n = len(regex)
    branches, total = [], 0
    while i < n:
        c = regex[i]
        if c == "|":
            branches.append(total)
            total, i = 0, i + 1
            continue
        if c == ")":
            if depth:
                break
            i += 1  # an unbalanced ")" is not a literal
            continue
        if c in "^$":
            i += 1
            continue
        if c == "(":
            j = i + 1
            if regex.startswith("?", j):
                k = j + 1
                if regex.startswith(("P<", "<"), k) and not regex.startswith(("<=", "<!"), k):
                    end = regex.find(">", k)
                    if end == -1:
                        raise ValueError("unterminated group name")
                    k = end + 1
                else:
                    while k < n and regex[k] not in ":)":
                        k += 1
                    if k < n and regex[k] == ")":  # flags only, (?i): zero width
                        i = k + 1
                        continue
                    k += 1
                j = k
            inner, j = _min_literal(regex, j, depth + 1)
            j += 1  # the closing ")"
            lo, i = _quant(regex, j)
            total += inner * lo
            continue
        if c == "[":
            j = i + 1
            if regex.startswith("^", j):
                j += 1
            if regex.startswith("]", j):
                j += 1
            while j < n and regex[j] != "]":
                if regex[j] == "\\":
                    j += 1
                elif regex.startswith("[:", j):
                    end = regex.find(":]", j + 2)
                    j = end + 1 if end != -1 else j
                j += 1
            _lo, i = _quant(regex, j + 1)
            continue
        if c == "\\" and i + 1 < n:
            e = regex[i + 1]
            if e in _ZERO_WIDTH_ESCAPES:
                i += 2
                continue
            j = i + 2
            if e in "pP":
                j = regex.find("}", j) + 1 if regex.startswith("{", j) else j + 1
            lit = 0 if (e.isalnum() or e.isspace()) else 1  # \. \| \[ are literal; \d \x41 \n are not counted
            lo, i = _quant(regex, j)
            total += lit * lo
            continue
        lit = 0 if (c == "." or c.isspace()) else 1
        lo, i = _quant(regex, i + 1)
        total += lit * lo
    branches.append(total)
    return min(branches), i


def has_literal(regex):
    """True when every match of ``regex`` must contain at least one literal character that is not whitespace:
    every alternative of ``|`` needs one, and a group made optional or a class (``\\pL``, ``\\S``, ``[a-z]``)
    gives none. ``^\\S+ \\S+ `` or ``^$|^ERROR`` would let the predecoder take almost every event."""
    try:
        return _min_literal(regex)[0] > 0
    except (ValueError, IndexError, RecursionError):
        return False


def hoist(expr):
    """A condition on fields the event has before the predecoder runs that every event accepted by ``expr``
    (a decoder check under the predecoder) also passes, or None when nothing of ``expr`` can be kept."""
    expr = expr.strip()
    while _wrapped(expr):
        expr = expr[1:-1].strip()
    ors = _split_top(expr, "OR")
    if len(ors) > 1:
        parts = [hoist(p) for p in ors]
        if any(p is None for p in parts):
            return None
        return "(%s)" % " OR ".join(parts)
    ands = _split_top(expr, "AND")
    if len(ands) > 1:
        parts = [p for p in (hoist(a) for a in ands) if p is not None]
        return " AND ".join(parts) if parts else None
    if expr.startswith("NOT "):
        return None  # a negation of a moved test would not be a superset
    m = _ATOM.match(expr)
    if not m:
        return None
    helper, field, args = m.group(1), m.group(2), (m.group(3) or "").strip()
    if not field.startswith(COMPUTED_PREFIXES):
        return expr  # a field of the event itself (wazuh.protocol.location, event.original)
    if helper in REGEX_HELPERS and field in SUBSTRING_FIELDS:
        rx = unquote(args)
        if rx is None or "\\Q" in rx:
            return None  # \Q...\E quotes ^ and $: dropping them would make the gate narrower than the child
        rx = drop_anchors(rx)
        if not has_literal(rx):
            return None  # no literal text left (``\S+``): it would accept every line
        return "%s($event.original, %s)" % (helper, helper_quote(rx))
    return None


def gate(children):
    """The predecoder's check: one alternative per child (``[(name, check)]``, in out/ order). Raises
    ``GateError`` naming each child that keeps nothing."""
    alts, bad = [], []
    for name, check in children:
        if not check:
            bad.append("%s: no check, it accepts every event" % name)
            continue
        if not isinstance(check, str):
            bad.append("%s: its check is not a condition string" % name)
            continue
        h = hoist(check)
        if h is None:
            bad.append("%s: its check (%s) only tests what the predecoder computes" % (name, check))
            continue
        if h not in alts:
            alts.append(h)
    if bad:
        raise GateError(bad)
    if not alts:
        raise GateError(["the predecoder has no children"])
    return alts[0] if len(alts) == 1 else " OR ".join("(%s)" % a for a in alts)


# -- out/ under a shared root -----------------------------------------------------------------------------------
def share(out, root_name):
    """Rewrite ``out`` (an ``outdir.Out``) in memory to hang from ``root_name``: drop the tool's root, reparent
    its children, and give each top-level decoder without a check one (``gate``). Returns a list of notes
    (what was chosen). Raises ``GateError``."""
    from .outdir import BASE_KEY

    if not out.root:
        return []
    root = out.by_local[out.root["local_id"]]
    old = root.resource.get("name")
    base = out.integration(out.root.get("integration") or BASE_KEY)
    decoders = [d for i in out.integrations for d in i.decoders if d.local_id != root.local_id]
    notes, new = [], {}
    for d in decoders:
        if (d.resource.get("parents") or []) != [old]:
            continue
        res = copy.deepcopy(d.resource)
        res["parents"] = [root_name]
        name = res.get("name")
        if res.get("check"):
            notes.append("%s: keeps its own check." % name)
        elif name != PREDECODER:
            raise GateError(["%s: no check, it hangs from the root and accepts every event" % name])
        else:
            kids = [(k.resource.get("name"), k.resource.get("check")) for k in decoders
                    if name in (k.resource.get("parents") or [])]
            res["check"] = gate(kids)
            notes.append("%s: no check of its own; it gets one built from its %d child decoder(s), each test "
                         "moved onto $event.original (approximate: it accepts every event a child accepts, and "
                         "a few more)." % (name, len(kids)))
        new[d.local_id] = res
    # nothing changes until every check is built
    base.decoders = [d for d in base.decoders if d.local_id != root.local_id]
    del out.by_local[root.local_id]
    for d in decoders:
        if d.local_id in new:
            d.resource = new[d.local_id]
            d.sha256 = canonical_sha256(d.resource)
    out.shared_root = {"name": root_name, "base_integration": base.key, "tool_root": old,
                       "tool_root_local_id": root.local_id}
    out.root = None
    return notes


def tool_root_resource(out):
    if not out.root:
        return None
    return out.by_local[out.root["local_id"]].resource


__all__ = ["STOCK_ROOT", "GateError", "compatibility", "gate", "hoist", "drop_anchors", "share",
           "tool_root_resource"]


def load_out(path, state):
    """``out/`` as the applied content sees it: under the shared root when ``state.json`` records one."""
    from .outdir import Out

    out = Out(path)
    rec = state.data.get("shared_root") or {}
    if rec.get("name") and out.root:
        try:
            share(out, rec["name"])
        except GateError as exc:
            # out/ was rebuilt since apply and no longer fits under the shared root: apply stops on it and rollback
            # works from the state; whoever checks out/ must say it does not show what is applied
            out.share_error = ("out/ no longer fits under the shared root %s that apply used (%s): it was rebuilt "
                               "since apply. Run apply again (it stops and says why) before checking it."
                               % (rec["name"], "; ".join(exc.items)))
    return out
