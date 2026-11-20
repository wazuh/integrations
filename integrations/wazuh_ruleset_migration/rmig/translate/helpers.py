"""Engine helper dialects (wazuh/wazuh#41150).

Between 5.0.0-rc1 and 5.0.0 the engine renamed most helpers (``kvdb_match`` ->
``in_kvdb``, ``ip_cidr_match`` -> ``in_cidr``, ``kvdb_get`` -> ``kvdb_lookup``,
``parse_key_value`` -> ``parse_kv``...). The tool has **one** internal dialect,
the current names (``5.0``): the translator and ``wazuh4-base.json`` use them.
This module is the last step: it rewrites a decoder resource to the dialect
asked for (``--engine-helpers``) and validates that every helper name of the
result is registered by that engine.

Data (copied, with their provenance):

* ``rmig/data/helpers-5.0.0.json``: the names the 5.0.0 engine registers;
* ``rmig/data/helper-renames-41150.json``: the #41150 table (old -> new).

The ``5.0-rc1`` set is the 5.0.0 set with the new names of the table replaced
by the old ones, minus the helpers added after rc1 (``added_after_rc1``).

Call forms that change (checked in wazuh@v5.0.0-rc1 and the main docs):

* ``in_cidr($f, 'a.b.c.d/nn'[, ...])`` (expression) or ``in_cidr('a.b.c.d/nn')``
  (``field: value`` form) <-> ``ip_cidr_match($f, 'a.b.c.d', 'nn')`` /
  ``ip_cidr_match('a.b.c.d', 'nn')``: rc1 takes exactly one network and its
  mask as two values, so several networks become ``(... OR ...)``;
* ``in_kvdb``/``not_in_kvdb``/``kvdb_lookup`` keep their arguments
  (``kvdb_match($f, 'db')``, ``kvdb_not_match($f, 'db')``, ``kvdb_get('db', $f)``):
  inside a ``check`` expression the target is the first argument, as for every
  helper.

A call that cannot be rewritten is left as it is: the validator then finds a
name the dialect does not have (``RM-D-HELPER-UNAVAILABLE``).
"""

import copy
import json
import os
import re

from ..stock import DATA_DIR

CURRENT = "5.0"
RC1 = "5.0-rc1"
DIALECTS = (RC1, CURRENT)
DEFAULT = CURRENT

HELPERS_PATH = os.path.join(DATA_DIR, "helpers-5.0.0.json")
RENAMES_PATH = os.path.join(DATA_DIR, "helper-renames-41150.json")

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TOKEN_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$.@-")
_OPERATORS = ("AND", "OR", "NOT")
CIDR_OLD, CIDR_NEW = "ip_cidr_match", "in_cidr"
_CACHE = {}


class HelperError(Exception):
    pass


def _load(path):
    if path not in _CACHE:
        with open(path, "r", encoding="utf-8") as fh:
            _CACHE[path] = json.load(fh)
    return _CACHE[path]


def renames():
    """Plain renames of #41150 (old -> new), both sides plain names."""
    table = _load(RENAMES_PATH)["renames"]
    return {o: n for o, n in table.items() if _NAME.match(n)}


def known(dialect):
    """The helper names the engine of ``dialect`` registers."""
    if dialect not in DIALECTS:
        raise HelperError("unknown engine helper dialect %r (expected one of %s)" % (dialect, ", ".join(DIALECTS)))
    current = set(_load(HELPERS_PATH)["helpers"])
    if dialect == CURRENT:
        return frozenset(current)
    data = _load(RENAMES_PATH)
    plain = renames()
    old = (current - set(plain.values()) - set(data.get("added_after_rc1", {}).get("helpers", []))) | set(data["renames"])
    return frozenset(old)


def _to_old():
    """New -> old for the plain renames. A new name with several old ones
    (``number_eq`` <- ``number_equal``, ``int_equal``) takes the one with the
    same prefix."""
    by_new = {}
    for o, n in renames().items():
        by_new.setdefault(n, []).append(o)
    out = {}
    for n, olds in by_new.items():
        olds = sorted(olds)
        same = [o for o in olds if o.split("_", 1)[0] == n.split("_", 1)[0]]
        out[n] = (same or olds)[0]
    out.pop(CIDR_NEW, None)  # signature change: see _cidr_to_old
    return out


# -- scanning -------------------------------------------------------------------------
def _skip_quoted(text, i):
    """Index after the quoted string that starts at ``text[i]``."""
    q = text[i]
    i += 1
    while i < len(text):
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == q:
            return i + 1
        i += 1
    return i


def _close(text, i):
    """Index of the parenthesis that closes the one at ``text[i]`` (or -1)."""
    depth = 0
    while i < len(text):
        c = text[i]
        if c in "'\"":
            i = _skip_quoted(text, i)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def calls(text):
    """Helper calls outside quotes: ``[(name, start, open, close)]``, nested
    ones included. A name is a plain identifier right before ``(``; ``$refs``
    and dotted names are not calls."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c in "'\"":
            i = _skip_quoted(text, i)
            continue
        if c in _TOKEN_CHARS:
            j = i
            while j < n and text[j] in _TOKEN_CHARS:
                j += 1
            tok = text[i:j]
            if j < n and text[j] == "(" and _NAME.match(tok) and tok not in _OPERATORS:
                end = _close(text, j)
                out.append((tok, i, j, end if end >= 0 else n - 1))
            i = j
            continue
        i += 1
    return out


def split_args(args):
    """Top-level arguments of a call (commas outside quotes and parentheses), stripped."""
    parts, depth, cur, i = [], 0, [], 0
    while i < len(args):
        c = args[i]
        if c in "'\"":
            j = _skip_quoted(args, i)
            cur.append(args[i:j])
            i = j
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if c == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    last = "".join(cur).strip()
    if last or parts:
        parts.append(last)
    return parts


def _unquote(s):
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"" and "\\" not in s:
        return s[1:-1]
    return None


# -- rewriting -----------------------------------------------------------------------
def _cidr_to_old(args, expr):
    """``in_cidr`` arguments -> rc1 text, or None when there is no rc1 form."""
    parts = split_args(args)
    target = []
    if expr:
        if not parts or not parts[0].startswith("$"):
            return None
        target, parts = [parts[0]], parts[1:]
    if not parts:
        return None
    calls_ = []
    for p in parts:
        net = _unquote(p)
        if net is None or net.count("/") != 1:
            return None
        addr, mask = net.split("/")
        calls_.append("%s(%s)" % (CIDR_OLD, ", ".join(target + ["'%s'" % addr, "'%s'" % mask])))
    if len(calls_) == 1:
        return calls_[0]
    if not expr:
        return None  # field: value form takes one call only
    return "(" + " OR ".join(calls_) + ")"


def _cidr_to_new(args, expr):
    parts = split_args(args)
    target = []
    if expr:
        if not parts or not parts[0].startswith("$"):
            return None
        target, parts = [parts[0]], parts[1:]
    if len(parts) != 2:
        return None
    addr, mask = _unquote(parts[0]), _unquote(parts[1])
    if addr is None or mask is None:
        return None
    return "%s(%s)" % (CIDR_NEW, ", ".join(target + ["'%s/%s'" % (addr, mask)]))


def _rewrite_text(text, names, cidr, expr):
    """Rename the calls of ``text`` with ``names`` and the cidr call with
    ``cidr(args, expr)``; right to left so that offsets stay valid."""
    found = calls(text)
    # outermost first is not needed: helper arguments are values or references
    for name, start, op, end in sorted(found, key=lambda t: -t[1]):
        if name == cidr[0]:
            new = cidr[1](text[op + 1:end], expr)
            if new is not None:
                text = text[:start] + new + text[end + 1:]
        elif name in names:
            text = text[:start] + names[name] + text[op:]
    return text


def _walk(res, fn):
    """Apply ``fn(text, expr)`` to every helper site of a decoder resource:
    ``check`` (an expression, or a list of ``{field: value}``) and the
    ``check``/``map`` of every ``normalize`` block. ``parse|*`` is not touched."""
    res = copy.deepcopy(res)

    def check(value):
        if isinstance(value, str):
            return fn(value, True)
        if isinstance(value, list):
            return [{k: fn(v, False) if isinstance(v, str) else v for k, v in e.items()} if isinstance(e, dict) else e
                    for e in value]
        return value

    def mapping(value):
        if isinstance(value, list):
            return [{k: fn(v, False) if isinstance(v, str) else v for k, v in e.items()} if isinstance(e, dict) else e
                    for e in value]
        return value

    if "check" in res:
        res["check"] = check(res["check"])
    if "map" in res:
        res["map"] = mapping(res["map"])
    if isinstance(res.get("normalize"), list):
        blocks = []
        for b in res["normalize"]:
            if isinstance(b, dict):
                b = dict(b)
                if "check" in b:
                    b["check"] = check(b["check"])
                if "map" in b:
                    b["map"] = mapping(b["map"])
            blocks.append(b)
        res["normalize"] = blocks
    return res


def to_dialect(res, dialect):
    """A decoder resource in current names rewritten to ``dialect``."""
    known(dialect)
    if dialect == CURRENT:
        return copy.deepcopy(res)
    names = _to_old()
    return _walk(res, lambda t, expr: _rewrite_text(t, names, (CIDR_NEW, _cidr_to_old), expr))


def to_current(res):
    """A decoder resource in rc1 names rewritten to the current ones (for
    ``scripts/build_base.py``). Raises HelperError on an old name with no
    plain rewrite."""
    names = {o: n for o, n in renames().items() if o != CIDR_OLD}
    out = _walk(res, lambda t, expr: _rewrite_text(t, names, (CIDR_OLD, _cidr_to_new), expr))
    left = sorted(n for n in names_in(out) if n in _load(RENAMES_PATH)["renames"] and n not in known(CURRENT))
    if left:
        raise HelperError("old helper name(s) with no automatic rewrite: %s" % ", ".join(left))
    return out


def names_in(res):
    """Every helper name called in a decoder resource."""
    seen = set()

    def collect(text, expr):
        for name, _s, _o, _e in calls(text):
            seen.add(name)
        return text

    _walk(res, collect)
    return seen


def unavailable(res, dialect):
    """Names called in ``res`` that the engine of ``dialect`` does not register."""
    return sorted(names_in(res) - known(dialect))


__all__ = ["CURRENT", "RC1", "DIALECTS", "DEFAULT", "HelperError", "known", "renames", "calls", "split_args",
           "to_dialect", "to_current", "names_in", "unavailable"]
