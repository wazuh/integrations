"""Local reading of a rule's ``detection`` against a normalized event.

Two readers:

* :func:`evaluate` explains a result the server gave (which condition was not
  met); the fake indexer of the tests uses it too. It is lenient and never a
  verdict.
* :func:`verdict` is the strict reader of ``verify --engine-socket`` (no
  indexer): ``True`` (match), ``False`` (no match) or ``None`` (``NOT_CHECKED``:
  the rule uses a form this reader does not cover, or a form whose meaning
  differs between the indexer's logtest and its detector). It never guesses.
"""

import ipaddress
import re

from ..translate import re_dialect


def flatten(obj, prefix=""):
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = "%s.%s" % (prefix, k) if prefix else str(k)
            if isinstance(v, dict):
                out.update(flatten(v, key))
            else:
                out[key] = v
    return out


RE_MAX_INPUT = 4096  # longest value a regular expression is run on locally (the message field is not indexed above)


RE_STEP_BUDGET = 10 ** 8  # estimated backtracking steps (see too_costly) above this: NOT_CHECKED


def unbounded_quantifiers(pattern):
    """How many ``*``, ``+`` and ``{n,}`` the pattern has outside classes and escapes, without the ``.*`` the
    tool wraps a search in (one at the start, one at the end)."""
    core = pattern
    if core.startswith(".*"):
        core = core[2:]
    if core.endswith(".*") and not core.endswith("\\.*"):
        core = core[:-2]
    n, i = 0, 0
    while i < len(core):
        c = core[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            j = i + 1
            if j < len(core) and core[j] == "^":
                j += 1
            if j < len(core) and core[j] == "]":
                j += 1
            while j < len(core) and core[j] != "]":
                j += 2 if core[j] == "\\" else 1
            i = j + 1
            continue
        if c in "*+" and i > 0 and core[i - 1] not in "*+?":
            n += 1
        elif c == "{" and re.match(r"\{\d+,\}", core[i:]):
            n += 1
        i += 1
    return n


def too_costly(pattern, value):
    """True when Python's backtracking could need more than :data:`RE_STEP_BUDGET` steps on ``value``
    (adjacent quantifiers such as ``a*a*a*b``: polynomial, not exponential, but hours on a long value)."""
    k = unbounded_quantifiers(pattern)
    # a leading .* adds one more factor of len(value) once the core can backtrack (measured: .*f.*o.* takes 23 s on
    # 4096 characters)
    exponent = k + 1 + (1 if pattern.startswith(".*") else 0)
    return k > 0 and len(value) ** exponent > RE_STEP_BUDGET


MAX_ALTERNATION_GROUPS = 8  # a chain of (a|a) groups doubles the backtracking paths per group


def _brace_repeats(text):
    """True when ``text`` starts with a ``{m}``, ``{m,}`` or ``{m,n}`` that can repeat more than once."""
    m = re.match(r"\{(\d*)(,?)(\d*)\}", text)
    if not m:
        return False
    low, comma, high = m.groups()
    if not comma:
        return low != "" and int(low) > 1
    return high == "" or int(high) > 1


def catastrophic(pattern):
    """Why ``pattern`` can make Python's backtracking ``re`` run for ages (nested quantifiers such as ``(a+)+``,
    ``(a*)*``, ``(a|aa)+``, ``(?:x+y?)*``), or None. The detector uses automata and is not affected; the local
    reader gives ``NOT_CHECKED`` instead of running it."""
    stack = [[False, False]]  # per open group: [has a quantifier, has an alternation]
    alternations = 0
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            j = i + 1
            if j < n and pattern[j] == "^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 2 if pattern[j] == "\\" else 1
            i = j + 1
            continue
        if c == "(":
            stack.append([False, False])
        elif c == ")":
            if len(stack) > 1:
                inner = stack.pop()
                nxt = pattern[i + 1] if i + 1 < n else ""
                repeated = (nxt != "" and nxt in "*+") or (nxt == "{" and _brace_repeats(pattern[i + 1:]))
                if repeated and (inner[0] or inner[1]):
                    return "a repeated group holds a quantifier or an alternation (nested quantifiers)"
                if inner[0] or repeated:
                    stack[-1][0] = True
                if inner[1]:
                    alternations += 1
                    if alternations > MAX_ALTERNATION_GROUPS:
                        return "more than %d groups with an alternation" % MAX_ALTERNATION_GROUPS
        elif c in "*+" or (c == "?" and i > 0 and pattern[i - 1] not in "(*+?}"):
            stack[-1][0] = True
        elif c == "{" and re.match(r"\{\d*,?\d*\}", pattern[i:]):
            stack[-1][0] = True
        elif c == "|":
            stack[-1][1] = True
        i += 1
    return None


def _as_list(v):
    return v if isinstance(v, list) else [v]


def _match_value(actual, expected, mods):
    if actual is None:
        return "exists" in mods and expected is False
    if "exists" in mods:
        return bool(expected)
    vals = [str(x) for x in _as_list(actual)]
    exp = str(expected)
    for a in vals:
        if "re" in mods:
            if catastrophic(exp) or len(a) > RE_MAX_INPUT or too_costly(exp, a):
                continue
            try:
                if re.search(exp, a):
                    return True
            except re.error:
                return False
            continue
        al, el = a.lower(), exp.lower()
        if "contains" in mods:
            if el in al:
                return True
        elif "startswith" in mods:
            if al.startswith(el):
                return True
        elif "endswith" in mods:
            if al.endswith(el):
                return True
        elif "*" in el or "?" in el:
            pat = "^" + re.escape(el).replace("\\*", ".*").replace("\\?", ".") + "$"
            if re.match(pat, al, re.S):
                return True
        elif al == el:
            return True
    return False


def eval_selection(sel, flat):
    """``(matched, [why not])`` for one named selection (a map, or a list of
    maps = OR)."""
    if isinstance(sel, list):
        reasons = []
        for alt in sel:
            ok, why = eval_selection(alt, flat) if isinstance(alt, dict) else (False, ["keyword search is not explained"])
            if ok:
                return True, []
            reasons.extend(why)
        return False, reasons
    if not isinstance(sel, dict):
        return False, ["unsupported selection"]
    why = []
    for key, expected in sel.items():
        field, _, mod = key.partition("|")
        mods = set(mod.split("|")) if mod else set()
        actual = flat.get(field)
        exps = _as_list(expected)
        if "all" in mods:
            ok = all(_match_value(actual, e, mods) for e in exps)
        else:
            ok = any(_match_value(actual, e, mods) for e in exps)
        if not ok:
            got = "absent" if actual is None else repr(actual)
            why.append("%s: expected %s%s, got %s" % (field, ("%s " % "|".join(sorted(mods))) if mods else "",
                                                       repr(expected), got))
    return not why, why


_TOKEN = re.compile(r"\(|\)|[^\s()]+")


class _Parser:
    def __init__(self, text, values):
        self.toks = _TOKEN.findall(text or "")
        self.i = 0
        self.values = values

    def peek(self):
        return self.toks[self.i].lower() if self.i < len(self.toks) else None

    def take(self):
        t = self.toks[self.i]
        self.i += 1
        return t

    def parse(self):
        v = self.expr_or()
        if self.i != len(self.toks):
            raise ValueError("trailing tokens")
        return v

    def expr_or(self):
        v = self.expr_and()
        while self.peek() == "or":
            self.take()
            r = self.expr_and()
            v = v or r
        return v

    def expr_and(self):
        v = self.expr_not()
        while self.peek() == "and":
            self.take()
            r = self.expr_not()
            v = v and r
        return v

    def expr_not(self):
        if self.peek() == "not":
            self.take()
            return not self.expr_not()
        return self.atom()

    def atom(self):
        t = self.peek()
        if t is None:
            raise ValueError("unexpected end")
        if t == "(":
            self.take()
            v = self.expr_or()
            if self.peek() != ")":
                raise ValueError("missing )")
            self.take()
            return v
        if t in ("1", "all") and self.i + 2 < len(self.toks) and self.toks[self.i + 1].lower() == "of":
            self.take()
            self.take()
            pat = self.take()
            names = [n for n in self.values if re.match("^" + re.escape(pat).replace("\\*", ".*") + "$", n)]
            if pat == "them":
                names = list(self.values)
            vals = [self.values[n] for n in names]
            return (any(vals) if t == "1" else all(vals)) if vals else False
        name = self.take()
        if name not in self.values:
            raise ValueError("unknown selection %s" % name)
        return self.values[name]


def evaluate(detection, event):
    """``(matched, [explanations of what was not met])``. ``event`` is the
    normalized document (nested or flat)."""
    detection = detection or {}
    flat = flatten(event) if any(isinstance(v, dict) for v in (event or {}).values()) else dict(event or {})
    values, why = {}, {}
    for name, sel in detection.items():
        if name == "condition":
            continue
        values[name], why[name] = eval_selection(sel, flat)
    cond = detection.get("condition", "selection")
    if isinstance(cond, list):
        cond = " or ".join("(%s)" % c for c in cond)
    try:
        matched = _Parser(cond, values).parse()
    except (ValueError, IndexError) as exc:
        return False, ["condition %r cannot be read locally: %s" % (cond, exc)]
    if matched:
        return True, []
    out = []
    for name in sorted(values):
        if not values[name] and why[name]:
            out.extend("%s: %s" % (name, w) for w in why[name])
        elif values[name] and re.search(r"\bnot\s+%s\b" % re.escape(name), cond):
            out.append("%s matched, and the condition excludes it (%s)" % (name, cond))
    return False, out or ["condition %r is false" % cond]


# -- strict reader (verify --engine-socket) ------------------------------------------------------------------------
#
# Three values: True, False, None (not covered). and/or/not follow Kleene logic, so an uncovered part changes
# nothing when the rest of the condition settles the result.
#
# Semantics, and why each choice is safe:
# * a field that is absent never matches (any modifier but ``exists``): the same on logtest and on the detector;
# * ``|re``: the value must pass the detector dialect validator (``translate/re_dialect.py``, the barrier every
#   emitted value passed) and have no Lucene operator or Python-only construct. The detector reads it as a
#   whole-term regexp; logtest may search. A verdict is given only when full match and search agree;
# * equality, ``contains``, ``startswith``, ``endswith``: logtest and the detector differ on letter case
#   (README, Limits). A verdict is given only when the case-sensitive and the case-insensitive comparison agree.
#   A ``*`` or ``?`` in the value is a Sigma wildcard: not covered;
# * ``cidr``: address in network (``ipaddress``); ``exists``: the field is present;
# * any other modifier, a keyword list, a value that is a map, a field inside a list of objects, or a condition
#   this parser does not read: not covered.

COVERED_MODIFIERS = ("re", "contains", "startswith", "endswith", "exists", "cidr")
_LUCENE_OPERATORS = set("&~<>@#\"")
_BAD_BRACE = re.compile(r"\{(?!\d+(?:,\d*)?\})")
_CLASS = re.compile(r"\[\^?\]?[^\]]*\]")


def _and3(values):
    values = list(values)
    if any(v is False for v in values):
        return False
    if any(v is None for v in values):
        return None
    return True


def _or3(values):
    values = list(values)
    if any(v is True for v in values):
        return True
    if any(v is None for v in values):
        return None
    return False


def _not3(v):
    return None if v is None else not v


class _Lookup:
    """Field values of a normalized event: dotted names, the nested and the flat form."""

    def __init__(self, event):
        event = event or {}
        self.flat = flatten(event) if any(isinstance(v, dict) for v in event.values()) else dict(event)

    def get(self, field):
        """``(value, covered)``; value None = absent."""
        if field in self.flat:
            return self.flat[field], True
        parts = field.split(".")
        for i in range(1, len(parts)):
            v = self.flat.get(".".join(parts[:i]))
            if isinstance(v, list) and any(isinstance(x, dict) for x in v):
                return None, False  # a field inside a list of objects
        return None, True


def _number(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _one(actual, expected, mod, why):
    """Verdict for one scalar ``actual`` against one ``expected`` value."""
    if isinstance(actual, (dict, list)):
        why.append("a list or an object value")
        return None
    if mod == "cidr":
        try:
            net = ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            why.append("cidr value %r is not a network" % (expected,))
            return None
        try:
            addr = ipaddress.ip_address(str(actual))
        except ValueError:
            why.append("cidr on a value that is not an address (%r)" % (actual,))
            return None
        return addr.version == net.version and addr in net
    if mod == "re":
        a = actual if isinstance(actual, str) else None  # a regexp on a number or a boolean field: not covered
        if not isinstance(expected, str) or a is None:
            why.append("re on a value that is not text")
            return None
        bare = _CLASS.sub("", expected)  # inside a [...] class these characters are literal in both dialects
        if re_dialect.problems(expected) or _LUCENE_OPERATORS & set(bare) or "(?" in bare or _BAD_BRACE.search(bare):
            why.append("re value %r is outside the covered dialect" % expected)
            return None
        bad = catastrophic(expected)
        if bad:
            why.append("re value %r is not run locally: %s" % (expected, bad))
            return None
        if len(a) > RE_MAX_INPUT:
            why.append("re on a value longer than %d characters is not run locally" % RE_MAX_INPUT)
            return None
        if too_costly(expected, a):
            why.append("re value %r is not run locally on a value of %d characters: too many unbounded quantifiers"
                       % (expected, len(a)))
            return None
        try:
            rx = re.compile(expected, re.S)
        except re.error:
            why.append("re value %r does not compile" % expected)
            return None
        full, found = rx.fullmatch(a) is not None, rx.search(a) is not None
        if full != found:
            why.append("re %r: whole-term and search differ on %r" % (expected, a))
            return None
        return full
    # equality and the substring modifiers
    if isinstance(expected, bool) or isinstance(actual, bool):
        if mod == "" and isinstance(expected, bool) and isinstance(actual, bool):
            return actual == expected
        why.append("boolean comparison of %r and %r" % (expected, actual))
        return None
    if isinstance(expected, (int, float)) or isinstance(actual, (int, float)):
        a, e = _number(actual), _number(expected)
        # number against number only: a text against a number field (or the reverse) has no recorded verdict
        if mod or a is None or e is None or isinstance(expected, str) or isinstance(actual, str):
            why.append("number comparison of %r and %r" % (expected, actual))
            return None
        return a == e
    if not isinstance(expected, str) or not isinstance(actual, str):
        why.append("value %r against %r" % (expected, actual))
        return None
    if "*" in expected or "?" in expected:
        why.append("wildcard in %r" % expected)
        return None
    op = {"": lambda x, y: x == y, "contains": lambda x, y: y in x,
          "startswith": lambda x, y: x.startswith(y), "endswith": lambda x, y: x.endswith(y)}[mod]
    cs, ci = op(actual, expected), op(actual.lower(), expected.lower())
    if cs != ci:
        why.append("%r against %r differs only in letter case" % (expected, actual))
        return None
    return cs


def _key(field_mods, expected, look, why):
    field, _, mod = field_mods.partition("|")
    mods = mod.split("|") if mod else []
    use_all = "all" in mods
    mods = [m for m in mods if m != "all"]
    if len(mods) > 1 or (mods and mods[0] not in COVERED_MODIFIERS):
        why.append("%s: modifier %s not covered" % (field, "|".join(mods)))
        return None
    mod = mods[0] if mods else ""
    actual, covered = look.get(field)
    if not covered:
        why.append("%s: inside a list of objects" % field)
        return None
    if mod == "exists":
        if not isinstance(expected, bool) or use_all:
            why.append("%s|exists: value %r" % (field, expected))
            return None
        if actual == []:
            why.append("%s|exists on an empty list" % field)
            return None
        return (actual is not None) == expected
    exps = expected if isinstance(expected, list) else [expected]
    if not exps or any(e is None or isinstance(e, (dict, list)) for e in exps):
        why.append("%s: empty, null or nested value" % field)
        return None
    if actual is None:
        return False
    vals = actual if isinstance(actual, list) else [actual]
    if not vals:
        return False
    per = [_or3([_one(a, e, mod, why) for a in vals]) for e in exps]
    return _and3(per) if use_all else _or3(per)


def _selection3(sel, look, why):
    if isinstance(sel, list):
        if not sel or not all(isinstance(x, dict) for x in sel):
            why.append("keyword search")
            return None
        return _or3([_selection3(x, look, why) for x in sel])
    if not isinstance(sel, dict) or not sel:
        why.append("selection of an unsupported form")
        return None
    return _and3([_key(k, v, look, why) for k, v in sorted(sel.items())])


class _Parser3(_Parser):
    """The condition grammar of :class:`_Parser` over three values."""

    def expr_or(self):
        vals = [self.expr_and()]
        while self.peek() == "or":
            self.take()
            vals.append(self.expr_and())
        return _or3(vals)

    def expr_and(self):
        vals = [self.expr_not()]
        while self.peek() == "and":
            self.take()
            vals.append(self.expr_not())
        return _and3(vals)

    def expr_not(self):
        if self.peek() == "not":
            self.take()
            return _not3(self.expr_not())
        return self.atom()

    def atom(self):
        t = self.peek()
        if t is None:
            raise ValueError("unexpected end")
        if t == "(":
            self.take()
            v = self.expr_or()
            if self.peek() != ")":
                raise ValueError("missing )")
            self.take()
            return v
        if t in ("1", "all") and self.i + 2 < len(self.toks) and self.toks[self.i + 1].lower() == "of":
            self.take()
            self.take()
            pat = self.take()
            if pat == "them":
                names = list(self.values)
            else:
                names = [n for n in self.values if re.match("^" + re.escape(pat).replace("\\*", ".*") + "$", n)]
            if not names:
                raise ValueError("no selection matches %s" % pat)
            vals = [self.values[n] for n in names]
            return _or3(vals) if t == "1" else _and3(vals)
        name = self.take()
        if name not in self.values:
            raise ValueError("unknown selection %s" % name)
        return self.values[name]


def verdict(detection, event):
    """``(True | False | None, [notes])``. True: the rule matches the event; False: it does not (notes: what was not
    met, from :func:`evaluate`); None: NOT_CHECKED (notes: the forms not covered)."""
    if not isinstance(detection, dict) or not isinstance(detection.get("condition"), (str, list)):
        return None, ["no readable condition"]
    look = _Lookup(event)
    values, why = {}, []
    for name, sel in sorted(detection.items()):
        if name != "condition":
            values[name] = _selection3(sel, look, why)
    cond = detection["condition"]
    if isinstance(cond, list):
        cond = " or ".join("(%s)" % c for c in cond)
    try:
        result = _Parser3(cond, values).parse()
    except (ValueError, IndexError) as exc:
        return None, ["condition %r is not read by the local reader: %s" % (cond, exc)]
    if result is None:
        notes = []
        for w in why:
            if w not in notes:
                notes.append(w)
        return None, notes or ["not covered"]
    if result:
        return True, []
    return False, evaluate(detection, event)[1]
