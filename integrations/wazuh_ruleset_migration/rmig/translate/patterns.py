"""4.x patterns (OS_Match, OS_Regex, PCRE2) to Sigma values and to RE2.

Every pattern is first parsed into *alternatives* (a top-level ``|``) made of
tokens, each alternative with its own start and end anchor:

``("lit", ch)``
    a literal character;
``("cls", key)``
    an OS_Regex class (``d D w W s S p t`` and ``any`` for ``\\.``) or a PCRE2
    escape class (``pd pD pw pW ps pS`` and ``any`` for ``.``);
``("set", negated, items)``
    a PCRE2 bracket class; items are ``(lo, hi)`` ranges or ``("esc", key)``;
``("open", capturing)`` / ``("close",)`` / ``("bar",)``
    a group and an alternation inside a group (PCRE2 only);
``("quant", text)``
    ``+ * ?`` or ``{n,m}`` applying to the previous token or group.

Character sets of OS_Regex come from ``wazuh@4.14.13:src/os_regex/os_regex_maps.c``
(``\\w`` = letters, digits, ``-``, ``_`` and ``@``; ``\\s`` = the space only;
``\\p`` = ``!"#$%&'()*+,-.:;<=>?[]{|}``). OS_Match and OS_Regex ignore case;
PCRE2 does not, unless the pattern starts with ``(?i)``.

Two renderings:

* :func:`to_sigma` gives the terms of a Sigma selection for a field: ``|re``
  values in the detector's dialect (validated by :mod:`.re_dialect`), or
  ``startswith``/``endswith``/``contains``/equality for a PCRE2 literal. It says
  whether the result is exact and, if not, why.
* :func:`to_re2` gives RE2 patterns for the engine helpers ``regex_match`` and
  ``regex_extract`` (always exact for OS_Match/OS_Regex; PCRE2 constructs that
  RE2 lacks are refused).
"""

import re

from . import re_dialect


class PatternError(Exception):
    """The pattern has a construct with no translation (or 4.x refuses it)."""


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------

class Alt:
    __slots__ = ("start", "end", "tokens")

    def __init__(self, start, end, tokens):
        self.start = start
        self.end = end
        self.tokens = tokens

    def is_literal(self):
        return all(t[0] == "lit" for t in self.tokens)

    def text(self):
        return "".join(t[1] for t in self.tokens)


class Parsed:
    __slots__ = ("engine", "ci", "alts", "groups")

    def __init__(self, engine, ci, alts, groups):
        self.engine = engine
        self.ci = ci
        self.alts = alts
        self.groups = groups  # number of capturing groups (all alternatives)


def _split_top(pattern, escape=True):
    """Split on top-level ``|`` (outside escapes, groups and classes)."""
    parts, cur, depth, i, in_set = [], [], 0, 0, False
    n = len(pattern)
    while i < n:
        c = pattern[i]
        if escape and c == "\\" and i + 1 < n:
            cur.append(pattern[i:i + 2])
            i += 2
            continue
        if in_set:
            if c == "]":
                in_set = False
            cur.append(c)
            i += 1
            continue
        if escape and c == "[":
            in_set = True
            cur.append(c)
            # a ']' right after '[' or '[^' is a member
            if i + 1 < n and pattern[i + 1] == "^":
                cur.append("^")
                i += 1
            if i + 1 < n and pattern[i + 1] == "]":
                cur.append("]")
                i += 1
            i += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        if c == "|" and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts


def _anchors(alt):
    start = alt.startswith("^")
    if start:
        alt = alt[1:]
    end = False
    if alt.endswith("$"):
        # an escaped '\$' is a literal
        k = len(alt) - 2
        backslashes = 0
        while k >= 0 and alt[k] == "\\":
            backslashes += 1
            k -= 1
        if backslashes % 2 == 0:
            end = True
            alt = alt[:-1]
    return start, end, alt


def parse_osmatch(pattern):
    """OS_Match: ``|`` alternatives, ``^``/``$`` anchors, every other character
    literal, case-insensitive (``os_regex_match.c``)."""
    alts = []
    for part in pattern.split("|"):
        start = part.startswith("^")
        if start:
            part = part[1:]
        end = part.endswith("$") and len(part) >= 1
        if end:
            part = part[:-1]
        alts.append(Alt(start, end, [("lit", c) for c in part]))
    return Parsed("osmatch", True, alts, 0)


_OSREGEX_CLASSES = "dwspDWSt"
_OSREGEX_LITERAL_ESCAPES = "()\\$|<"


def parse_osregex(pattern):
    """OS_Regex (``os_regex_compile.c``): escapes ``\\d \\w \\s \\p \\D \\W \\S \\t
    \\.``, literal escapes ``\\( \\) \\\\ \\$ \\| \\<``, ``+``/``*`` only after a
    class, one level of capture groups, case-insensitive."""
    alts = []
    groups = 0
    for part in _split_top(pattern, escape=True):
        start, end, body = _anchors(part)
        tokens = []
        depth = 0
        i, n = 0, len(body)
        while i < n:
            c = body[i]
            if c == "\\":
                if i + 1 >= n:
                    raise PatternError("trailing backslash")
                e = body[i + 1]
                i += 2
                if e in _OSREGEX_CLASSES:
                    tokens.append(("cls", e))
                elif e == ".":
                    tokens.append(("cls", "any"))
                elif e in _OSREGEX_LITERAL_ESCAPES:
                    tokens.append(("lit", e))
                    continue
                else:
                    raise PatternError("invalid OS_Regex escape \\%s (4.x refuses the pattern)" % e)
                if i < n and body[i] in "+*":
                    tokens.append(("quant", body[i]))
                    i += 1
                continue
            if c == "(":
                depth += 1
                if depth > 1:
                    raise PatternError("nested parentheses (4.x refuses the pattern)")
                groups += 1
                tokens.append(("open", True))
            elif c == ")":
                if depth == 0:
                    raise PatternError("unbalanced ')'")
                depth -= 1
                tokens.append(("close",))
            else:
                tokens.append(("lit", c))
            i += 1
        if depth:
            raise PatternError("unbalanced '('")
        alts.append(Alt(start, end, tokens))
    return Parsed("osregex", True, alts, groups)


_PCRE_CLASS_ESC = "dDwWsS"
_PCRE_UNSUPPORTED_ESC = "bBAzZGQEKkgpPXRhHvVNC0123456789"
_QUANT_RE = re.compile(r"\{(\d+)(,(\d*))?\}")


def _pcre_set(body, i):
    """Parse a bracket class starting after '['. Returns (token, new index)."""
    n = len(body)
    neg = False
    if i < n and body[i] == "^":
        neg = True
        i += 1
    items = []
    first = True
    while i < n:
        c = body[i]
        if c == "]" and not first:
            return ("set", neg, items), i + 1
        first = False
        if c == "[" and body.startswith("[:", i):
            raise PatternError("POSIX class inside brackets")
        if c == "\\":
            if i + 1 >= n:
                raise PatternError("trailing backslash")
            e = body[i + 1]
            i += 2
            if e in _PCRE_CLASS_ESC:
                items.append(("esc", e))
                continue
            if e in "tnr":
                lo = {"t": "\t", "n": "\n", "r": "\r"}[e]
            elif e.isalnum():
                raise PatternError("escape \\%s inside a class" % e)
            else:
                lo = e
        else:
            lo = c
            i += 1
        if i + 1 < n and body[i] == "-" and body[i + 1] != "]":
            hi = body[i + 1]
            if hi == "\\":
                if i + 2 >= n or body[i + 2].isalnum():
                    raise PatternError("escaped range end inside a class")
                hi = body[i + 2]
                i += 3
            else:
                i += 2
            if ord(hi) < ord(lo):
                raise PatternError("invalid range %s-%s" % (lo, hi))
            items.append((lo, hi))
        else:
            items.append((lo, lo))
    raise PatternError("unclosed '['")


def parse_pcre2(pattern):
    """A PCRE2 subset that both RE2 and the Sigma dialect can carry:
    literals, ``.``, escapes ``\\d \\D \\w \\W \\s \\S``, bracket classes, groups
    (capturing, ``(?:``, named), alternation, ``* + ? {n,m}`` (lazy accepted),
    ``^`` at the start and ``$`` at the end of an alternative, and a leading
    ``(?i)``. Lookarounds, back references, word boundaries, possessive and
    atomic groups, inline flags elsewhere: :class:`PatternError`."""
    ci = False
    if pattern.startswith("(?i)"):
        ci = True
        pattern = pattern[4:]
    alts = []
    groups = 0
    for part in _split_top(pattern, escape=True):
        start, end, body = _anchors(part)
        tokens = []
        depth = 0
        i, n = 0, len(body)
        while i < n:
            c = body[i]
            if c == "\\":
                if i + 1 >= n:
                    raise PatternError("trailing backslash")
                e = body[i + 1]
                if e in _PCRE_CLASS_ESC:
                    tokens.append(("cls", "p" + e))
                    i += 2
                elif e in "tnr":
                    tokens.append(("lit", {"t": "\t", "n": "\n", "r": "\r"}[e]))
                    i += 2
                elif e == "x" and re.match(r"[0-9A-Fa-f]{2}", body[i + 2:i + 4]):
                    tokens.append(("lit", chr(int(body[i + 2:i + 4], 16))))
                    i += 4
                elif e.isalnum() or e in _PCRE_UNSUPPORTED_ESC:
                    raise PatternError("PCRE2 escape \\%s has no translation" % e)
                else:
                    tokens.append(("lit", e))
                    i += 2
            elif c == ".":
                tokens.append(("cls", "any"))
                i += 1
            elif c == "[":
                tok, i = _pcre_set(body, i + 1)
                tokens.append(tok)
            elif c == "(":
                if body.startswith("(?:", i):
                    tokens.append(("open", False))
                    i += 3
                elif body.startswith("(?P<", i) or (body.startswith("(?<", i) and not body.startswith("(?<=", i)
                                                     and not body.startswith("(?<!", i)):
                    close = body.find(">", i)
                    if close < 0:
                        raise PatternError("unclosed group name")
                    tokens.append(("open", True))
                    groups += 1
                    i = close + 1
                elif body.startswith("(?", i):
                    raise PatternError("PCRE2 group %s has no translation" % body[i:i + 3])
                else:
                    tokens.append(("open", True))
                    groups += 1
                    i += 1
                depth += 1
            elif c == ")":
                if depth == 0:
                    raise PatternError("unbalanced ')'")
                depth -= 1
                tokens.append(("close",))
                i += 1
            elif c == "|":
                tokens.append(("bar",))
                i += 1
            elif c in "*+?":
                if not tokens or tokens[-1][0] in ("open", "bar", "quant"):
                    raise PatternError("quantifier without operand")
                q = c
                i += 1
                if i < n and body[i] == "?":
                    i += 1  # lazy: same match/no-match result
                elif i < n and body[i] == "+":
                    raise PatternError("possessive quantifier")
                tokens.append(("quant", q))
            elif c == "{":
                mq = _QUANT_RE.match(body, i)
                if mq and tokens and tokens[-1][0] not in ("open", "bar", "quant"):
                    tokens.append(("quant", mq.group(0)))
                    i = mq.end()
                    if i < n and body[i] == "?":
                        i += 1
                else:
                    tokens.append(("lit", "{"))
                    i += 1
            elif c in "^$":
                raise PatternError("'%s' in the middle of the pattern" % c)
            else:
                tokens.append(("lit", c))
                i += 1
        if depth:
            raise PatternError("unbalanced '('")
        alts.append(Alt(start, end, tokens))
    return Parsed("pcre2", ci, alts, groups)


def parse(engine, pattern):
    if engine == "osmatch":
        return parse_osmatch(pattern)
    if engine == "osregex":
        return parse_osregex(pattern)
    if engine == "pcre2":
        return parse_pcre2(pattern)
    if engine == "string":
        return Parsed("string", False, [Alt(True, True, [("lit", c) for c in pattern])], 0)
    raise PatternError("unknown engine %s" % engine)


# --------------------------------------------------------------------------
# Sigma (detector dialect)
# --------------------------------------------------------------------------

SIGMA_PLAIN = set("_:=,;!%'`-")
SIGMA_CLASSABLE = set(".?+*|{}()#@&<>~")

_SIGMA_CLASS = {
    "d": ("[0-9]", True),
    "D": ("[^0-9]", True),
    "w": ("[-A-Za-z0-9_@]", True),
    "W": ("[^-A-Za-z0-9_@]", True),
    "s": (".", False),
    "S": ("[!-~]", False),
    "p": ("[-!#%&'()*+,.:;<=>?{|}]", False),
    "t": (".", False),
    "any": (".", True),
    "pd": ("[0-9]", True),
    "pD": ("[^0-9]", True),
    "pw": ("[A-Za-z0-9_]", True),
    "pW": ("[^A-Za-z0-9_]", True),
    "ps": (".", False),
    "pS": ("[!-~]", False),
}
_SIGMA_CLASS_WHY = {
    "s": "\\s (a space) became '.'",
    "S": "\\S became [!-~] (no characters outside ASCII)",
    "p": "\\p lost '\"', '$', '[' and ']'",
    "t": "\\t became '.'",
    "ps": "\\s became '.'",
    "pS": "\\S became [!-~] (no characters outside ASCII)",
}


def _sigma_char(c, ci):
    """(text, exact, why)."""
    if ci and c.upper() != c.lower() and len(c.upper()) == 1 and len(c.lower()) == 1:
        return "[%s%s]" % (c.upper(), c.lower()), True, None
    if c.isascii() and c.isalnum():
        return c, True, None
    if c in SIGMA_PLAIN:
        return c, True, None
    if c in SIGMA_CLASSABLE:
        return "[%s]" % c, True, None
    if not c.isascii() and not c.isspace() and c.isprintable():
        return c, True, None
    shown = {" ": "a space", "/": "'/'", "\t": "a tab"}.get(c, repr(c))
    return ".", False, "%s became '.'" % shown


def _sigma_set_char(c):
    if c.isascii() and c.isalnum():
        return c
    if c in SIGMA_PLAIN or c in SIGMA_CLASSABLE:
        return c
    if not c.isascii() and not c.isspace() and c.isprintable():
        return c
    return None


def _sigma_set(neg, items, ci):
    """A PCRE2 bracket class in the dialect: (text, exact, why)."""
    parts = []
    hyphen = False
    for it in items:
        if it[0] == "esc":
            e = it[1]
            if e == "d":
                parts.append("0-9")
            elif e == "w":
                parts.append("A-Za-z0-9_")
            else:
                return ".", False, "a bracket class with \\%s became '.'" % e
            continue
        lo, hi = it
        if lo == "-" and hi == "-":
            hyphen = True
            continue
        a, b = _sigma_set_char(lo), _sigma_set_char(hi)
        if a is None or b is None or a == "-" or b == "-":
            return ".", False, "a bracket class with %r became '.'" % (lo if a is None else hi)
        if ci and lo == hi and lo.upper() != lo.lower():
            parts.append(lo.upper() + lo.lower())
        elif ci and lo != hi and lo.isalpha() and hi.isalpha():
            parts.append("%s-%s%s-%s" % (lo.lower(), hi.lower(), lo.upper(), hi.upper()))
        else:
            parts.append(a if lo == hi else "%s-%s" % (a, b))
    body = ("-" if hyphen else "") + "".join(parts)
    if not body:
        return ".", False, "an empty bracket class became '.'"
    return "[%s%s]" % ("^" if neg else "", body), True, None


def _sigma_alt(alt, ci):
    out = []
    exact = True
    why = []
    for tok in alt.tokens:
        kind = tok[0]
        if kind == "lit":
            text, ok, w = _sigma_char(tok[1], ci)
        elif kind == "cls":
            text, ok = _SIGMA_CLASS[tok[1]]
            w = None if ok else _SIGMA_CLASS_WHY.get(tok[1])
        elif kind == "set":
            text, ok, w = _sigma_set(tok[1], tok[2], ci)
        elif kind == "open":
            text, ok, w = "(", True, None
        elif kind == "close":
            text, ok, w = ")", True, None
        elif kind == "bar":
            text, ok, w = "|", True, None
        elif kind == "quant":
            text, ok, w = tok[1], True, None
        else:  # pragma: no cover
            raise PatternError("unknown token %r" % (tok,))
        out.append(text)
        if not ok:
            exact = False
            if w and w not in why:
                why.append(w)
    body = "".join(out)
    value = ("" if alt.start else ".*") + body + ("" if alt.end else ".*")
    if value.startswith(".*.*"):
        value = value[2:]
    if value.endswith(".*.*"):
        value = value[:-2]
    if value == "":
        value = ".*" if not (alt.start and alt.end) else value
    return value, exact, why


class SigmaForm:
    """Terms of a Sigma selection for one field: ``terms`` is a list of
    ``(modifier, [values])`` OR-ed together (modifier ``""`` is equality)."""

    __slots__ = ("terms", "exact", "why")

    def __init__(self, terms, exact, why):
        self.terms = terms
        self.exact = exact
        self.why = why


def _pcre_literal_terms(parsed):
    by_mod = {}
    for alt in parsed.alts:
        text = alt.text()
        if alt.start and alt.end:
            mod = ""
        elif alt.start:
            mod = "startswith"
        elif alt.end:
            mod = "endswith"
        else:
            mod = "contains"
        if text == "" and mod != "":
            return None
        by_mod.setdefault(mod, [])
        if text not in by_mod[mod]:
            by_mod[mod].append(text)
    return [(mod, by_mod[mod]) for mod in ("", "startswith", "endswith", "contains") if mod in by_mod]


def to_sigma(engine, pattern):
    """:class:`SigmaForm` for a pattern on a keyword field. Raises
    :class:`PatternError` when there is no form at all."""
    parsed = parse(engine, pattern)
    if engine in ("pcre2", "string") and not parsed.ci and all(a.is_literal() for a in parsed.alts):
        terms = _pcre_literal_terms(parsed)
        if terms is not None:
            return SigmaForm(terms, True, [])
    values, exact, why = [], True, []
    for alt in parsed.alts:
        v, ok, w = _sigma_alt(alt, parsed.ci)
        bad = re_dialect.problems(v)
        if bad:
            raise PatternError("no form in the detector dialect (%s)" % "; ".join(bad))
        if v not in values:
            values.append(v)
        if not ok:
            exact = False
            why.extend(x for x in w if x not in why)
    return SigmaForm([("re", values)], exact, why)


def literal_value(engine, pattern):
    """The exact value a pattern accepts when it is a fixed string (anchored at
    both ends, no class): used for numeric and IP fields. None otherwise."""
    try:
        parsed = parse(engine, pattern)
    except PatternError:
        return None
    if len(parsed.alts) != 1:
        return None
    alt = parsed.alts[0]
    if engine in ("osmatch", "osregex", "pcre2") and not (alt.start and alt.end):
        return None
    if not alt.is_literal():
        return None
    return alt.text()


def literal_values(engine, pattern):
    """Like :func:`literal_value` for every alternative; None if any is not."""
    try:
        parsed = parse(engine, pattern)
    except PatternError:
        return None
    out = []
    for alt in parsed.alts:
        if not (alt.start and alt.end) or not alt.is_literal():
            return None
        out.append(alt.text())
    return out


# --------------------------------------------------------------------------
# RE2 (engine helpers)
# --------------------------------------------------------------------------

_RE2_META = set("\\.^$|?*+()[]{}")
_RE2_CLASS = {
    "d": "[0-9]",
    "D": "[^0-9]",
    "w": "[-0-9@A-Z_a-z]",
    "W": "[^-0-9@A-Z_a-z]",
    "s": " ",
    "S": "[^ ]",
    "p": "[!-.:-?\\[\\]{-}]",
    "t": "\\t",
    "any": ".",
    "pd": "\\d",
    "pD": "\\D",
    "pw": "\\w",
    "pW": "\\W",
    "ps": "\\s",
    "pS": "\\S",
}


def _re2_char(c):
    if c in _RE2_META:
        return "\\" + c
    if c == "\t":
        return "\\t"
    if c == "\n":
        return "\\n"
    if c == "\r":
        return "\\r"
    return c


def _re2_set(neg, items):
    parts = []
    for it in items:
        if it[0] == "esc":
            parts.append("\\" + it[1])
            continue
        lo, hi = it
        esc = lambda ch: ("\\" + ch) if ch in "\\]-^[" else _re2_char(ch) if ch in "\t\n\r" else ch  # noqa: E731
        parts.append(esc(lo) if lo == hi else "%s-%s" % (esc(lo), esc(hi)))
    return "[%s%s]" % ("^" if neg else "", "".join(parts))


def _re2_tokens(tokens, lazy, keep):
    """Render tokens; ``keep`` is the 1-based capture index left capturing
    (0: none, -1: all)."""
    out = []
    idx = 0
    # OS_Regex stops a repetition as soon as the rest of the pattern can go
    # on (lazy), except when nothing follows: then it takes the whole run.
    last_operand = max([i for i, t in enumerate(tokens) if t[0] in ("lit", "cls", "set")] or [-1])
    for pos, tok in enumerate(tokens):
        kind = tok[0]
        if kind == "lit":
            out.append(_re2_char(tok[1]))
        elif kind == "cls":
            out.append(_RE2_CLASS[tok[1]])
        elif kind == "set":
            out.append(_re2_set(tok[1], tok[2]))
        elif kind == "open":
            if tok[1]:
                idx += 1
                out.append("(" if keep == -1 or keep == idx else "(?:")
            else:
                out.append("(?:")
        elif kind == "close":
            out.append(")")
        elif kind == "bar":
            out.append("|")
        elif kind == "quant":
            out.append(tok[1] + ("?" if lazy and tok[1] in "+*" and pos < last_operand else ""))
    return "".join(out), idx


class Re2Form:
    """RE2 rendering of a parsed pattern. ``alts`` keeps, per alternative,
    ``(start, end, body_renderer)`` so that callers can compose prematch and
    regex; :meth:`pattern` gives the whole pattern."""

    def __init__(self, parsed):
        self.parsed = parsed
        self.lazy = parsed.engine == "osregex"
        self.flags = "(?i)" if parsed.ci else ""

    def bodies(self, keep=-1):
        """[(start, end, body)] with capture group ``keep`` (global index)."""
        res = []
        offset = 0
        for alt in self.parsed.alts:
            n = sum(1 for t in alt.tokens if t[0] == "open" and t[1])
            if keep == -1:
                local_keep = -1
            elif offset < keep <= offset + n:
                local_keep = keep - offset
            else:
                local_keep = 0
            body, _n = _re2_tokens(alt.tokens, self.lazy, local_keep)
            offset += n
            res.append((alt.start, alt.end, body))
        return res

    def pattern(self, keep=-1):
        parts = []
        for start, end, body in self.bodies(keep):
            parts.append(("^" if start else "") + body + ("$" if end else ""))
        if len(parts) == 1:
            return self.flags + parts[0]
        return self.flags + "(?:" + "|".join(parts) + ")"


def to_re2(engine, pattern):
    """:class:`Re2Form` of a pattern (raises :class:`PatternError`)."""
    return Re2Form(parse(engine, pattern))


def compose_re2(prefix_forms, last_form, keep=-1, flags=""):
    """Compose patterns applied one after the other.

    Each element of ``prefix_forms`` is a :class:`Re2Form` whose match end is
    where the next one starts; ``last_form`` is applied after them. An
    alternative anchored with ``^`` starts exactly at the offset; one without
    it searches forward (``.*?``). Capture indexes in ``keep`` count only the
    groups of ``last_form``; the prefixes never capture."""
    forms = list(prefix_forms) + [last_form]
    out = []
    for n, form in enumerate(forms):
        is_last = n == len(forms) - 1
        bodies = form.bodies(keep if is_last else 0)
        alts = []
        for start, end, body in bodies:
            if n == 0:
                text = ("^" if start else "") + body
            else:
                text = ("" if start else ".*?") + body
            if end:
                text += "$"
            alts.append(text)
        piece = alts[0] if len(alts) == 1 else "(?:" + "|".join(alts) + ")"
        if form.parsed.ci and not flags:
            piece = "(?i:" + piece + ")"
        out.append(piece)
    return flags + "".join(out)


def helper_quote(regex):
    """A regex as a single-quoted literal argument of an engine helper: the
    quote becomes ``\\x27`` (RE2) and every backslash is doubled, as in the
    standard ``decoder/syslog/0``."""
    regex = regex.replace("'", "\\x27")
    return "'" + regex.replace("\\", "\\\\") + "'"


def collapse_doubled_backslash(engine, pattern):
    """The pattern with each pair of literal backslashes made one literal backslash.

    4.x keeps the JSON escaping in the values of the eventchannel decoder (``win.*``): a path separator is two
    backslashes there (the stock 4.14 rules write four backslashes in PCRE2 for one separator,
    0860-sysmon_id_13.xml),
    and the 5.x Windows integration stores one. Only for ``win.*`` conditions. A backslash in a bracket class,
    or a single literal backslash, is kept."""
    if not pattern or "\\" not in pattern:
        return pattern
    if engine == "osmatch":  # no escapes: a backslash is itself
        return re.sub(r"\\\\", r"\\", pattern)
    out = []
    i, n = 0, len(pattern)
    in_class = False
    while i < n:
        c = pattern[i]
        if c == "\\" and i + 1 < n:
            pair = pattern[i:i + 2]
            if pair == "\\\\" and not in_class and pattern[i + 2:i + 4] == "\\\\":
                out.append(pair)  # two escaped backslashes -> one
                i += 4
                continue
            out.append(pair)
            i += 2
            continue
        if engine == "pcre2":
            if c == "[" and not in_class:
                in_class = True
            elif c == "]" and in_class:
                in_class = False
        out.append(c)
        i += 1
    return "".join(out)
