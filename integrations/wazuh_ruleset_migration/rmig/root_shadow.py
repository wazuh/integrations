"""Custom root decoders that 4.x never reaches.

analysisd keeps two lists of root decoders, in load order: those with
``<program_name>`` and those without (``wazuh@4.14.10:src/analysisd/decoders/
decoders_list.c``, ``OS_AddOSDecoder``). An event with a program name is tried
against the first list, an event without one against the second
(``OS_GetFirstOSDecoder``). ``DecodeEvent`` (``decoder.c``) stops at the first
root whose ``program_name`` and ``prematch`` match, whether or not a child
then matches: a later root is never tried for that event.

So a custom root decoder ``B`` never decodes anything when a root ``A`` of the
same list, loaded before it, accepts every event ``B`` accepts. This module
finds the cases that are provable from the XML alone, and nothing else:

* ``program_name`` (both present, or both absent: they are in the same list)
  and ``prematch`` of ``A`` each accept a superset of those of ``B``;
* a missing element accepts everything (``A`` without ``prematch``);
* an OS_Match or OS_Regex pattern with ``|`` is an OR: it accepts a superset
  when each alternative of ``B`` is covered by one alternative of ``A``;
* an element accepts a superset when it is identical (same engine, same text),
  or when both are plain literals (no metacharacter of their engine, ASCII) and
  ``A``'s literal is found in every text ``B``'s literal matches: substring
  for unanchored ``A``, prefix with ``^``, suffix with ``$`` (same engine),
  following the letter case of each engine (OS_Match and OS_Regex ignore case,
  PCRE2 does not).

Only the first such ``A`` counts. When it has the name of ``B`` (or is itself
shadowed by a decoder with that name), nothing is reported: the events go to
a decoder with that name anyway. A name is dead when every loaded decoder with
that name is: a shadowed root, or a child whose parents are all dead. Stock
decoders are never dead.
"""

import re

from .load_order import CUSTOM, STOCK_DECODER_DIR

# Characters that make a pattern something other than plain text, per engine.
# The sets are wider than strictly needed: an unsure case is not reported.
_META = {
    "osmatch": set("\\^$|!"),
    "osregex": set("\\^$|()*+?"),
    "pcre2": set("\\^$.|?*+()[]{}"),
}
_CASELESS = {"osmatch": True, "osregex": True, "pcre2": False}


def _literal(expr):
    """``(start, text, end, caseless)`` when ``expr`` is plain text with
    optional ``^``/``$`` anchors, else None."""
    engine = expr.get("engine")
    if engine not in _META:
        return None
    value = expr.get("value") or ""
    start = value.startswith("^")
    if start:
        value = value[1:]
    end = value.endswith("$")
    if end:
        value = value[:-1]
    if not value or any(ch in _META[engine] for ch in value):
        return None
    if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in value):
        return None
    return start, value, end, _CASELESS[engine]


def covers(a, b):
    """True when it is provable that pattern ``a`` matches every text that
    pattern ``b`` matches. ``None`` is a missing element: it matches
    everything."""
    if a is None:
        return True
    if b is None:
        return False
    if a.get("offset") or b.get("offset"):
        return False
    if a.get("engine") == b.get("engine") and a.get("value") == b.get("value"):
        return True
    alts_a, alts_b = _alternatives(a), _alternatives(b)
    if len(alts_a) > 1 or len(alts_b) > 1:
        # OS_Match and OS_Regex: "|" is an OR of patterns, each with its own anchors. Every
        # alternative of b must be covered by one alternative of a.
        return all(any(_covers_one(x, y) for x in alts_a) for y in alts_b)
    return _covers_one(a, b)


def _alternatives(expr):
    """The top-level ``|`` alternatives of an OS_Match or OS_Regex pattern
    (``[expr]`` when there is none, or when an escaped bar makes the split unsure)."""
    value = expr.get("value") or ""
    if expr.get("engine") not in ("osmatch", "osregex") or "|" not in value or "\\|" in value:
        return [expr]
    return [dict(expr, value=part) for part in value.split("|")]


def _covers_one(a, b):
    la, lb = _literal(a), _literal(b)
    if la is None or lb is None:
        return False
    a_start, a_text, a_end, a_caseless = la
    b_start, b_text, b_end, b_caseless = lb
    if a_end and a.get("engine") != b.get("engine"):
        return False  # "$" before a final newline in PCRE2, only at the end in OS_Regex
    if not a_caseless and b_caseless:
        # b also matches other letter cases: a must have no letters
        if a_text.lower() != a_text.upper():
            return False
    if a_caseless or b_caseless:
        a_text, b_text = a_text.lower(), b_text.lower()
    if a_start and not b_start:
        return False
    if a_end and not b_end:
        return False
    if a_start and a_end:
        return a_text == b_text
    if a_start:
        return b_text.startswith(a_text)
    if a_end:
        return b_text.endswith(a_text)
    return a_text in b_text


def _selector(el):
    return el.get("program_name"), el.get("prematch")


def shadows(a, b):
    """``a`` (loaded first) takes every event of root decoder ``b``."""
    a_pn, a_pm = _selector(a)
    b_pn, b_pm = _selector(b)
    if (a_pn is None) != (b_pn is None):
        return False  # different lists in analysisd
    if a_pn is None and a_pm is None:
        return False  # 4.x refuses such a root
    return covers(a_pn, b_pn) and covers(a_pm, b_pm)


def _usable(el):
    return not el.get("invalid") and not el.get("unknown")


def find(load, items, stock):
    """Dead custom decoders of a simulated load.

    Returns ``(dead_uids, dead_names)``: ``dead_uids`` maps the uid of every
    dead custom decoder to ``(why, winner)`` where ``why`` is ``"root"`` or
    ``"parent"`` and ``winner`` is ``{name, at}`` of the decoder that takes
    its events; ``dead_names`` maps a decoder name with every loaded decoder
    dead to the same ``winner``."""
    stock_by_loc = {(d["file"], d["line"]): d for d in stock.decoders}
    roots = []  # (node, element) of loaded roots, load order
    dead = {}
    for uid, node in load.dec_nodes.items():
        if node["origin"] == CUSTOM:
            el = items[uid]
            at = "%s:%d" % (el["file"], el["line"])
        else:
            el = items.get(uid) or stock_by_loc.get((node["file"], node["line"]))
            at = ("%s:%d" % (el["file"], el["line"]) if uid in items
                  else "%s/%s:%d" % (STOCK_DECODER_DIR, node["file"], node["line"]))
        if node.get("parents"):
            if node["origin"] == CUSTOM and all(p in dead for p in node["parents"]):
                dead[uid] = ("parent", dead[node["parents"][0]][1])
            continue
        if el is None:
            continue
        if node["origin"] == CUSTOM and _usable(el):
            for a_node, a_el, a_at in roots:
                if not (_usable(a_el) and shadows(a_el, el)):
                    continue
                # A shadowed winner has its own winner, loaded earlier, which takes these events too.
                winner = dead[a_node["uid"]][1] if a_node["uid"] in dead else {"name": a_node["name"], "at": a_at}
                if winner["name"] != node["name"]:
                    dead[uid] = ("root", winner)
                break  # the first root that takes the events decides
        roots.append((node, el, at))
    by_name = {}
    for uid, node in load.dec_nodes.items():
        by_name.setdefault(node["name"], []).append(uid)
    dead_names = {name: dead[uids[0]][1] for name, uids in by_name.items() if all(u in dead for u in uids)}
    return dead, dead_names


# -- likely shadows (not provable) -------------------------------------------
# A literal run of a stock prematch counts when it has this many characters.
_RUN_MIN = 4
_RUN_TOTAL = 12
_RUN_SPLIT = {
    "osregex": re.compile(r"\\.[+*]?|[\^$|()*+?]"),
    "osmatch": re.compile(r"[\\^$|!]"),
    "pcre2": re.compile(r"\\.|\[[^\]]*\][+*?]?|\{[^}]*\}|[\^$.|?*+()]"),
}


def _runs(expr):
    """Literal runs of a pattern, in order, lower case (the stock 4.x engines ignore case)."""
    split = _RUN_SPLIT.get(expr.get("engine"))
    if split is None:
        return []
    return [r.lower() for r in split.split(expr.get("value") or "") if r]


def likely_shadows(a, b):
    """``a`` (a stock root, loaded first) very probably takes the events of custom root ``b``: same list, no
    ``|`` in ``a``, and every distinctive literal run of ``a``'s prematch is found, in order, in ``b``'s
    prematch. Not a proof: a pattern can need more than its literals (``devid=`` then ``FG``)."""
    a_pn, a_pm = _selector(a)
    b_pn, b_pm = _selector(b)
    if (a_pn is None) != (b_pn is None) or a_pm is None or b_pm is None:
        return False
    if a_pn is not None and not covers(a_pn, b_pn):
        return False
    if a_pm.get("offset") or b_pm.get("offset") or "|" in (a_pm.get("value") or ""):
        return False
    runs = [r for r in _runs(a_pm) if len(r) >= _RUN_MIN]
    if len(runs) < 2 or sum(len(r) for r in runs) < _RUN_TOTAL:
        return False
    text = (b_pm.get("value") or "").lower()
    pos = 0
    for r in runs:
        i = text.find(r, pos)
        if i < 0:
            return False
        pos = i + len(r)
    return True


def find_likely(load, items, stock, dead):
    """Custom root decoders that a stock root loaded first very probably shadows (``likely_shadows``), and not
    already proven dead. Returns ``(uids, names)`` like ``find``: ``uids`` maps a custom decoder (the root and its
    children) to the stock winner ``{name, at}``; ``names`` a decoder name with every loaded decoder in it."""
    stock_by_loc = {(d["file"], d["line"]): d for d in stock.decoders}
    stock_roots = []
    likely = {}
    for uid, node in load.dec_nodes.items():
        if node.get("parents"):
            if node["origin"] == CUSTOM and uid not in dead and all(p in likely for p in node["parents"]):
                likely[uid] = likely[node["parents"][0]]
            continue
        if node["origin"] != CUSTOM:
            el = stock_by_loc.get((node["file"], node["line"]))
            if el is not None and _usable(el):
                stock_roots.append((node, el, "%s/%s:%d" % (STOCK_DECODER_DIR, node["file"], node["line"])))
            continue
        el = items[uid]
        if uid in dead or not _usable(el):
            continue
        for a_node, a_el, a_at in stock_roots:
            if a_node["name"] != node["name"] and likely_shadows(a_el, el):
                likely[uid] = {"name": a_node["name"], "at": a_at}
                break
    by_name = {}
    for uid, node in load.dec_nodes.items():
        by_name.setdefault(node["name"], []).append(uid)
    names = {name: likely[uids[0]] for name, uids in by_name.items() if all(u in likely for u in uids)}
    return likely, names
