"""Decoders: RE2 with ``regex_match`` in ``check`` and one
``regex_extract`` per capture, ``<order>`` to temporaries ``_c<n>`` and one
``map`` per decided field, converted to its WCS type.

4.x decoders with the same name are one 5.x decoder: the first one gives the
``check``; each one adds its extraction block (offsets composed in the
order the 4.x pointer moves). Parents are referred to by name: a custom parent
is ``decoder/wazuh4-<parent>/0``; a root decoder hangs from the predecoder of
``wazuh4-base``, which repeats the 4.x pre-decoding: ``process.name`` is the
4.x ``program_name`` and ``message`` the text 4.x decoders read. A stock parent
is recreated from the user's own 4.x stock ruleset (``stock_parents`` of
:func:`rmig.translate.engine.load_base`).
"""

from ..fields import static_destination
from .meta import PREFIX, slug
from .patterns import PatternError, compose_re2, helper_quote, to_re2

NUMERIC = ("long", "integer", "short", "byte")
FLOATING = ("float", "double", "scaled_float", "half_float")


def decoder_name(name4):
    return "decoder/%s%s/0" % (PREFIX, slug(name4))


def convert_expr(wcs_type, temp):
    """(expression, ok) mapping temporary ``temp`` to a field of ``wcs_type``."""
    if wcs_type in ("keyword", "match_only_text", "text", "wildcard", "constant_keyword"):
        return "$%s" % temp, True
    if wcs_type in NUMERIC:
        return "parse_long($%s)" % temp, True
    if wcs_type in FLOATING:
        return "parse_double($%s)" % temp, True
    if wcs_type == "ip":
        return "parse_ip($%s)" % temp, True
    if wcs_type == "boolean":
        return "parse_bool($%s)" % temp, True
    return None, False


class DecoderGroup:
    """Every registered custom 4.x decoder with one name, in load order."""

    def __init__(self, name, uids):
        self.name = name
        self.uids = uids
        self.resource = None
        self.text_field = None
        self.codes = {}  # uid -> [(code, detail)]
        self.notes = {}
        # lower-case 4.x field name -> [value expression], in extraction order: what a decoder-side
        # rule check (RM-F-DECODER-CHECK) copies into a temporary of its own
        self.field_exprs = {}


class DecoderTranslator:
    def __init__(self, tr):
        self.tr = tr
        self.clf = tr.clf
        self.base = tr.base
        self.groups = {}
        for name, uids in sorted(self.clf.custom_decoders.items(), key=lambda kv: self._order(kv[1][0])):
            self.groups[name] = DecoderGroup(name, list(uids))

    def _order(self, uid):
        it = self.clf.items[uid]
        return (it["file"], it["line"])

    def item(self, uid):
        return self.clf.items[uid]

    # -- structure -------------------------------------------------------------
    def parent_info(self, group):
        """(parent 5.x name or None, text field, problem code or None)."""
        first = self.item(group.uids[0])
        node = self.clf.load.dec_nodes[group.uids[0]]
        parents = node.get("parents", [])
        if not first["parent"]:
            return self.base["predecoder"], "message", None
        pnode = self.clf.load.dec_nodes[parents[0]] if parents else None
        if pnode is not None and pnode["origin"] == "custom":
            pgroup = self.groups.get(pnode["name"])
            ptext = self.text_field(pgroup) if pgroup else "message"
            return decoder_name(pnode["name"]), ptext, None
        stock_def = self.base.get("stock_parents", {}).get(first["parent"])
        if stock_def is None:
            return None, "message", ("RM-D-STOCK-PARENT", "%s: no recreated definition in wazuh4-base.json" % first["parent"])
        return stock_def["resource"]["name"], stock_def.get("text_field", "message"), None

    def text_field(self, group):
        if group.text_field is None:
            group.text_field = "message"  # guard against cycles
            group.text_field = self.parent_info(group)[1]
        return group.text_field

    def top_name(self, name):
        """Name of the top custom decoder of the chain of ``name``."""
        seen = set()
        while name not in seen:
            seen.add(name)
            g = self.groups.get(name)
            if g is None:
                return name
            p = self.item(g.uids[0])["parent"]
            if not p or p not in self.groups:
                return name
            name = p
        return name

    def descendants(self, name):
        """Custom decoder names under ``name`` (not included), parents first."""
        out = []
        frontier = [name]
        while frontier:
            nxt = []
            for gname, g in self.groups.items():
                p = self.item(g.uids[0])["parent"]
                if p in frontier and gname not in out and gname != name:
                    out.append(gname)
                    nxt.append(gname)
            frontier = nxt
        return out

    def ancestors(self, name):
        out = []
        cur = name
        while True:
            g = self.groups.get(cur)
            if g is None:
                break
            p = self.item(g.uids[0])["parent"]
            if not p or p not in self.groups or p in out:
                break
            out.append(p)
            cur = p
        return out

    # -- patterns ----------------------------------------------------------------
    def _form(self, el, problems, uid):
        if el is None:
            return None
        try:
            return to_re2(el["engine"], el["value"])
        except PatternError as exc:
            code = "RM-D-REGEX-UNSUPPORTED" if el["engine"] == "pcre2" else "RM-X-INVALID"
            problems.append((uid, code, "%s %r: %s" % (el["engine"], el["value"], exc)))
            return None

    def translate_group(self, group):
        """Build the 5.x decoder of a group. Codes go to ``group.codes``."""
        problems = []
        parent, text, pcode = self.parent_info(group)
        first_uid = group.uids[0]
        if pcode:
            problems.append((first_uid, pcode[0], pcode[1]))
        first = self.item(first_uid)
        parent_pre = None
        pnode_parents = self.clf.load.dec_nodes[first_uid].get("parents", [])
        if pnode_parents:
            pn = self.clf.load.dec_nodes[pnode_parents[0]]
            if pn["origin"] == "custom":
                pitem = self.item(self.groups[pn["name"]].uids[0]) if pn["name"] in self.groups else None
                if pitem is not None and pitem["prematch"]:
                    parent_pre = self._form(pitem["prematch"], [], first_uid)
        checks = []
        if not first["parent"] and not first["program_name"]:
            # 4.x keeps two lists of root decoders: an event with a program name is only tried against the
            # roots that have <program_name>, one without it only against the others
            # (wazuh@4.14.10:src/analysisd/decoders/decoders_list.c OS_GetFirstOSDecoder, OS_AddOSDecoder).
            checks.append("not_exists($process.name)")
        if first["program_name"]:
            pf = self._form(first["program_name"], problems, first_uid)
            if pf is not None:
                checks.append("regex_match($process.name, %s)" % helper_quote(pf.pattern()))
        pre_form = self._form(first["prematch"], problems, first_uid)
        pre_prefix = []
        if first["prematch"] and first["prematch"].get("offset") == "after_parent" and parent_pre is not None:
            pre_prefix = [parent_pre]
        if pre_form is not None:
            checks.append("regex_match($%s, %s)" % (text, helper_quote(compose_re2(pre_prefix, pre_form))))
            self._unanchored(pre_prefix, problems, first_uid)
        normalize = []
        temp = 0
        prev_chain = None  # (prefix forms, regex form) of the previous sibling
        mapped_any = False
        for n, uid in enumerate(group.uids):
            it = self.item(uid)
            if n > 0 and self.tr.state(uid) != "AUTO":
                continue
            rx = it["regex"]
            if rx is None:
                prev_chain = None
                continue
            rform = self._form(rx, problems, uid)
            if rform is None:
                continue
            offset = rx.get("offset")
            own_pre = self._form(it["prematch"], [], uid) if it["prematch"] else None
            if offset == "after_prematch":
                base_pre = own_pre or pre_form
                prefix = pre_prefix + ([base_pre] if base_pre is not None else [])
            elif offset == "after_parent":
                prefix = [parent_pre] if parent_pre is not None else []
            elif offset == "after_regex":
                prefix = (prev_chain[0] + [prev_chain[1]]) if prev_chain else []
            else:
                prefix = []
            self._unanchored(prefix, problems, uid)
            if n == 0 and pre_form is None:
                checks.append("regex_match($%s, %s)" % (text, helper_quote(compose_re2(prefix, rform))))
            prev_chain = (prefix, rform)
            extract, maps = [], []
            ncap = rform.parsed.groups
            for pos, word in enumerate(it["order"], start=1):
                if pos > ncap:
                    problems.append((uid, "RM-X-INVALID", "<order> names %d field(s) but the regex has %d capture group(s)" % (len(it["order"]), ncap)))
                    break
                temp += 1
                tname = "_c%d" % temp
                expr = "regex_extract($%s, %s)" % (text, helper_quote(compose_re2(prefix, rform, keep=pos)))
                extract.append({tname: expr})
                group.field_exprs.setdefault(word.lower(), []).append(expr)
                wcs = self._wcs(word)
                if wcs is None:
                    continue
                wtype = self.tr.wcs.type_of(wcs)
                expr, ok = convert_expr(wtype, tname)
                if not ok:
                    problems.append((uid, "RM-F-TYPE", "%s -> %s (%s): no conversion; left unmapped" % (word, wcs, wtype)))
                    continue
                maps.append({wcs: expr})
            if extract:
                normalize.append({"map": extract + maps})
                mapped_any = mapped_any or bool(maps)
        for uid, code, detail in problems:
            group.codes.setdefault(uid, []).append((code, detail))
        return parent, checks, normalize

    def _unanchored(self, prefix, problems, uid):
        for form in prefix:
            if any(not a.start for a in form.parsed.alts) and prefix.index(form) == 0:
                problems.append((uid, "RM-D-REGEX-DIALECT",
                                 "the offset is composed after an unanchored pattern: RE2 may take a later occurrence than 4.x"))
                return

    def _wcs(self, word):
        is_static, dest = static_destination(word)
        if is_static and dest:
            return dest
        action, wcs = self.clf.field_action(word)
        if action == "map":
            return wcs
        return None
