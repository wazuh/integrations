"""Classification of every inventory item.

Each rule, decoder and list gets exactly one state and at least one reason
code from :mod:`rmig.reasons`. This stage knows what can be known without
translating: constructs with no 5.x support, fields without a decision, stock
content without equivalence, rules without a source, what 4.x itself discards,
and the tree semantics (grouping rules, silencers, shadowing, propagation).
Everything else is ``AUTO`` until the translator confirms it: with
``translate=True`` (``plan`` and ``build`` from the command line) the
translator runs after the classification and its codes decide the state.
"""

import re

from . import feeds as F
from . import model4 as m
from . import reasons as R
from . import root_shadow
from .decisions import feed_entry, field_action, json_check, list_action, stock_resolved
from .fields import STATIC_TO_WCS, TYPE_TO_CATEGORY, static_destination
from .load_order import CUSTOM, STOCK, simulate
from .stock import load_equivalence, load_stock_index
from .tree import RuleTree
from .winpack import load_pack

# 4.x alerts of a rule with no_full_log carry no original log line: verify cannot replay them
NO_FULL_LOG_NOTE = ("no_full_log: the 4.x alerts of this rule have no original log line, so verify cannot replay "
                    "them. Provide sample logs: verify --samples DIR, one line per event in DIR/<rule id>.log")
_JSON_GENERIC_PREMATCH = {"", "^{", "^\\{", "{", "^{\\s*\"", "^{\""}
# PCRE-style syntax that OS_Regex and OS_Match read as literal text
# (wazuh@4.14:src/os_regex/os_regex_compile.c: only \d \w \s \p \( \) \\ \D \W \S \. \t \$ \| \<, ( ) | ^ $
# and + * after a backslash class are special; OS_Match has only ^ $ | !)
_LITERAL_SYNTAX = (
    # class-shaped only: a leading ^, a range, or a count after ]; "[error]" or "[(\S+)]" is plain text on purpose
    (re.compile(r"\[(?:\^[^\]]*|[^\]]*[A-Za-z0-9]-[A-Za-z0-9][^\]]*)\]|\[[^\]]+\][*+?{]"), "class [...]"),
    (re.compile(r"(?<!\\)\.[*+]"), ".* or .+"),
    (re.compile(r"\{\d+(,\d*)?\}"), "count {n}"),
)


def literal_syntax(engine, value):
    """Names of the PCRE-style constructs an OS_Regex or OS_Match pattern
    holds as literal text (empty for PCRE2 and other engines)."""
    if engine not in ("osregex", "osmatch") or not value:
        return []
    return [name for rx, name in _LITERAL_SYNTAX if rx.search(value)]
_CORRELATION_PREFIXES = ("different_", "not_same_")
FEED_LABEL = "feed:"  # label_dec of the rules of a feed (translate.engine.Feed)


def _id_key(rid):
    return (0, int(rid)) if str(rid).isdigit() else (1, str(rid))


class _Acc:
    """Codes and notes of one item."""

    def __init__(self):
        self.codes = {}
        self.notes = []

    def add(self, code, detail=""):
        if code not in R.CATALOG:
            raise KeyError("reason code outside the catalog: %s" % code)
        self.codes.setdefault(code, [])
        if detail and detail not in self.codes[code]:
            self.codes[code].append(detail)

    def has(self, code):
        return code in self.codes


class Classifier:
    def __init__(self, inv, decisions, stock=None, equivalence=None, translate=False, list_loader=None, date=None):
        self.inv = inv
        self.translate = translate
        self.list_loader = list_loader
        self.date = date
        self.translation = None
        self.decisions = decisions
        self.stock = stock or load_stock_index()
        self.eq = equivalence or load_equivalence()
        self.winpack = load_pack()
        self.load = simulate(inv, self.stock)
        self.items = {}
        for key in ("rules", "decoders", "lists"):
            for it in inv[key]:
                self.items[m.uid(it)] = it
        self.tree = RuleTree(self.load, self.items)
        self.acc = {uid: _Acc() for uid in self.items}
        self.extra = {uid: {} for uid in self.items}
        self.wanted = {"fields": {}, "integrations": {}, "stock": {}, "feeds": {}, "lists": {}}
        self.feed_roots = {}  # root rule uid -> feed (see _feed_root)
        self._catchall_feed = None  # the one integration that takes every JSON event
        self.stock_refs = {}  # ref -> set of item refs (direct references)
        self.custom_decoders = {}  # name -> [uids] registered custom decoders
        for uid, node in self.load.dec_nodes.items():
            if node["origin"] == CUSTOM:
                self.custom_decoders.setdefault(node["name"], []).append(uid)
        # custom decoders 4.x never reaches: an earlier root takes their events
        self.dead_decoders, self.dead_decoder_names = root_shadow.find(self.load, self.items, self.stock)
        # custom decoders a stock root very probably shadows (not provable offline)
        self.likely_dead, self.likely_dead_names = root_shadow.find_likely(self.load, self.items, self.stock,
                                                                           self.dead_decoders)
        self.dec_children = {}  # custom decoder name -> custom child names, load order
        for name, uids in self.custom_decoders.items():
            parent = self.items[uids[0]].get("parent")
            if parent and parent != name and parent in self.custom_decoders:
                self.dec_children.setdefault(parent, []).append(name)
        self.field_canon = self._field_canon()

    # -- 4.x field names ---------------------------------------------------
    def _field_canon(self):
        """lower-case name -> the spelling used as the decisions.json key.

        4.x compares dynamic field names without case (``FindField``,
        strcasecmp, ``wazuh@4.14:src/analysisd/decoders/decoder.c``), so the
        spellings of one name are one field. The key is the spelling already in
        decisions.json (first in file order), else the one of a decoder
        ``<order>``, else the first in sort order."""
        names, order_words = {}, set()
        for it in self.inv["decoders"]:
            for w in it.get("order", []):
                if w and not static_destination(w)[0]:
                    names.setdefault(w.lower(), set()).add(w)
                    order_words.add(w)
        for it in self.inv["rules"]:
            for f in it.get("fields", []):
                names.setdefault(f["name"].lower(), set()).add(f["name"])
            for li in it.get("lists", []):
                if li.get("field") and not static_destination(li["field"])[0]:
                    names.setdefault(li["field"].lower(), set()).add(li["field"])
        decided = list(self.decisions.get("fields", {}))
        canon = {}
        for low, spellings in names.items():
            existing = [k for k in decided if k.lower() == low]
            words = sorted(n for n in spellings if n in order_words)
            canon[low] = existing[0] if existing else (words[0] if words else sorted(spellings)[0])
        return canon

    def fkey(self, name):
        """decisions.json key of a 4.x field name."""
        return self.field_canon.get(name.lower(), name)

    def field_action(self, name):
        return field_action(self.decisions, self.fkey(name))

    def dec_descendants(self, name):
        out, frontier = [], [name]
        while frontier:
            nxt = []
            for n in frontier:
                for c in self.dec_children.get(n, []):
                    if c not in out and c != name:
                        out.append(c)
                        nxt.append(c)
            frontier = nxt
        return out

    def decoder_field_sources(self, dname, name):
        """Where the generated decoders can check field ``name`` for a rule
        whose events come from custom decoder ``dname``: ``(leaves, None)`` or
        ``(None, why not)``.

        In 4.x only the decoder that matched last extracts fields: when a
        decoder has children, only the child's regex runs (``DecodeEvent``), and
        a rule reads the first value of the name (``FindField``). So the value
        a rule sees comes from a leaf decoder under ``dname``. A leaf that
        extracts the name once is a source; a leaf that does not extract it
        gives events without the field, which the rule does not match in 4.x
        either."""
        if dname.startswith(FEED_LABEL):
            return self._feed_field_sources(dname, name)
        key = name.lower()
        scope = [dname] + self.dec_descendants(dname)
        found, multi = [], []
        for n in scope:
            if self.dec_children.get(n) or n not in self.custom_decoders:
                continue
            count = sum(1 for u in self.custom_decoders[n] for w in self.items[u]["order"] if w.lower() == key)
            if count == 1:
                found.append(n)
            elif count > 1:
                multi.append(n)
        if multi:
            return None, "decoder %s extracts it more than once" % ", ".join(multi)
        if not found:
            return None, "no decoder under %s extracts it" % dname
        return found, None

    def _feed_field_sources(self, label, name):
        """A JSON feed decoder reads every JSON key its rules use
        (``$_wazuh4_json.<key>``), as the 4.x JSON decoder did: the feed
        decoder is the one source. A feed without JSON has no fields."""
        integ = label[len(FEED_LABEL):]
        if not any(f["json"] for f in self.feed_roots.values() if f["integration"] == integ):
            return None, "feed %s is not JSON" % integ
        key = F.json_key_of(name)
        if key is None or F.json_path(key) is None:
            return None, "feed %s cannot read the JSON key" % integ
        return [label], None

    def dec_ancestors(self, name):
        out, cur = [], name
        while True:
            uids = self.custom_decoders.get(cur)
            parent = self.items[uids[0]].get("parent") if uids else None
            if not parent or parent not in self.custom_decoders or parent in out or parent == name:
                return out
            out.append(parent)
            cur = parent

    def decoder_line_problem(self, decs):
        """Why the decoders of a rule's chains are not one line of the
        decoder tree (``if_sid`` on rules of two sibling decoders), or None.
        The decoder-side field check is written under ``decs[0]`` only."""
        if len(decs) < 2:
            return None
        line = set([decs[0]] + self.dec_ancestors(decs[0]) + self.dec_descendants(decs[0]))
        if all(d in line for d in decs[1:]):
            return None
        return "the chains of the rule come from decoders %s" % ", ".join(decs)

    def field_use(self, name, dname, problem=None):
        """How a rule uses a field without a WCS destination:
        ``("decoder", detail)`` when the decoders can check it,
        ``(code, detail)`` with RM-F-UNMAPPED or RM-F-DROPPED otherwise.
        ``problem``: why the rule's decoders cannot carry the check."""
        key = self.fkey(name)
        action, _wcs = self.field_action(name)
        why = problem
        if dname and not problem:
            leaves, why = self.decoder_field_sources(dname, name)
            if leaves:
                return "decoder", key
        code = "RM-F-DROPPED" if action == "drop" else "RM-F-UNMAPPED"
        return code, ("%s (%s)" % (key, why) if why else key)

    # ------------------------------------------------------------------
    def run(self):
        for uid, codes in self.load.codes.items():
            for code, detail in codes:
                self.acc[uid].add(code, detail)
        for uid, notes in self.load.notes.items():
            self.acc[uid].notes.extend(notes)
        for uid, item in self.items.items():
            for inv in item.get("invalid", []):
                self.acc[uid].add("RM-X-INVALID", "line %d: %s" % (inv["line"], inv["message"]))
            for unk in item.get("unknown", []):
                self.acc[uid].add("RM-X-UNKNOWN-ELEMENT", "line %d: <%s>" % (unk["line"], unk["element"]))
        self._list_classes()
        self._decoders()
        self._rules()
        self._lists()
        if self.translate:
            from .translate.engine import Translator

            self.translation = Translator(self, list_loader=self.list_loader, date=self.date).run()
        return self

    # -- helpers ---------------------------------------------------------
    def _want_field(self, name, used_by, seen_in, required=False):
        name = self.fkey(name)
        entry = self.wanted["fields"].setdefault(name, {"action": None, "wcs": None, "used_by": [], "seen_in": seen_in,
                                                        "required": False})
        if required:
            entry["required"] = True
        if used_by not in entry["used_by"]:
            entry["used_by"].append(used_by)
        if seen_in < entry["seen_in"]:
            entry["seen_in"] = seen_in

    def _want_stock(self, key, used_by, seen_in):
        default = {"integration": None, "used_by": [], "seen_in": seen_in}
        if not key.startswith("decoder:"):
            default["selection"] = None
        entry = self.wanted["stock"].setdefault(key, default)
        if used_by not in entry["used_by"]:
            entry["used_by"].append(used_by)
        if seen_in < entry["seen_in"]:
            entry["seen_in"] = seen_in

    def _ref_stock(self, ref, item_ref):
        self.stock_refs.setdefault(ref, set()).add(item_ref)

    def _equivalent(self, key):
        kind, _, name = key.partition(":")
        section = {"rule": "rules", "group": "groups", "decoder": "decoders"}[kind]
        return name in self.eq.get(section, {}) or stock_resolved(self.decisions, key) or self.winpack.knows(key)

    def _by_pack(self, key):
        """The Windows pack resolves the reference (no table entry, no decision)."""
        kind, _, name = key.partition(":")
        section = {"rule": "rules", "group": "groups", "decoder": "decoders"}[kind]
        return (self.winpack.knows(key) and name not in self.eq.get(section, {})
                and not stock_resolved(self.decisions, key))

    def _check_field(self, acc, name, item, line, codes_for_drop=True, dname=None, problem=None):
        """Field used by a rule or decoder whose events come from a generated
        decoder: static with a fixed WCS destination, or a decision. A decoder
        (``codes_for_drop`` false) extracts the value whatever the decision;
        a rule (events from custom decoder ``dname``) checks it in the decoder
        when it has no WCS destination (:meth:`field_use`)."""
        is_static, dest = static_destination(name)
        if is_static and dest is not None:
            return
        seen = "%s:%d" % (item["file"], line)
        key = self.fkey(name)
        action, _wcs = self.field_action(name)
        if action == "map":
            self._want_field(key, m.ref(item), seen)
            return
        if not codes_for_drop:
            self._want_field(key, m.ref(item), seen)
            if action is None:
                acc.add("RM-F-NOT-STORED", key)
            else:
                acc.notes.append("field %s is dropped (decisions.json)" % key)
            return
        use, detail = self.field_use(name, dname, problem)
        self._want_field(key, m.ref(item), seen, required=use != "decoder")
        acc.add("RM-F-DECODER-CHECK" if use == "decoder" else use, detail)

    def _inherit(self, acc, parent_uid, parent_label):
        pacc = self.acc.get(parent_uid)
        if pacc is None:
            return
        recipe_from = []
        for code in sorted(pacc.codes):
            reason = R.CATALOG[code]
            if not reason.propagates:
                continue
            if reason.state == R.NOT_APPLICABLE:
                continue  # handled by the load: the child is not loaded either
            acc.add(code, "from %s" % parent_label)
            if reason.state == R.RECIPE and code != "RM-R-PARENT-RECIPE":
                recipe_from.append(code)
        if recipe_from or pacc.has("RM-R-PARENT-RECIPE"):
            acc.add("RM-R-PARENT-RECIPE", "%s is RECIPE (%s)" % (parent_label, ", ".join(recipe_from or ["RM-R-PARENT-RECIPE"])))

    # -- decoders --------------------------------------------------------
    def _recreated_parent(self, name):
        """With the translator, a stock parent that ``wazuh4-base.json``
        recreates needs no decision."""
        if not self.translate:
            return False
        from .translate.engine import load_base

        return name in load_base().get("stock_parents", {})

    def _integration_of(self, dec_uid):
        """Top custom decoder of the chain (its name names the integration)."""
        node = self.load.dec_nodes[dec_uid]
        seen = set()
        while True:
            seen.add(node["uid"])
            custom_parents = [p for p in node.get("parents", []) if self.load.dec_nodes[p]["origin"] == CUSTOM]
            if not custom_parents or custom_parents[0] in seen:
                return node
            node = self.load.dec_nodes[custom_parents[0]]

    def _shadow_detail(self, uid):
        why, winner = self.dead_decoders[uid]
        if why == "root":
            return "root decoder %s (%s) is tried first and takes every event of this one" % (winner["name"], winner["at"])
        return "its parent decoder never matches: root decoder %s (%s) takes its events" % (winner["name"], winner["at"])

    def _dead_rule(self, uid, eff, dead_rules):
        """Detail of RM-D-SHADOWED-ROOT for a rule that needs a decoder 4.x
        never reaches: its own decoded_as, or every parent rule."""
        name = eff.get("decoded_as")
        if name in self.dead_decoder_names:
            winner = self.dead_decoder_names[name]
            return "decoder %s never matches in 4.x: root decoder %s (%s) takes its events" % (name, winner["name"], winner["at"])
        parents = [p for p in self.tree.parents(uid) if not self.tree.is_template(p)]
        if parents and all(p in dead_rules for p in parents):
            return dead_rules[parents[0]]
        return None

    def _likely_dead_rule(self, uid, eff, likely_rules):
        """Detail of RM-D-SHADOWED-LIKELY for a rule whose decoded_as is very probably shadowed by a stock root,
        or whose parent rules all are."""
        name = eff.get("decoded_as")
        if name in self.likely_dead_names:
            w = self.likely_dead_names[name]
            return ("decoder %s is possibly shadowed by stock 4.x decoder %s (%s), confirm with 4.x logtest (the "
                    "stock file is loaded: no decoder_exclude for it)" % (name, w["name"], w["at"]))
        parents = [p for p in self.tree.parents(uid) if not self.tree.is_template(p)]
        if parents and all(p in likely_rules for p in parents):
            return likely_rules[parents[0]]
        return None

    def _decoders(self):
        for uid, node in self.load.dec_nodes.items():
            if node["origin"] != CUSTOM:
                continue
            item = self.items[uid]
            acc = self.acc[uid]
            ref = m.ref(item)
            top = self._integration_of(uid)
            integ = top["name"]
            top_item = self.items[top["uid"]]
            self.extra[uid]["integration"] = integ
            plugin = item["plugin_decoder"]
            if plugin:
                if plugin["value"] == "JSON_Decoder":
                    pm = item["prematch"]["value"].strip() if item["prematch"] else ""
                    parent_is_stock = bool(node.get("parents")) and all(
                        self.load.dec_nodes[p]["origin"] == STOCK for p in node["parents"])
                    if (not item["parent"] or parent_is_stock) and pm in _JSON_GENERIC_PREMATCH:
                        self.extra[uid]["json_catchall"] = True
                        if not json_check(self.decisions, integ):
                            acc.add("RM-D-JSON-CATCHALL", "JSON_Decoder without a specific prematch")
                else:
                    acc.add("RM-D-PLUGIN", plugin["value"])
            for el in ("program_name", "prematch", "regex"):
                if item.get(el):
                    self._literal_syntax(acc, "<%s>" % el, item[el].get("engine"), item[el].get("value"))
            if item["fts"] or item["ftscomment"]:
                acc.add("RM-D-FTS", ", ".join(item["fts"]))
            if item["accumulate"]:
                acc.add("RM-D-ACCUMULATE")
            if uid in self.dead_decoders:
                acc.add("RM-D-SHADOWED-ROOT", self._shadow_detail(uid))
            elif uid in self.likely_dead:
                w = self.likely_dead[uid]
                acc.add("RM-D-SHADOWED-LIKELY", "possibly shadowed by stock 4.x decoder %s (%s), tried first; it may "
                                                "take the events of %s; confirm with 4.x logtest (the stock file is "
                                                "loaded: no decoder_exclude for it)" % (
                                                    w["name"], w["at"],
                                                    "its root decoder" if node.get("parents") else "this one"))
            parents = node.get("parents", [])
            stock_parents = [p for p in parents if self.load.dec_nodes[p]["origin"] == STOCK]
            if stock_parents:
                key = "decoder:%s" % item["parent"]
                self._ref_stock(key, ref)
                if self._recreated_parent(item["parent"]):
                    acc.notes.append("stock parent %s is recreated in wazuh4-base" % item["parent"])
                else:
                    self._want_stock(key, ref, m.origin(item))
                    if not stock_resolved(self.decisions, key):
                        acc.add("RM-D-STOCK-PARENT", item["parent"])
                acc.add("RM-D-DUAL-DOCUMENT", "child of stock decoder %s" % item["parent"])
            for word in item["order"]:
                self._check_field(acc, word, item, (item["regex"] or {}).get("line", item["line"]), codes_for_drop=False)
            for p in parents:
                if self.load.dec_nodes[p]["origin"] == CUSTOM:
                    self._inherit(acc, p, "parent decoder %s" % self.load.dec_nodes[p]["name"])
            # integration entry
            want = self.wanted["integrations"].setdefault(integ, {
                "category": TYPE_TO_CATEGORY.get(top_item.get("type") or "syslog", "other"),
                "category_source": "default", "used_by": [], "seen_in": m.origin(top_item)})
            if ref not in want["used_by"]:
                want["used_by"].append(ref)
            if self.extra[uid].get("json_catchall"):
                want.setdefault("json_check", None)

    # -- rules -----------------------------------------------------------
    def _literal_syntax(self, acc, what, engine, value):
        found = literal_syntax(engine, value)
        if found:
            acc.add("RM-X-LITERAL-SYNTAX", "%s %r: %s read as text" % (what, value, ", ".join(found)))

    def _rule_constructs(self, acc, it):
        for c in it["conditions"]:
            self._literal_syntax(acc, "<%s>" % c["elem"], c.get("engine"), c.get("value"))
        for f in it["fields"]:
            self._literal_syntax(acc, "<field name=\"%s\">" % f["name"], f.get("engine"), f.get("value"))
        attrs = it["attrs"]
        p = it["parents"]
        if "frequency" in attrs:
            acc.add("RM-R-FREQUENCY", "frequency=%s timeframe=%s" % (attrs["frequency"], attrs.get("timeframe", "default")))
        corr = [k for k in it["correlation"] if k.startswith(_CORRELATION_PREFIXES) or k == "global_frequency"]
        if p.get("if_matched_group") or p.get("if_matched_regex"):
            corr.append("if_matched_group" if p.get("if_matched_group") else "if_matched_regex")
        if p.get("if_matched_sid") and "frequency" not in attrs:
            corr.append("if_matched_sid")
        if corr:
            acc.add("RM-R-CORRELATION", ", ".join(sorted(set(corr))))
        flags = it["flags"]
        if "if_fts" in flags:
            acc.add("RM-R-FTS")
        if "check_diff" in flags:
            acc.add("RM-R-CHECK-DIFF")
        for f in ("time", "weekday"):
            if f in flags:
                acc.add("RM-R-TIME", "%s %s" % (f, flags[f]))
        if "compiled_rule" in flags:
            acc.add("RM-R-COMPILED", flags["compiled_rule"])
        if p.get("if_level") and not p.get("if_sid"):
            acc.add("RM-R-IF-LEVEL", "if_level %s" % p["if_level"])
        ign = []
        if "ignore" in attrs:
            ign.append("ignore=%s" % attrs["ignore"])
        if "ignore" in flags:
            ign.append("<ignore>%s" % flags["ignore"])
        if "check_if_ignored" in flags:
            ign.append("<check_if_ignored>%s" % flags["check_if_ignored"])
        if ign:
            acc.add("RM-R-IGNORE", ", ".join(ign))
        opts = list(it["options"])
        if "maxsize" in attrs:
            opts.append("maxsize=%s" % attrs["maxsize"])
        if opts:
            acc.add("RM-R-OPTIONS", ", ".join(opts))
        if "no_full_log" in it["options"]:
            acc.notes.append(NO_FULL_LOG_NOTE)
        for li in it["lists"]:
            if li["lookup"] == "address_match_key_value":
                acc.add("RM-L-KEY-VALUE-INVERTED", li["path"])

    def _rules(self):
        tree = self.tree
        stock_dec_names = self.stock.decoder_names
        dead_rules = {}  # uid -> detail of RM-D-SHADOWED-ROOT; parents come first in node_order
        likely_rules = {}  # uid -> detail of RM-D-SHADOWED-LIKELY
        for uid in self.load.node_order:
            node = tree.node(uid)
            if node.get("item") is None or node["origin"] != CUSTOM:
                continue
            item = self.items[uid]
            eff = tree.item_of(uid)
            acc = self.acc[uid]
            ref = m.ref(item)
            seen = m.origin(item)
            if node.get("overwritten_by"):
                acc.notes.append("content overwritten by %s" % node["overwritten_by"])
            # direct stock references
            for p in tree.parents(uid):
                if tree.is_stock(p) and not tree.is_template(p):
                    if node.get("link") == "if_group":
                        g = item["parents"].get("if_group") or item["parents"].get("if_matched_group")
                        self._ref_stock("group:%s" % g, ref)
                    else:
                        self._ref_stock("rule:%s" % tree.node(p)["id"], ref)
            own_dec = eff.get("decoded_as")
            if not [p for p in tree.parents(uid) if not tree.is_template(p)]:
                self._feed_root(uid, item, eff, acc)
            feed = self._feed_source(uid)
            if own_dec and feed:
                pass  # decoded_as json of a feed: no stock reference
            elif own_dec:
                if own_dec in self.custom_decoders:
                    pass
                elif own_dec in stock_dec_names:
                    self._ref_stock("decoder:%s" % own_dec, ref)
                else:
                    acc.add("RM-X-INVALID", "decoded_as %s: no decoder with that name is loaded" % own_dec)
            self._rule_constructs(acc, eff)
            dead = self._dead_rule(uid, eff, dead_rules)
            if dead:
                dead_rules[uid] = dead
                acc.add("RM-D-SHADOWED-ROOT", dead)
            else:
                likely = self._likely_dead_rule(uid, eff, likely_rules)
                if likely:
                    likely_rules[uid] = likely
                    acc.add("RM-D-SHADOWED-LIKELY", likely)
            grouping = tree.is_grouping_only(uid)
            # source
            decs = tree.chain_decoded_as(uid)
            custom_decs = [d for d in decs if d in self.custom_decoders]
            stock_decs = [d for d in decs if d not in self.custom_decoders and d in stock_dec_names]
            refs = tree.stock_anchors(uid) + ["decoder:%s" % d for d in stock_decs]
            source = "custom" if custom_decs else ("stock" if refs else None)
            if feed:
                source, refs = "feed", []
                self.extra[uid]["source"] = {"kind": source, "decoders": stock_decs, "stock_refs": [],
                                             "feeds": sorted({f["root_id"] for f in feed}, key=_id_key)}
                self.extra[uid]["integration"] = sorted({f["integration"] for f in feed})
                self._feed_codes(acc, feed)
            else:
                self.extra[uid]["source"] = {"kind": source, "decoders": custom_decs + stock_decs, "stock_refs": refs}
            if custom_decs:
                integ = [self.extra[u].get("integration") for d in custom_decs for u in self.custom_decoders[d]]
                self.extra[uid]["integration"] = sorted({i for i in integ if i})
            missing = []
            for key in refs:
                if self._by_pack(key):
                    continue  # no question: the Windows pack answers it
                self._want_stock(key, ref, seen)
                if not self._equivalent(key):
                    missing.append(key)
            if missing:
                acc.add("RM-S-NO-EQUIVALENT", ", ".join(missing))
            if source is None and not grouping:
                acc.add("RM-R-NO-SOURCE")
            # fields (only when the events come from generated decoders)
            if source in ("custom", "feed"):
                dname, problem = None, None
                if source == "feed" and len({f["integration"] for f in feed}) == 1:
                    dname = FEED_LABEL + feed[0]["integration"]
                if source == "custom":
                    dname = custom_decs[0]
                    problem = self.decoder_line_problem(custom_decs)
                for f in eff["fields"]:
                    self._check_field(acc, f["name"], item, f["line"], dname=dname, problem=problem)
                for c in eff["conditions"]:
                    if c["elem"] in STATIC_TO_WCS and c["elem"] not in ("program_name", "hostname", "location"):
                        self._check_field(acc, c["elem"], item, c["line"], dname=dname, problem=problem)
                for li in eff["lists"]:
                    if li["field"] and li["path"] not in self.ioc_feed_lists:
                        self._check_field(acc, li["field"], item, li["line"], dname=dname, problem=problem)
                if feed and any(f["json"] for f in feed):
                    names = [f["name"] for f in eff["fields"]] + [li["field"] for li in eff["lists"] if li["field"]]
                    for name in names:
                        key = F.json_key_of(name)
                        if key is not None and F.json_path(key) is None:
                            acc.add("RM-F-JSON-PATH", name)
            elif any(li["path"] not in self.ioc_feed_lists for li in eff["lists"]):
                acc.add("RM-R-LABEL-UNAVAILABLE", "<list> on events of stock content")
            # tree semantics
            if grouping:
                acc.add("RM-R-GROUPING-ONLY", "%d child rule(s)" % len(tree.children.get(uid, [])))
            elif tree.is_silencer(uid):
                targets = tree.silencer_targets(uid)
                stock_t = [t for t in targets if tree.is_stock(t)]
                custom_t = [t for t in targets if not tree.is_stock(t)]
                self.extra[uid]["exclusion_targets"] = custom_t
                self.extra[uid]["exclusion_stock_targets"] = ["rule:%s" % tree.node(t)["id"] for t in stock_t]
                for t in custom_t:
                    self.extra.setdefault(t, {}).setdefault("excluded_by", []).append(uid)
                if stock_t:
                    ids = sorted({tree.node(t)["id"] for t in stock_t}, key=lambda x: int(x))
                    shown = ", ".join(ids[:10]) + (" and %d more" % (len(ids) - 10) if len(ids) > 10 else "")
                    acc.add("RM-R-SILENCER-STOCK", "silences stock rule(s) %s" % shown)
                else:
                    acc.add("RM-R-SILENCER", "exclusion on %d rule(s)" % len(custom_t))
            elif tree.alerting(uid) and tree.shadowed(uid):
                acc.add("RM-R-SHADOWING")
            for p in tree.custom_chain_parents(uid):
                self._inherit(acc, p, "parent rule %s" % tree.node(p)["id"])
            self.extra[uid]["chains"] = tree.effective_rule(uid)["chains"]

    # -- feeds -----------------------------------------------------------
    def _feed_root(self, uid, item, eff, acc):
        """Register a root rule as a feed root (see :mod:`rmig.feeds`)."""
        json_allowed = not self._equivalent("decoder:json")  # a decided stock entry keeps the old route
        kind = F.root_kind(eff, json_allowed)
        if kind is None:
            return
        rid = item["id"]
        entry = feed_entry(self.decisions, rid)
        default = F.default_integration(kind, eff)
        if default in F.RESERVED or default in self.custom_decoders or default in self._recreated_names():
            default = "feed-%s" % default
        integ = entry.get("integration") or default
        if integ != default and (integ in F.RESERVED or integ in self.custom_decoders or integ in self._recreated_names()):
            acc.notes.append("feed integration %s is a name the migration already uses: %s is used" % (integ, "feed-" + integ))
            integ = "feed-%s" % integ
        is_json = kind != F.LOCATION or F.reads_decoded_fields(eff) or any(
            F.reads_decoded_fields(self.tree.item_of(d)) for d in self.tree.descendants(uid))
        default_sel, err = (None, None)
        if kind == F.LOCATION:
            default_sel, err = F.location_selector(eff)
        selector = entry.get("selector") or default_sel
        needed = False
        why = None
        if not selector:
            if kind == F.LOCATION and err:
                needed, why = True, err
            elif not is_json:
                needed, why = True, "the feed is not JSON and its root has no <location>"
            elif self._catchall_feed is None or self._catchall_feed == integ:
                self._catchall_feed = integ
            else:
                needed, why = True, "integration %s already takes every JSON event" % self._catchall_feed
        feed = {"root_id": rid, "root_uid": uid, "kind": kind, "integration": integ, "json": is_json,
                "selector": selector, "catchall": not selector and not needed,
                "probe": F.root_probe(eff) if is_json else None}
        self.feed_roots[uid] = feed
        if default_sel is None and feed["catchall"]:
            # informational: the check the root adds to the feed that takes the JSON events (Feed.check)
            default_sel = feed["probe"]
        self.wanted["feeds"][rid] = {
            "integration": default, "category": "other", "category_source": "default", "selector": None,
            "kind": kind, "default_selector": default_sel, "selector_needed": needed and not entry.get("selector"),
            "used_by": [m.ref(item)], "seen_in": m.origin(item)}
        if needed:
            acc.add("RM-R-FEED-NO-SELECTOR", "feed %s (root rule %s): %s" % (integ, rid, why))

    def _recreated_names(self):
        if not self.translate:
            return ()
        from .translate.engine import load_base

        return load_base().get("stock_parents", {})

    def _feed_source(self, uid):
        """Feeds of a rule whose every chain starts at a feed root and reaches
        no stock rule and no custom decoder; None otherwise."""
        if self.tree.stock_anchors(uid):
            return None
        decs = self.tree.chain_decoded_as(uid)
        if any(d != "json" for d in decs):
            return None
        roots = {p[0] for p in self.tree.paths(uid)}
        if not roots or not all(r in self.feed_roots for r in roots):
            return None
        feeds = [self.feed_roots[r] for r in sorted(roots, key=lambda r: self.tree.node(r)["seq"])]
        for f in feeds:
            ref = m.ref(self.items[uid])
            want = self.wanted["feeds"][f["root_id"]]
            if ref not in want["used_by"]:
                want["used_by"].append(ref)
        return feeds

    def _feed_codes(self, acc, feeds):
        for f in feeds:
            acc.add("RM-R-FEED", "feed %s, root rule %s" % (f["integration"], f["root_id"]))
            if f["selector"] and "wazuh.protocol.location" in f["selector"]:
                acc.add("RM-R-FEED-LOCATION", "root rule %s" % f["root_id"])
            if f["json"]:
                acc.add("RM-D-FEED-JSON", "root rule %s%s" % (
                    f["root_id"], "" if f["kind"] == F.JSON else " (no decoded_as: fields assumed from the 4.x JSON decoder)"))

    # -- lists -----------------------------------------------------------
    def _list_classes(self):
        """Class of every list (stock, IoC, business) and the IoC lists moved to the 5.x feeds by
        decisions.json (``lists``, ``"action": "ioc-feed"``)."""
        from .quality import lists as LC

        self.list_classes = LC.classify_lists(self)
        self.ioc_feed_lists = set()
        for name, res in self.list_classes.items():
            if res["class"] == "ioc" and res["uses"]:
                self.wanted["lists"][name] = LC.wanted_entry(name, res)
            if list_action(self.decisions, name) == "ioc-feed":
                self.ioc_feed_lists.add(name)

    def _lists(self):
        for li in self.inv["lists"]:
            uid = m.uid(li)
            acc = self.acc[uid]
            if acc.codes:
                continue
            if li["prefix_key_count"]:
                acc.add("RM-L-PREFIX-KEYS", "%d prefix key(s)" % li["prefix_key_count"])

    # -- output ----------------------------------------------------------
    def items_out(self):
        out = []
        for uid in sorted(self.items, key=lambda u: (self.items[u]["file"], self.items[u]["line"], u)):
            item = self.items[uid]
            acc = self.acc[uid]
            if not acc.codes:
                acc.add("RM-X-PROVISIONAL-AUTO")
            codes = sorted(acc.codes)
            state = R.state_of(codes)
            entry = {
                "uid": uid,
                "kind": item["kind"],
                "ref": m.ref(item),
                "file": item["file"],
                "line": item["line"],
                "state": state,
                "fidelity": R.fidelity_of(codes) if state == R.AUTO else None,
                "codes": [{"code": c, "details": acc.codes[c]} for c in codes],
                "notes": acc.notes,
            }
            if item["kind"] == m.RULE:
                entry["level"] = item["level"]
                entry["description"] = item["description"]
            extra = self.extra.get(uid, {})
            for k in ("source", "integration", "chains", "exclusion_targets", "exclusion_stock_targets", "excluded_by", "json_catchall"):
                if k in extra:
                    entry[k] = extra[k]
            out.append(entry)
        return out

    def wanted_decisions(self):
        res = {}
        for section, entries in self.wanted.items():
            res[section] = {}
            for key, entry in entries.items():
                e = dict(entry)
                e["used_by"] = sorted(e["used_by"])
                res[section][key] = e
        return res

    def stock_references(self):
        out = []
        for ref, users in self.stock_refs.items():
            kind, _, name = ref.partition(":")
            loc = None
            if kind == "rule" and name in self.stock.rules_by_id:
                e = self.stock.rules_by_id[name][0]
                loc = "ruleset/rules/%s:%d" % (e["file"], e["line"])
            elif kind == "decoder" and name in self.stock.decoder_names:
                e = self.stock.decoder_names[name][0]
                loc = "ruleset/decoders/%s:%d" % (e["file"], e["line"])
            out.append({"ref": ref, "count": len(users), "stock_location": loc,
                        "equivalence": self._equivalent(ref)})
        out.sort(key=lambda r: (-r["count"], r["ref"]))
        return out


def classify(inv, decisions, stock=None, equivalence=None, translate=False, list_loader=None, date=None):
    """Classify the inventory. With ``translate`` the translator runs
    too and the states come out of the translation (``RM-X-TRANSLATED``
    instead of ``RM-X-PROVISIONAL-AUTO``); ``.translation.package`` holds the
    5.x content."""
    return Classifier(inv, decisions, stock, equivalence, translate, list_loader, date).run()
