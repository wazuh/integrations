"""Rule tree, flattening data and shadowing.

Built from :class:`rmig.load_order.LoadResult`: every loaded rule, stock and
custom, with its parents. Children of a node are kept in 4.x evaluation order:
level descending with level 0 first (stored as 99 while loading:
``wazuh@4.14.13:src/analysisd/rules.c:399-413``), ties in load order
(``rules_list.c:270``).

What this module answers:

* ``paths(uid)``: every chain from the top (below the category template) to
  the rule; several ``if_sid`` ids or an ``if_group`` give several chains (OR);
* ``stock_anchors(uid)``: the nearest stock rule of each chain, and whether the
  link was by ``if_group`` (then the anchor is the group);
* ``is_grouping_only`` / ``is_silencer``;
* ``silencer_targets(uid)``: the rules that need the silencer's exclusion
  (the exact exclusion set): every emitted ancestor and, at each level of the path, the
  siblings evaluated after the path node and their descendants;
* ``effective_rule(uid)``: what the translator consumes.
"""

from .load_order import STOCK

MAX_PATHS = 64


def _eval_level(node):
    lvl = node["level"] or 0
    return 99 if lvl == 0 else lvl


def has_detection(item):
    """Own detection conditions (anything beyond decoded_as/category/if_*)."""
    if item is None:
        return True
    return bool(item["conditions"] or item["fields"] or item["lists"] or item["flags"]
                or item["correlation"] or "frequency" in item["attrs"]
                or "maxsize" in item["attrs"])


class RuleTree:
    def __init__(self, load, items_by_uid):
        self.load = load
        self.nodes = load.nodes
        self.items = items_by_uid
        self.children = {uid: [] for uid in self.nodes}
        for uid in load.node_order:
            for p in self.nodes[uid].get("parents", []):
                self.children.setdefault(p, []).append(uid)
        for p, kids in self.children.items():
            kids.sort(key=lambda u: (-_eval_level(self.nodes[u]), self.nodes[u]["seq"]))
        self._paths = {}
        self._descendants = {}
        self._anchors = {}

    # -- basic predicates --------------------------------------------------
    def node(self, uid):
        return self.nodes[uid]

    def is_stock(self, uid):
        return self.nodes[uid]["origin"] == STOCK

    def is_template(self, uid):
        return bool(self.nodes[uid].get("template"))

    def item_of(self, uid):
        n = self.nodes[uid]
        if n.get("overwritten_by"):
            return self.items.get(n["overwritten_by"])
        return self.items.get(n.get("item")) if n.get("item") else None

    def alerting(self, uid):
        """The rule raises an alert of its own in 4.x when it is the winner."""
        n = self.nodes[uid]
        if self.is_template(uid) or n["noalert"]:
            return False
        if (n["level"] or 0) == 0:
            return False
        if not self.is_stock(uid) and self.is_grouping_only(uid):
            return False
        return True

    def is_grouping_only(self, uid):
        n = self.nodes[uid]
        if self.is_stock(uid):
            return False
        if not ((n["level"] or 0) == 0 or n["noalert"]):
            return False
        return bool(self.children.get(uid)) and not has_detection(self.item_of(uid))

    def is_silencer(self, uid):
        n = self.nodes[uid]
        if self.is_stock(uid) or n["noalert"] or (n["level"] or 0) != 0:
            return False
        return not self.is_grouping_only(uid)

    # -- structure ---------------------------------------------------------
    def parents(self, uid):
        return [p for p in self.nodes[uid].get("parents", []) if p in self.nodes]

    def paths(self, uid):
        """Chains [top, ..., uid] without category templates; capped."""
        if uid in self._paths:
            return self._paths[uid]
        parents = [p for p in self.parents(uid) if not self.is_template(p)]
        if not parents:
            res = [[uid]]
        else:
            res = []
            for p in parents:
                for path in self.paths(p):
                    res.append(path + [uid])
                    if len(res) >= MAX_PATHS:
                        break
                if len(res) >= MAX_PATHS:
                    break
        self._paths[uid] = res
        return res

    def ancestors(self, uid):
        seen = set()
        stack = list(self.parents(uid))
        while stack:
            p = stack.pop()
            if p in seen or self.is_template(p):
                continue
            seen.add(p)
            stack.extend(self.parents(p))
        return seen

    def descendants(self, uid):
        """Every rule below ``uid``. The tree does not change once built, so the
        result is cached: silencers under wide stock parents ask for the same
        subtrees many times."""
        if uid in self._descendants:
            return self._descendants[uid]
        seen = set()
        stack = list(self.children.get(uid, ()))
        while stack:
            c = stack.pop()
            if c in seen:
                continue
            seen.add(c)
            stack.extend(self.children.get(c, ()))
        self._descendants[uid] = frozenset(seen)
        return self._descendants[uid]

    def custom_chain_parents(self, uid):
        """Custom parents (not templates, not stock)."""
        return [p for p in self.parents(uid) if not self.is_stock(p) and not self.is_template(p)]

    def stock_anchors(self, uid):
        """Stock references that the rule's chains reach through custom rules.

        Returns a sorted list of refs: ``rule:<id>`` for an ``if_sid`` link to a
        stock rule, ``group:<if_group>`` when a custom rule of the chain links by
        ``if_group`` to stock rules."""
        return sorted(self._anchor_set(uid))

    def _anchor_set(self, uid):
        """``stock_anchors`` as a cached set: the anchors of a rule are its own
        stock links plus those of its custom parents. Parents always load
        before their children, so the graph has no cycles."""
        # Iterative post-order: chains through if_group can be deeper than the recursion limit.
        stack = [(uid, False)]
        while stack:
            u, expanded = stack.pop()
            if u in self._anchors:
                continue
            ps = [p for p in self.parents(u) if not self.is_template(p)]
            custom_ps = [p for p in ps if not self.is_stock(p)]
            if not expanded:
                stack.append((u, True))
                stack.extend((p, False) for p in custom_ps if p not in self._anchors)
                continue
            refs = set()
            if len(custom_ps) < len(ps):
                if self.nodes[u].get("link") == "if_group":
                    item = self.item_of(u)
                    g = (item["parents"].get("if_group") or item["parents"].get("if_matched_group")) if item else None
                    refs.add("group:%s" % g)
                else:
                    for p in ps:
                        if self.is_stock(p):
                            refs.add("rule:%s" % self.nodes[p]["id"])
            for p in custom_ps:
                refs |= self._anchors.get(p, frozenset())
            self._anchors[u] = frozenset(refs)
        return self._anchors[uid]

    def chain_decoded_as(self, uid):
        """decoded_as values along the custom part of the chains (own first)."""
        out = []
        seen = set()
        stack = [uid]
        while stack:
            u = stack.pop()
            if u in seen or self.is_stock(u):
                continue
            seen.add(u)
            item = self.item_of(u)
            if item and item.get("decoded_as") and item["decoded_as"] not in out:
                out.append(item["decoded_as"])
            stack.extend(p for p in self.parents(u) if not self.is_template(p))
        return out

    # -- shadowing ----------------------------------------------------
    def later_siblings(self, parent, child):
        kids = self.children.get(parent, [])
        if child not in kids:
            return []
        later = kids[kids.index(child) + 1:]
        if self.is_template(parent):
            later = self._same_decoder_roots(child, later)
        return later

    def earlier_siblings(self, parent, child):
        kids = self.children.get(parent, [])
        if child not in kids:
            return []
        earlier = kids[:kids.index(child)]
        if self.is_template(parent):
            earlier = self._same_decoder_roots(child, earlier)
        return earlier

    def _same_decoder_roots(self, child, siblings):
        """Root rules hang from the category template; without condition
        analysis, only roots bound to the same decoder are taken as competing
        for the same events."""
        dec = self.nodes[child].get("decoded_as")
        if not dec:
            return []
        return [k for k in siblings if self.nodes[k].get("decoded_as") == dec]

    def silencer_targets(self, uid):
        """Rules that need the exclusion of silencer ``uid``: sorted uids."""
        targets = set()
        for path in self.paths(uid):
            # emitted ancestors on this path
            for a in path[:-1]:
                if self.alerting(a):
                    targets.add(a)
            # later siblings of every node of the path, and their descendants
            full = path
            top_parents = [p for p in self.parents(path[0]) if self.is_template(p)]
            pairs = [(full[i - 1], full[i]) for i in range(1, len(full))]
            pairs += [(t, full[0]) for t in top_parents]
            for parent, node in pairs:
                for sib in self.later_siblings(parent, node):
                    targets.add(sib)
                    targets.update(self.descendants(sib))
        targets.discard(uid)
        return sorted(t for t in targets if self.alerting(t))

    def shadowed(self, uid):
        """In 4.x another rule could win over this one for the same event: an
        alerting ancestor, or an alerting sibling evaluated before it."""
        for a in self.ancestors(uid):
            if self.alerting(a):
                return True
        for p in self.parents(uid):
            for s in self.earlier_siblings(p, uid):
                if self.alerting(s):
                    return True
        return False

    # -- translator input --------------------------------------------------
    def effective_rule(self, uid):
        """Data for ``translate_rule``: the rule after ``overwrite`` and the custom
        part of each chain (OR of chains, AND inside a chain), with the stock
        anchors whose condition comes from the equivalence table."""
        chains = []
        for path in self.paths(uid):
            custom = []
            anchor = None
            for u in path:
                if self.is_stock(u):
                    anchor = self.nodes[u]["id"]
                    custom = []
                    continue
                custom.append(u)
            chains.append({"stock_anchor": anchor, "rules": custom})
        return {
            "uid": uid,
            "rule": self.item_of(uid),
            "chains": chains,
            "stock_refs": self.stock_anchors(uid),
        }
