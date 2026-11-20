"""Boolean conditions over Sigma selections and their rendering to a
``detection`` block (``condition`` + named selections).

A node is one of ``("sel", {key: value})``, ``("and", [nodes])``,
``("or", [nodes])``, ``("not", node)``. Selections AND-ed together are merged
into one when their keys do not collide; equal selections share a name.
Positive selections are named ``selection``, ``selection_2``…; selections that
only appear negated are named ``filter``, ``filter_2``….
"""

import json


def sel(mapping):
    return ("sel", dict(mapping))


def AND(*nodes):
    flat = []
    for n in nodes:
        if n is None:
            continue
        if n[0] == "and":
            flat.extend(n[1])
        else:
            flat.append(n)
    if not flat:
        return None
    if len(flat) == 1:
        return flat[0]
    return ("and", flat)


def OR(*nodes):
    flat = []
    for n in nodes:
        if n is None:
            continue
        if n[0] == "or":
            flat.extend(n[1])
        else:
            flat.append(n)
    uniq = []
    seen = set()
    for n in flat:
        k = _key(n)
        if k not in seen:
            seen.add(k)
            uniq.append(n)
    if not uniq:
        return None
    if len(uniq) == 1:
        return uniq[0]
    return ("or", uniq)


def NOT(node):
    if node is None:
        return None
    if node[0] == "not":
        return node[1]
    return ("not", node)


def _key(node):
    return json.dumps(node, sort_keys=True)


def _merge_and(children):
    """Merge the selection children of an AND when keys do not collide."""
    merged = []
    out = []
    for c in children:
        if c[0] == "sel":
            for m in merged:
                if not (set(m) & set(c[1])):
                    m.update(c[1])
                    break
                if all(m.get(k) == v for k, v in c[1].items()):
                    break  # already implied
            else:
                merged.append(dict(c[1]))
        else:
            out.append(c)
    # keep first-seen order: selections first, then compound nodes
    res = [("sel", m) for m in merged]
    seen = set()
    for c in out:
        k = _key(c)
        if k not in seen:
            seen.add(k)
            res.append(c)
    return res


def simplify(node):
    if node is None:
        return None
    kind = node[0]
    if kind == "sel":
        return node
    if kind == "not":
        inner = simplify(node[1])
        return NOT(inner)
    kids = [simplify(c) for c in node[1]]
    if kind == "and":
        n = AND(*kids)
        if n is None or n[0] != "and":
            return n
        kids = _merge_and(n[1])
        return kids[0] if len(kids) == 1 else ("and", kids)
    return OR(*kids)


class _Namer:
    def __init__(self):
        self.names = {}
        self.blocks = {}
        self.pos = 0
        self.neg = 0

    def name(self, mapping, negated):
        k = json.dumps(mapping, sort_keys=True)
        if k in self.names:
            return self.names[k]
        if negated:
            self.neg += 1
            nm = "filter" if self.neg == 1 else "filter_%d" % self.neg
        else:
            self.pos += 1
            nm = "selection" if self.pos == 1 else "selection_%d" % self.pos
        self.names[k] = nm
        self.blocks[nm] = mapping
        return nm


def _negated_only(node, under_not=False, acc=None):
    """Keys of selections that appear only under a NOT."""
    if acc is None:
        acc = {}
    kind = node[0]
    if kind == "sel":
        k = json.dumps(node[1], sort_keys=True)
        prev = acc.get(k, True)
        acc[k] = prev and under_not
    elif kind == "not":
        _negated_only(node[1], True, acc)
    else:
        for c in node[1]:
            _negated_only(c, under_not, acc)
    return acc


def render(node):
    """``{"condition": "...", <name>: {...}, ...}`` for a node."""
    node = simplify(node)
    if node is None:
        raise ValueError("empty condition")
    neg = _negated_only(node)
    namer = _Namer()

    def text(n, parent):
        kind = n[0]
        if kind == "sel":
            return namer.name(n[1], neg[json.dumps(n[1], sort_keys=True)])
        if kind == "not":
            return "not " + text(n[1], "not")
        sep = " and " if kind == "and" else " or "
        body = sep.join(text(c, kind) for c in n[1])
        if parent in ("and", "or", "not") and parent != kind:
            return "(%s)" % body
        return body

    cond = text(node, None)
    det = {"condition": cond}
    det.update(namer.blocks)
    return det


def selection_keys(node):
    """Every field key used in the node (``field|modifier``)."""
    out = []
    if node is None:
        return out
    if node[0] == "sel":
        out.extend(node[1].keys())
    elif node[0] == "not":
        out.extend(selection_keys(node[1]))
    else:
        for c in node[1]:
            out.extend(selection_keys(c))
    return out
