"""Simulated 4.x load and "what is custom".

Reproduces what analysisd does when it loads the ruleset
(``wazuh@4.14.13:src/config/rules-config.c``, ``src/analysisd/rules.c``,
``rules_list.c``, ``decoders/decoders_list.c``):

* the file list: ``rule_include`` first, then every ``rule_dir`` in order;
  ``rule_exclude`` matches the full path *or* the base name; a full path
  already added is skipped; the list is sorted by base name (stable);
* rules are registered in that order: a repeated id without ``overwrite`` is
  ignored; ``if_sid``/``if_group``/``if_level`` link only to rules already
  loaded; a rule without parent, or whose list is not loaded, is discarded;
* decoders: same file logic with ``decoder_*``; a child needs its parent
  loaded before it.

On top of that it tells custom from stock by comparing each element with the
stock index (sha256 of the normalized element).

The result feeds ``tree`` (the rule tree, stock and custom) and ``classify``
(the codes found here).
"""

from . import model4 as m
from .stock import StockIndex, element_sha256

STOCK = "stock"
CUSTOM = "custom"
TEMPLATE_FILE = "0010-rules_config.xml"
STOCK_RULE_DIR = "ruleset/rules"
STOCK_DECODER_DIR = "ruleset/decoders"


def os_word_match(pattern, text):
    """``OS_WordMatch``: case-insensitive OS_Match with ``|``, ``^`` and ``$``
    (``wazuh@4.14.13:src/os_regex/os_regex_match.c:32``)."""
    if not pattern or text is None:
        return False
    t = text.lower()
    for alt in pattern.lower().split("|"):
        if alt == "":
            return True
        if alt.startswith("^") and alt.endswith("$") and len(alt) > 1:
            if t == alt[1:-1]:
                return True
        elif alt.startswith("^"):
            if t.startswith(alt[1:]):
                return True
        elif alt.endswith("$"):
            if t.endswith(alt[:-1]):
                return True
        elif alt in t:
            return True
    return False


def _pattern_matches(pattern, fname):
    """``rule_dir pattern`` (OS_Regex, case-insensitive). Literal patterns with
    optional ``^``/``$`` are exact; others fall back to a suffix test on .xml."""
    p = pattern or ".xml$"
    lit = p
    start = lit.startswith("^")
    end = lit.endswith("$")
    lit = lit.lstrip("^").rstrip("$")
    if "\\" in lit:
        return fname.lower().endswith(".xml")
    f = fname.lower()
    lit = lit.lower()
    if start and end:
        return f == lit
    if start:
        return f.startswith(lit)
    if end:
        return f.endswith(lit)
    return lit in f


class LoadResult:
    def __init__(self):
        self.rule_files = []      # [{conf_path, basename, origin, display, loaded, reason}]
        self.decoder_files = []
        self.nodes = {}           # uid -> rule node (stock and custom)
        self.node_order = []      # uids in load order
        self.by_id = {}           # id -> uid of the loaded rule
        self.codes = {}           # item uid -> [[code, detail]]
        self.item_node = {}       # custom item uid -> node uid (if registered)
        self.dec_nodes = {}       # uid -> decoder node
        self.dec_by_name = {}     # name -> [uids] loaded
        self.declared_lists = []
        self.available_lists = set()
        self.stock_overwrites = {}  # stock node uid -> [item uids]
        self.notes = {}           # item uid -> [text]

    def add_code(self, item_uid, code, detail=""):
        self.codes.setdefault(item_uid, []).append([code, detail])

    def add_note(self, item_uid, text):
        self.notes.setdefault(item_uid, []).append(text)


def _file_list(directives, kind, stock_files, inv_files):
    """Simulate Read_Rules for ``kind`` (``rule`` or ``decoder``).

    Returns (loaded, excluded): lists of conf paths. ``inv_files`` maps a conf
    path to its inventory file entry."""
    inc_el, dir_el, exc_el = kind + "_include", kind + "_dir", kind + "_exclude"
    default_dir = STOCK_RULE_DIR if kind == "rule" else STOCK_DECODER_DIR
    includes = []
    excludes = [d[1] for d in directives if d[0] == exc_el]
    dirs = []
    for el, value, attrs in directives:
        if el == inc_el:
            includes.append(value if "/" in value else default_dir + "/" + value)
        elif el == dir_el:
            dirs.append((value.rstrip("/"), attrs.get("pattern")))
    if not dirs:
        dirs.append((default_dir, None))
    excluded = []
    # entries per directory: stock files from the index + files of the inventory
    entries = {}
    for conf_path in inv_files:
        d, _, base = conf_path.rpartition("/")
        entries.setdefault(d, set()).add(base)
    for base in stock_files:
        entries.setdefault(default_dir, set()).add(base)
    for d, pattern in dirs:
        for name in sorted(entries.get(d, ())):
            fname = d + "/" + name
            if fname in excludes or name in excludes:
                excluded.append(fname)
                continue
            if fname in includes:
                continue
            if _pattern_matches(pattern, fname):
                includes.append(fname)
    # rule_include of a file that does not exist: analysisd fails; we skip it
    existing = set(inv_files) | {default_dir + "/" + b for b in stock_files}
    loaded = [f for f in includes if f in existing]
    loaded.sort(key=lambda f: f.rsplit("/", 1)[-1])  # stable sort by base name
    return loaded, excluded


def simulate(inv, stock: StockIndex):
    res = LoadResult()
    directives = inv["ruleset"]["directives"]
    files = {f["conf_path"]: f for f in inv["files"]}
    rule_files = {p: f for p, f in files.items() if f["role"] == "rules"}
    dec_files = {p: f for p, f in files.items() if f["role"] == "decoders"}
    mode = inv["source"]["mode"]

    # ---- lists ---------------------------------------------------------
    declared = [d[1] for d in directives if d[0] == "list"]
    res.declared_lists = declared
    stock_list_names = {"etc/lists/" + li["name"] for li in stock.lists}
    physical = {li["name"] for li in inv["lists"]}
    for name in declared:
        if name in physical or (mode != "etc" and name in stock_list_names):
            res.available_lists.add(name)
    for li in inv["lists"]:
        uid = m.uid(li)
        if li["sha256"] in stock.list_sha:
            res.add_code(uid, "RM-L-STOCK", "same content as stock list %s" % stock.list_sha[li["sha256"]][0]["name"])
        elif li["name"] not in declared:
            res.add_code(uid, "RM-L-MISSING", "not declared in <ruleset><list>: 4.x does not load it")

    # ---- decoders ------------------------------------------------------
    loaded_dec, excluded_dec = _file_list(directives, "decoder", stock.decoder_files, dec_files)
    excluded_set = set(excluded_dec)
    for p in sorted(dec_files):
        if p in excluded_set or p not in loaded_dec:
            for d in inv["decoders"]:
                if d["file"] == dec_files[p]["path"]:
                    res.add_code(m.uid(d), "RM-D-FILE-SHADOWED", "file %s is not loaded by 4.x (decoder_exclude or pattern)" % p)
    inv_decs_by_file = {}
    for d in inv["decoders"]:
        inv_decs_by_file.setdefault(d["file"], []).append(d)
    for conf_path in loaded_dec:
        base = conf_path.rsplit("/", 1)[-1]
        fentry = dec_files.get(conf_path)
        is_stock_file = conf_path.startswith(STOCK_DECODER_DIR + "/") and base in stock.decoders_by_file
        res.decoder_files.append({"conf_path": conf_path, "origin": STOCK if is_stock_file else CUSTOM})
        elements = []
        if is_stock_file:
            elements.extend(("stock", e) for e in stock.decoders_by_file[base])
        if fentry is not None:
            elements.extend(("custom", d) for d in inv_decs_by_file.get(fentry["path"], []))
        for origin, el in elements:
            _register_decoder(res, origin, el, stock)

    # ---- rules ---------------------------------------------------------
    loaded_rules, excluded_rules = _file_list(directives, "rule", stock.rule_files, rule_files)
    excluded_set = set(excluded_rules)
    res.excluded_rule_files = excluded_rules
    res.loaded_rule_files = loaded_rules
    for p in sorted(rule_files):
        if p in excluded_set or p not in loaded_rules:
            for r in inv["rules"]:
                if r["file"] == rule_files[p]["path"]:
                    res.add_code(m.uid(r), "RM-R-FILE-SHADOWED", "file %s is not loaded by 4.x (rule_exclude or pattern)" % p)
    excluded_stock_bases = {p.rsplit("/", 1)[-1] for p in excluded_rules if p.startswith(STOCK_RULE_DIR + "/")}
    inv_rules_by_file = {}
    for r in inv["rules"]:
        inv_rules_by_file.setdefault(r["file"], []).append(r)
    seq = 0
    for conf_path in loaded_rules:
        base = conf_path.rsplit("/", 1)[-1]
        fentry = rule_files.get(conf_path)
        is_stock_file = conf_path.startswith(STOCK_RULE_DIR + "/") and base in stock.rules_by_file
        res.rule_files.append({"conf_path": conf_path, "origin": STOCK if is_stock_file else CUSTOM})
        elements = []
        customs = inv_rules_by_file.get(fentry["path"], []) if fentry is not None else []
        if is_stock_file:
            replaced = {r["id"] for r in customs}
            for e in stock.rules_by_file[base]:
                if e["id"] in replaced:
                    continue
                elements.append((e["line"], "stock", e))
        for r in customs:
            elements.append((r["line"], "custom", r))
        elements.sort(key=lambda x: x[0])
        for _line, origin, el in elements:
            seq += 1
            _register_rule(res, origin, el, seq, stock, excluded_stock_bases)
    return res


def _register_decoder(res, origin, el, stock):
    if origin == "stock":
        uid = StockIndex.decoder_uid(el)
        node = {"uid": uid, "origin": STOCK, "name": el["name"], "parent": el["parent"],
                "file": el["file"], "line": el["line"], "type": el.get("type")}
    else:
        uid = m.uid(el)
        if not el["name"]:
            res.add_code(uid, "RM-X-INVALID", "decoder without name")
            return
        same = [d for d in stock.decoder_names.get(el["name"], []) if d["sha256"] == element_sha256(el)]
        if same:
            res.add_code(uid, "RM-D-STOCK-COPY", "identical to stock decoder %s (%s:%d)" % (el["name"], same[0]["file"], same[0]["line"]))
        node = {"uid": uid, "origin": STOCK if same else CUSTOM, "name": el["name"], "parent": el["parent"],
                "file": el["file"], "line": el["line"], "type": el.get("type")}
    if node["parent"]:
        parents = res.dec_by_name.get(node["parent"], [])
        if not parents:
            if origin != "stock":
                res.add_code(uid, "RM-D-PARENT-NOT-LOADED", "parent decoder '%s' is not loaded before it" % node["parent"])
            return
        node["parents"] = list(parents)
    else:
        node["parents"] = []
    res.dec_nodes[uid] = node
    res.dec_by_name.setdefault(node["name"], []).append(uid)


def _rule_parents(res, el):
    """Resolve parents like OS_AddChild. Returns (parent uids, how, missing)."""
    p = el["parents"]
    if_sid = p.get("if_sid")
    if not if_sid and not p.get("if_group") and p.get("if_matched_sid"):
        if_sid = [p["if_matched_sid"]] if isinstance(p["if_matched_sid"], str) and p["if_matched_sid"].isdigit() else []
    if if_sid:
        found, missing = [], []
        for sid in if_sid:
            uid = res.by_id.get(sid)
            if uid is None:
                missing.append(sid)
            elif uid not in found:
                found.append(uid)
        return found, "if_sid", missing
    if p.get("if_level"):
        try:
            lvl = int(p["if_level"])
        except ValueError:
            return [], "if_level", [p["if_level"]]
        found = [u for u in res.node_order if (res.nodes[u]["level"] or 0) >= lvl and res.nodes[u]["id"] != el["id"]]
        return found, "if_level", [] if found else [p["if_level"]]
    group = p.get("if_group") or p.get("if_matched_group")
    if group:
        found = [u for u in res.node_order
                 if res.nodes[u]["id"] != el["id"] and os_word_match(group, res.nodes[u]["group_string"])]
        return found, "if_group", [] if found else [group]
    # root rule: first template of its category (rules_list.c:112)
    cat = el.get("category") or "syslog"
    for u in res.node_order:
        n = res.nodes[u]
        if n.get("template") and n.get("category") == cat:
            return [u], "category", []
    return [], "category", []


def _register_rule(res, origin, el, seq, stock, excluded_stock_bases):
    if origin == "stock":
        uid = StockIndex.rule_uid(el)
        node = {
            "uid": uid, "origin": STOCK, "id": el["id"], "level": el["level"],
            "noalert": el["attrs"].get("noalert") == "1", "group_string": el["group_string"],
            "category": el.get("category"), "file": el["file"], "line": el["line"], "seq": seq,
            "template": el["file"] == TEMPLATE_FILE and not el["parents"],
            "decoded_as": el.get("decoded_as"), "item": None,
        }
        if el["id"] in res.by_id:
            return
        parents, how, _missing = _rule_parents(res, el)
        if not parents and not node["template"]:
            return  # stock rule whose parent is excluded: 4.x discards it
        node["parents"] = parents
        node["link"] = how
        res.nodes[uid] = node
        res.node_order.append(uid)
        res.by_id[el["id"]] = uid
        return

    uid = m.uid(el)
    if el["id"] is None or el["level"] is None:
        return  # classify adds RM-X-INVALID from the parse problems
    if res.codes.get(uid) and any(c[0] == "RM-R-FILE-SHADOWED" for c in res.codes[uid]):
        return
    sha = element_sha256(el)
    stock_same = [e for e in stock.rules_by_id.get(el["id"], []) if e["sha256"] == sha]
    overwrite = (el["attrs"].get("overwrite") or "").lower() == "yes"
    loaded_uid = res.by_id.get(el["id"])
    if loaded_uid is not None:
        target = res.nodes[loaded_uid]
        if overwrite:
            if target["origin"] == STOCK:
                res.add_code(uid, "RM-R-OVERWRITE-STOCK", "overwrite=\"yes\" on stock rule %s (%s:%d)" % (target["id"], target["file"], target["line"]))
                res.stock_overwrites.setdefault(loaded_uid, []).append(uid)
            else:
                res.add_code(uid, "RM-R-OVERWRITE-MERGED", "overwrites custom rule %s at %s:%d" % (target["id"], target["file"], target["line"]))
                target["overwritten_by"] = uid
            return
        detail = "id %s already loaded from %s:%d; 4.x ignores this one" % (el["id"], target["file"], target["line"])
        if stock_same:
            detail += " (identical to the stock rule)"
        res.add_code(uid, "RM-R-DUPLICATE-ID", detail)
        return
    # id not loaded yet
    parents, how, missing = _rule_parents(res, el)
    if not parents:
        what = ", ".join(missing) if missing else "its category template"
        res.add_code(uid, "RM-R-PARENT-NOT-LOADED", "%s %s is not loaded before this rule: 4.x discards it" % (how, what))
        return
    if missing:
        res.add_note(uid, "if_sid %s not loaded before this rule: 4.x links it only to the others" % ", ".join(missing))
    for li in el["lists"]:
        if li["path"] not in res.available_lists:
            if li["path"] in res.declared_lists:
                detail = "list %s is declared but its file is missing: 4.x discards the rule" % li["path"]
            else:
                detail = "list %s is not declared in <ruleset><list>: 4.x discards the rule" % li["path"]
            res.add_code(uid, "RM-L-MISSING", detail)
            return
    node_origin = CUSTOM
    if stock_same:
        res.add_code(uid, "RM-R-STOCK-COPY", "identical to stock rule %s (%s:%d)" % (el["id"], stock_same[0]["file"], stock_same[0]["line"]))
        node_origin = STOCK
    elif el["id"] in stock.rules_by_id:
        e = stock.rules_by_id[el["id"]][0]
        if el["file"].rsplit("/", 1)[-1] == e["file"]:
            why = "modified copy of its stock file"
        elif e["file"] in excluded_stock_bases:
            why = "its stock file is excluded"
        else:
            why = "loaded before the stock rule, which 4.x then ignores"
        res.add_code(uid, "RM-R-OVERWRITE-STOCK", "replaces stock rule %s (%s:%d), %s" % (el["id"], e["file"], e["line"], why))
    elif overwrite:
        res.add_note(uid, "overwrite=\"yes\" on an id that is not loaded: loaded as a normal rule")
    node = {
        "uid": uid, "origin": node_origin, "id": el["id"], "level": el["level"],
        "noalert": el["attrs"].get("noalert") == "1", "group_string": el["group_string"],
        "category": el.get("category"), "file": el["file"], "line": el["line"], "seq": seq,
        "template": False, "decoded_as": el.get("decoded_as"), "item": uid,
        "parents": parents, "link": how,
    }
    res.nodes[uid] = node
    res.node_order.append(uid)
    res.by_id[el["id"]] = uid
    res.item_node[uid] = uid
