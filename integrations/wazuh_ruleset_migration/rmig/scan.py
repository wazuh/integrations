"""``scan``: read a 4.14 tree into ``work/inventory.json``.

Three layouts are accepted for ``--source``:

``etc``
    a copy of ``/var/ossec/etc`` (has ``ossec.conf``): ``rules/``, ``decoders/``
    and ``lists/`` are read; ``ruleset/...`` paths are the stock index.
``root``
    a copy of ``/var/ossec`` (has ``etc/ossec.conf``): ``etc/...`` is read and, if
    present, ``ruleset/rules`` and ``ruleset/decoders`` are compared with the
    stock index element by element (only what differs is kept).
``loose``
    a tree of loose files without ``ossec.conf`` (a public rules repository):
    the default 4.14 ``<ruleset>`` block is assumed and every ``*.xml`` of the
    tree is read recursively and placed in ``etc/rules`` or ``etc/decoders``
    according to its content. A list referenced by a rule as
    ``etc/lists/<name>`` and found in the tree by base name is placed in
    ``etc/lists`` and declared, as an installation of those files would do.

The inventory keeps every element with its ``file:line`` and is plain JSON.
"""

import hashlib
import os

from . import __version__, fsutil
from .parse.decoders import parse_decoders_text
from .parse.lists import parse_list_bytes
from .parse.ossec_conf import default_config, parse_conf_blocks, parse_ossec_conf
from .parse.rules import parse_rules_text
from .quality.lists import list_shape
from .parse.xmlreader import read_xml
from .stock import element_sha256, load_stock_index


class ScanError(Exception):
    pass


def detect_mode(source):
    if os.path.isfile(os.path.join(source, "ossec.conf")):
        return "etc"
    if os.path.isfile(os.path.join(source, "etc", "ossec.conf")):
        return "root"
    return "loose"


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def classify_xml(text):
    """``rules``, ``decoders``, ``mixed`` or ``other`` from the root elements."""
    roots, _v, _e = read_xml(text)
    tags = {r.tag.lower() for r in roots} - {"var"}
    has_rules = bool(tags & {"group", "rule"})
    has_dec = "decoder" in tags
    if has_rules and has_dec:
        return "mixed"
    if has_rules:
        return "rules"
    if has_dec:
        return "decoders"
    return "other"


def _file_entry(path_display, conf_path, role, data, problems=None, stock_dir=False):
    entry = {
        "path": path_display,
        "conf_path": conf_path,
        "basename": conf_path.rsplit("/", 1)[-1],
        "role": role,
        "sha256": _sha(data),
        "stock_dir": stock_dir,
        "errors": [],
        "unknown": [],
    }
    if problems:
        entry["errors"] = problems.get("errors", [])
        entry["unknown"] = problems.get("unknown", [])
    return entry


def scan(source, stock=None):
    """Return the inventory dict for ``source``."""
    if not os.path.isdir(source):
        raise ScanError("source directory not found: %s" % source)
    stock = stock or load_stock_index()
    mode = detect_mode(source)
    inv = {
        "version": 1,
        "tool": "rmig %s" % __version__,
        "source": {"mode": mode, "name": os.path.basename(os.path.normpath(source))},
        "stock_index": {"source": stock.source},
        "ruleset": None,
        "conf_problems": {"errors": [], "unknown": []},
        "files": [],
        "rules": [],
        "decoders": [],
        "lists": [],
        "stock_dir_summary": {},
        "conf_files": [],
        "agent_groups": [],
    }

    if mode == "etc":
        conf_text = fsutil.read_text(os.path.join(source, "ossec.conf"))
        inv["ruleset"], inv["conf_problems"] = parse_ossec_conf(conf_text)
        inv["conf_files"] = [parse_conf_blocks(conf_text, "ossec.conf")]
        etc_base = source
    elif mode == "root":
        conf_text = fsutil.read_text(os.path.join(source, "etc", "ossec.conf"))
        inv["ruleset"], inv["conf_problems"] = parse_ossec_conf(conf_text)
        inv["conf_files"] = [parse_conf_blocks(conf_text, "etc/ossec.conf")]
        etc_base = os.path.join(source, "etc")
    else:
        inv["ruleset"] = default_config()
        etc_base = None

    if mode in ("etc", "root"):
        _scan_configured(inv, source, mode, etc_base, stock)
        inv["agent_groups"] = sorted(n for n in fsutil.listdir_sorted(os.path.join(etc_base, "shared"))
                                     if os.path.isdir(os.path.join(etc_base, "shared", n)))
    else:
        _scan_loose(inv, source, stock)

    inv["files"].sort(key=lambda f: f["path"])
    for key in ("rules", "decoders", "lists"):
        inv[key].sort(key=lambda it: (it["file"], it["line"]))
    return inv


def _dirs_from_conf(config, element):
    return [d[1] for d in config["directives"] if d[0] == element]


def _scan_configured(inv, source, mode, etc_base, stock):
    config = inv["ruleset"]
    seen = set()

    root = source  # every read stays inside the tree given with --source
    skipped = []

    def refuse(what):
        if what not in skipped:
            skipped.append(what)
            inv["conf_problems"]["errors"].append(
                {"line": 0, "message": "%s leaves the source tree: not read" % what})

    def physical(conf_dir):
        """Directory on disk for a path of the ruleset block, or None (also when it leaves the source tree)."""
        conf_dir = conf_dir.rstrip("/")
        disk = disp = None
        if conf_dir.startswith("etc/"):
            disk, disp = os.path.join(etc_base, conf_dir[4:]), "etc/" + conf_dir[4:]
        elif mode == "root" and conf_dir.startswith("ruleset/"):
            disk, disp = os.path.join(source, conf_dir), conf_dir
        if disk is not None and not fsutil.inside(root, disk):
            refuse(conf_dir)
            return None, None
        return disk, disp

    for role, dir_el, inc_el in (("rules", "rule_dir", "rule_include"), ("decoders", "decoder_dir", "decoder_include")):
        dirs = _dirs_from_conf(config, dir_el)
        for conf_dir in dirs:
            disk, disp = physical(conf_dir)
            if disk is None or not os.path.isdir(disk):
                continue
            is_stock_dir = conf_dir.rstrip("/").startswith("ruleset/")
            for name in fsutil.listdir_sorted(disk):
                full = os.path.join(disk, name)
                if not os.path.isfile(full) or not name.endswith(".xml"):
                    continue
                if not fsutil.inside(root, full):
                    refuse(disp + "/" + name)
                    continue
                conf_path = conf_dir.rstrip("/") + "/" + name
                if conf_path in seen:
                    continue
                seen.add(conf_path)
                _read_xml_file(inv, full, disp + "/" + name, conf_path, role, stock, is_stock_dir)
        for inc in _dirs_from_conf(config, inc_el):
            disk_dir, disp_dir = physical(inc.rsplit("/", 1)[0]) if "/" in inc else (None, None)
            if disk_dir is None:
                continue
            full = os.path.join(disk_dir, inc.rsplit("/", 1)[1])
            if inc.rsplit("/", 1)[1] in ("..", ".") or (os.path.exists(full) and not fsutil.inside(root, full)):
                refuse(inc)
                continue
            if inc in seen or not os.path.isfile(full):
                continue
            seen.add(inc)
            _read_xml_file(inv, full, disp_dir + "/" + inc.rsplit("/", 1)[1], inc, role, stock,
                           inc.startswith("ruleset/"))

    # lists: every file under etc/lists, plus declared ones elsewhere
    lists_dir = os.path.join(etc_base, "lists")
    outside = []
    files = fsutil.walk_files(lists_dir, outside)
    for rel in outside:
        refuse("etc/lists/" + rel)
    for rel in files:
        if rel.endswith(".cdb") or rel.endswith(".tmp"):
            continue
        data = fsutil.read_bytes(os.path.join(lists_dir, rel))
        name = "etc/lists/" + rel
        item = parse_list_bytes(data, name, name)
        item["shape"] = list_shape(data)
        inv["lists"].append(item)
        inv["files"].append(_file_entry(name, name, "list", data))


def _read_xml_file(inv, full, display, conf_path, role, stock, is_stock_dir):
    data = fsutil.read_bytes(full)
    text = data.decode("utf-8", "replace").replace("\r\n", "\n")
    if role == "rules":
        items, problems = parse_rules_text(text, display)
    else:
        items, problems = parse_decoders_text(text, display)
    entry = _file_entry(display, conf_path, role, data, problems, stock_dir=is_stock_dir)
    if is_stock_dir:
        kept = _diff_against_stock(items, role, conf_path.rsplit("/", 1)[-1], stock)
        inv["stock_dir_summary"][display] = {"elements": len(items), "differing": len(kept)}
        items = kept
    inv["files"].append(entry)
    inv[role].extend(items)


def _diff_against_stock(items, role, basename, stock):
    """Elements of a physical stock file that differ from the index."""
    if role == "rules":
        ref = {(r["id"], r["sha256"]) for r in stock.rules_by_file.get(basename, [])}
        return [it for it in items if (it["id"], element_sha256(it)) not in ref]
    ref = {(d["name"], d["sha256"]) for d in stock.decoders_by_file.get(basename, [])}
    return [it for it in items if (it["name"], element_sha256(it)) not in ref]


def _scan_loose(inv, source, stock):
    all_files = fsutil.walk_files(source)
    by_base = {}
    for rel in all_files:
        by_base.setdefault(rel.rsplit("/", 1)[-1], []).append(rel)
    for rel in all_files:
        if not rel.lower().endswith(".xml"):
            continue
        full = os.path.join(source, rel)
        data = fsutil.read_bytes(full)
        text = data.decode("utf-8", "replace").replace("\r\n", "\n")
        kind = classify_xml(text)
        base = rel.rsplit("/", 1)[-1]
        if kind in ("rules", "mixed"):
            items, problems = parse_rules_text(text, rel)
            entry = _file_entry(rel, "etc/rules/" + base, "rules", data, problems)
            if kind == "mixed":
                entry["errors"].append({"line": 1, "message": "file mixes rules and decoders; read as rules"})
            inv["files"].append(entry)
            inv["rules"].extend(items)
        elif kind == "decoders":
            items, problems = parse_decoders_text(text, rel)
            inv["files"].append(_file_entry(rel, "etc/decoders/" + base, "decoders", data, problems))
            inv["decoders"].extend(items)
        else:
            inv["files"].append(_file_entry(rel, rel, "other", data))
    # ossec.conf files or fragments in the tree: read for the report only, never for the ruleset
    for rel in all_files:
        base = rel.rsplit("/", 1)[-1].lower()
        if base.startswith("ossec") and ".conf" in base:
            inv["conf_files"].append(parse_conf_blocks(fsutil.read_text(os.path.join(source, rel)), rel))
    # lists referenced by rules and present in the tree
    declared = {d[1] for d in inv["ruleset"]["directives"] if d[0] == "list"}
    wanted = sorted({li["path"] for r in inv["rules"] for li in r["lists"]})
    for path in wanted:
        if not path.startswith("etc/lists/"):
            continue
        base = path.rsplit("/", 1)[-1]
        candidates = [p for p in by_base.get(base, []) if not p.lower().endswith(".xml")]
        if not candidates:
            continue
        rel = candidates[0]
        data = fsutil.read_bytes(os.path.join(source, rel))
        item = parse_list_bytes(data, rel, path)
        item["shape"] = list_shape(data)
        inv["lists"].append(item)
        inv["files"].append(_file_entry(rel, path, "list", data))
        if path not in declared:
            inv["ruleset"]["directives"].append(["list", path, {"assumed": "loose tree"}])
            declared.add(path)


def scanned_counts(inv):
    return {
        "rules": len(inv["rules"]),
        "decoders": len(inv["decoders"]),
        "lists": len(inv["lists"]),
        "files": len(inv["files"]),
    }


__all__ = ["scan", "ScanError", "detect_mode", "classify_xml", "scanned_counts"]
