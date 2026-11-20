"""Parser of 4.14 rule files (``wazuh@4.14.13:src/analysisd/rules.c``)."""

import re

from .. import model4 as m
from .xmlreader import read_xml

_IF_SID_OK = re.compile(r"^[\d, ]+$")


def _engine(node, default, problems):
    t = node.attr("type")
    if t is None:
        return default
    t = t.strip().lower()
    if t in m.ENGINES:
        return t
    problems.append({"line": node.line, "message": "invalid type '%s' in <%s>; 4.14 keeps the default" % (t, node.tag)})
    return default


def _negate(node):
    v = node.attr("negate")
    return bool(v) and v.strip().lower() == "yes"


def _text(node):
    return node.text if node.text is not None else ""


def parse_rule(node, rel, group_name):
    """Turn a ``<rule>`` node into a Rule4 dict."""
    rule = {
        "kind": m.RULE,
        "file": rel,
        "line": node.line,
        "id": None,
        "level": None,
        "attrs": {},
        "group_string": group_name or "",
        "groups": [],
        "parents": {},
        "decoded_as": None,
        "category": None,
        "conditions": [],
        "fields": [],
        "lists": [],
        "correlation": {},
        "flags": {},
        "description": None,
        "mitre": [],
        "options": [],
        "info": [],
        "unknown": [],
        "invalid": [],
    }
    for key, value in node.attrs:
        k = key.lower()
        if k == "id":
            rule["id"] = value.strip()
        elif k == "level":
            rule["level"] = value.strip()
        elif k in m.RULE_ATTRIBUTES:
            rule["attrs"][k] = value.strip()
        else:
            rule["unknown"].append({"line": node.line, "element": "@" + key})
    # id / level validation (rules.c:2280, 2289)
    if rule["id"] is None or not re.fullmatch(r"\d{1,6}", rule["id"]):
        rule["invalid"].append({"line": node.line, "message": "missing or invalid rule id %r" % rule["id"]})
    else:
        rule["id"] = str(int(rule["id"]))
    lvl = rule["level"]
    if lvl is None or not re.fullmatch(r"\d{1,2}", lvl) or int(lvl) > 16:
        rule["invalid"].append({"line": node.line, "message": "missing or invalid level %r" % lvl})
        rule["level"] = None
    else:
        rule["level"] = int(lvl)

    pattern_acc = {}  # element -> [value, engine, negate, line]
    ips = {}
    own_groups = []
    for child in node.children:
        tag = child.tag.lower()
        text = _text(child)
        if tag in m.RULE_PATTERN_ELEMENTS:
            eng = _engine(child, m.RULE_PATTERN_ELEMENTS[tag], rule["invalid"])
            if tag in pattern_acc:
                acc = pattern_acc[tag]
                acc[0] += text  # loadmemory: strcat without separator
                acc[1] = eng
                acc[2] = _negate(child)
            else:
                pattern_acc[tag] = [text, eng, _negate(child), child.line]
        elif tag in m.RULE_IP_ELEMENTS:
            entry = ips.setdefault(tag, {"elem": tag, "values": [], "engine": "osip", "negate": False, "line": child.line})
            entry["values"].append(text.strip())
            if _negate(child):
                entry["negate"] = True
        elif tag == "field":
            rule["fields"].append({
                "name": (child.attr("name") or "").strip(),
                "value": text,
                "engine": _engine(child, "osregex", rule["invalid"]),
                "negate": _negate(child),
                "line": child.line,
            })
            if not child.attr("name"):
                rule["invalid"].append({"line": child.line, "message": "<field> without name"})
        elif tag == "list":
            lookup = (child.attr("lookup") or "match_key").strip()
            if lookup not in m.LIST_LOOKUPS:
                rule["invalid"].append({"line": child.line, "message": "invalid list lookup '%s'" % lookup})
            rule["lists"].append({
                "path": text.strip(),
                "field": (child.attr("field") or "").strip(),
                "lookup": lookup,
                "check_value": child.attr("check_value"),
                "line": child.line,
            })
        elif tag == "decoded_as":
            rule["decoded_as"] = text.strip()
        elif tag == "category":
            rule["category"] = text.strip()
            if rule["category"] not in m.RULE_CATEGORIES:
                rule["invalid"].append({"line": child.line, "message": "invalid category '%s'" % rule["category"]})
        elif tag == "if_sid":
            raw = text.strip()
            if not _IF_SID_OK.match(raw):
                rule["invalid"].append({"line": child.line, "message": "invalid if_sid '%s' (4.14 discards the rule)" % raw})
            ids = [str(int(x)) for x in re.split(r"[,\s]+", raw) if x.isdigit()]
            rule["parents"]["if_sid"] = ids
        elif tag == "if_matched_sid":
            raw = text.strip()
            if not raw.isdigit():
                rule["invalid"].append({"line": child.line, "message": "invalid if_matched_sid '%s'" % raw})
                rule["parents"]["if_matched_sid"] = raw
            else:
                rule["parents"]["if_matched_sid"] = str(int(raw))
        elif tag in ("if_group", "if_matched_group", "if_matched_regex", "if_level"):
            rule["parents"][tag] = text.strip()
        elif tag in m.RULE_FLAG_ELEMENTS:
            rule["flags"][tag] = text.strip()
        elif tag in m.RULE_SAME_DIFFERENT:
            rule["correlation"].setdefault(tag, []).append(text.strip())
        elif tag == "description":
            rule["description"] = text if rule["description"] is None else rule["description"] + text
        elif tag == "group":
            own_groups.append(text)
        elif tag == "info":
            rule["info"].append({"type": (child.attr("type") or "text").strip(), "value": text.strip()})
        elif tag == "cve":
            rule["info"].append({"type": "cve", "value": text.strip()})
        elif tag == "mitre":
            entry = {}
            for sub in child.children:
                st = sub.tag.lower()
                if st in ("id", "tacticid", "techniqueid"):
                    entry.setdefault(sub.tag, []).append(_text(sub).strip())
                else:
                    rule["unknown"].append({"line": sub.line, "element": "mitre/" + sub.tag})
            rule["mitre"].append(entry)
        elif tag == "options":
            for opt in text.split(","):
                opt = opt.strip()
                if not opt:
                    continue
                if opt not in m.RULE_OPTIONS:
                    rule["invalid"].append({"line": child.line, "message": "invalid option '%s'" % opt})
                rule["options"].append(opt)
        else:
            rule["unknown"].append({"line": child.line, "element": child.tag})

    for tag, (value, eng, neg, line) in pattern_acc.items():
        rule["conditions"].append({"elem": tag, "value": value, "engine": eng, "negate": neg, "line": line})
    for tag in m.RULE_IP_ELEMENTS:
        if tag in ips:
            rule["conditions"].append(ips[tag])
    rule["conditions"].sort(key=lambda c: (c["line"], c["elem"]))
    if rule["description"] is None:
        rule["invalid"].append({"line": node.line, "message": "rule without description"})
    # group string: file group name + own <group> elements (rules.c:427, 581)
    rule["group_string"] = (group_name or "") + "".join(g.replace("\n", "") for g in own_groups)
    rule["groups"] = [g.strip() for g in rule["group_string"].split(",") if g.strip()]
    # frequency without correlation is a load error (rules.c:1666)
    if "frequency" in rule["attrs"] and not (
        rule["parents"].get("if_matched_sid") or rule["parents"].get("if_matched_group")
        or rule["parents"].get("if_matched_regex") or "check_diff" in rule["flags"]
    ):
        rule["invalid"].append({"line": node.line, "message": "frequency without if_matched_* (4.14 refuses to load)"})
    return rule


def parse_rules_text(text, rel):
    """Parse the text of a rules file. Returns (rules, file_problems).

    ``file_problems`` is a dict with ``errors`` (syntax, from the XML reader)
    and ``unknown`` (root or group children that are not rules)."""
    roots, variables, errors = read_xml(text)
    problems = {"errors": [e.as_dict() for e in errors], "unknown": [], "variables": sorted(variables)}
    rules = []
    for root in roots:
        tag = root.tag.lower()
        if tag == "var":
            continue
        if tag == "group":
            gname = root.attr("name")
            if gname is None:
                problems["errors"].append({"line": root.line, "message": "<group> without name"})
                gname = ""
            for child in root.children:
                ctag = child.tag.lower()
                if ctag == "rule":
                    rules.append(parse_rule(child, rel, gname))
                elif ctag == "var":
                    continue
                else:
                    problems["unknown"].append({"line": child.line, "element": child.tag})
        elif tag == "rule":
            # 4.14 only accepts rules inside <group>
            problems["errors"].append({"line": root.line, "message": "<rule> outside <group>"})
            rules.append(parse_rule(root, rel, ""))
        else:
            problems["unknown"].append({"line": root.line, "element": root.tag})
    return rules, problems
