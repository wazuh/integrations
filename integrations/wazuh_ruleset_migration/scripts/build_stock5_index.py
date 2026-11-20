"""Build ``rmig/data/stock5-index.json``: the stock 5.x index of the offline
"5.x stock for your sources" report section (:mod:`rmig.stock5`).

Input: a catalog snapshot directory with ``manifest.json``, ``integrations/``,
``decoders/`` and ``rules/`` (one JSON per asset, ``payload.document``), as
pulled from the CTI catalog. The output keeps only what the report needs:

* integrations: title, enabled, category, decoder names, rule ids,
  ``detector.source``;
* decoders (roots of their integration, and any decoder with probes):
  integration, root flag, and typed probes taken from the ``check``
  (and the ``definitions`` the check names): literals the event must contain or
  start with, ``process.name`` values, the ``_tmp_json.integration`` tag and
  ``exists($_tmp_json.<key>)`` keys. Regular expressions give literal fragments
  only. No expression is evaluated;
* rules: id, title, level, enabled, integrations (a rule can sit in two), logsource product, MITRE
  technique ids, and the ``event.dataset``, ``event.code`` and
  ``wazuh.integration.name`` values of the detection.

usage: build_stock5_index.py <snapshot dir> [<out>]
"""

import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "rmig", "data", "stock5-index.json")

_Q = r"""(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")"""
_TEXT_FIELDS = r"\$(?:event\.original|message)"
RE_CONTAINS = re.compile(r"contains\(\s*" + _TEXT_FIELDS + r"\s*,\s*(?:" + _Q + r"|([^)'\"]+))\)")
RE_STARTS = re.compile(r"starts_with\(\s*" + _TEXT_FIELDS + r"\s*,\s*" + _Q + r"\)")
RE_REGEX = re.compile(r"regex_match\(\s*" + _TEXT_FIELDS + r"\s*,\s*" + _Q + r"\)")
RE_PROC = re.compile(r"\$process\.name\s*==\s*(?:" + _Q + r"|([A-Za-z0-9_.\-]+))")
RE_TAG = re.compile(r"\$_tmp_json\.integration\s*==\s*" + _Q)
RE_EXISTS = re.compile(r"exists\(\s*\$_tmp_json\.([A-Za-z0-9_.@\-]+)\s*\)")
RE_DEF = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")
RE_TECH = re.compile(r"^T\d{4}(?:\.\d{3})?$")
MIN_FRAGMENT = 4


def _q(m, first=1):
    """The first non-empty quoted or bare group of a match, unescaped."""
    for g in m.groups()[first - 1:]:
        if g:
            return g.replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")
    return None


def regex_fragments(pattern):
    """Literal runs of a regular expression (escaped punctuation kept, classes
    and quantified characters cut)."""
    out, cur, i = [], [], 0
    p = re.sub(r"\(\?[a-zA-Z]*:", "(", pattern)
    while i < len(p):
        c = p[i]
        if c == "\\" and i + 1 < len(p):
            n = p[i + 1]
            if n.isalnum():
                out.append("".join(cur))
                cur = []
            else:
                cur.append(n)
            i += 2
            continue
        if c in "^$.|()[]{}*+?":
            if c in "*+?{" and cur:
                cur.pop()
            if c == "[":
                j = p.find("]", i + 1)
                i = j if j > 0 else i
            if c == "{":
                j = p.find("}", i + 1)
                i = j if j > 0 else i
            out.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    out.append("".join(cur))
    return [f for f in out if len(f.strip()) >= MIN_FRAGMENT]


def _check_text(check, definitions):
    """The check as text, with the definitions it names appended."""
    if check is None:
        return ""
    if isinstance(check, list):
        parts = []
        for cond in check:
            for field, helper in cond.items():
                parts.append("%s(%s)" % (field, helper))
        text = " AND ".join(parts)
    else:
        text = str(check)
    defs = definitions or {}
    seen = set()
    todo = RE_DEF.findall(text)
    while todo:
        name = todo.pop()
        if name in seen or name not in defs or not isinstance(defs[name], str):
            continue
        seen.add(name)
        text += " AND " + defs[name]
        todo.extend(RE_DEF.findall(defs[name]))
    return text


def probes(check, definitions=None):
    """Typed probes of a decoder check."""
    contains, starts, frags, procs, tags, keys = set(), set(), set(), set(), set(), set()
    if isinstance(check, list):
        for cond in check:
            for field, helper in cond.items():
                if not isinstance(helper, str):
                    continue
                m = re.match(r"^(contains|starts_with|regex_match)\((.*)\)$", helper)
                if field in ("event.original", "message") and m:
                    arg = m.group(2).strip()
                    if len(arg) >= 2 and arg[0] in "'\"" and arg[-1] == arg[0]:
                        arg = arg[1:-1]
                    if m.group(1) == "contains":
                        contains.add(arg)
                    elif m.group(1) == "starts_with":
                        starts.add(arg)
                    else:
                        frags.update(regex_fragments(arg))
                elif field == "process.name" and re.match(r"^[A-Za-z0-9_.\-]+$", helper):
                    procs.add(helper)
                elif field.startswith("_tmp_json.") and helper.startswith("exists("):
                    keys.add(field[len("_tmp_json."):])
    text = _check_text(check, definitions)

    def positive(m):
        """Not negated (``NOT contains(...)`` asks the literal to be absent)."""
        return not text[:m.start()].rstrip().endswith("NOT")
    for m in RE_CONTAINS.finditer(text):
        if positive(m):
            contains.add(_q(m))
    for m in RE_STARTS.finditer(text):
        if positive(m):
            starts.add(_q(m))
    for m in RE_REGEX.finditer(text):
        if positive(m):
            frags.update(regex_fragments(_q(m)))
    for m in RE_PROC.finditer(text):
        procs.add(_q(m))
    for m in RE_TAG.finditer(text):
        tags.add(_q(m))
    for m in RE_EXISTS.finditer(text):
        keys.add(m.group(1))
    out = {}
    for k, v in (("contains", contains), ("starts_with", starts), ("regex_fragments", frags),
                 ("process_names", procs), ("json_tags", tags), ("json_keys", keys)):
        v = sorted(x for x in v if x)
        if v:
            out[k] = v
    return out


def _values(detection, field):
    """Values a detection selects for ``field`` (any modifier), as strings."""
    out = set()

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k.split("|")[0] == field:
                    for val in (v if isinstance(v, list) else [v]):
                        if isinstance(val, (str, int)):
                            out.add(str(val))
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk({k: v for k, v in detection.items() if k != "condition"})
    return sorted(out)


def _load(snap, kind):
    out = []
    for path in sorted(glob.glob(os.path.join(snap, kind, "*.json"))):
        with open(path, encoding="utf-8") as fh:
            out.append(json.load(fh)["payload"]["document"])
    return out


def build(snap):
    with open(os.path.join(snap, "manifest.json"), encoding="utf-8") as fh:
        man = json.load(fh)
    decs = {d["id"]: d for d in _load(snap, "decoders")}
    rules = {r["id"]: r for r in _load(snap, "rules")}
    integrations, decoders, rule_out = {}, {}, {}
    for doc in _load(snap, "integrations"):
        title = doc["metadata"]["title"]
        names = [decs[x]["name"] for x in doc.get("decoders", []) if x in decs]
        integrations[title] = {
            "enabled": bool(doc.get("enabled")),
            "category": doc.get("category"),
            "decoders": sorted(names),
            "rules": sorted(doc.get("rules", [])),
            "detector_source": sorted((doc.get("detector") or {}).get("source") or []),
        }
        for x in doc.get("decoders", []):
            d = decs.get(x)
            if d is None:
                continue
            root = not any(p in names for p in (d.get("parents") or []))
            pr = probes(d.get("check"), d.get("definitions"))
            if not root and not pr:
                continue
            ent = {"integration": title, "root": root, "parents": sorted(d.get("parents") or [])}
            if pr:
                ent["probes"] = pr
            decoders[d["name"]] = ent
        for rid in doc.get("rules", []):
            r = rules.get(rid)
            if r is None:
                continue
            if rid in rule_out:
                rule_out[rid]["integrations"] = sorted(set(rule_out[rid]["integrations"]) | {title})
                continue
            tech = sorted({t.upper() for t in ((r.get("mitre") or {}).get("technique") or {}).get("id") or []
                           if RE_TECH.match(t.upper())})
            det = r.get("detection") or {}
            ent = {"integrations": [title], "title": (r.get("metadata") or {}).get("title"), "level": r.get("level"),
                   "enabled": bool(r.get("enabled")), "product": (r.get("logsource") or {}).get("product"),
                   "techniques": tech}
            for key, field in (("datasets", "event.dataset"), ("event_codes", "event.code"),
                               ("integration_names", "wazuh.integration.name")):
                v = _values(det, field)
                if v:
                    ent[key] = v
            rule_out[rid] = ent
    return {
        "version": 1,
        "source": {"catalog": "Wazuh 5.0 content catalog", "consumer": man.get("consumer"), "context": man.get("context"),
                   "offset": man.get("offset"), "snapshot_at": man.get("snapshot_at"),
                   "ndjson_sha256": man.get("ndjson_sha256"),
                   "counts": {k: man.get("counts", {}).get(k) for k in ("integrations", "decoders", "rules")}},
        "generated_by": "scripts/build_stock5_index.py",
        "integrations": dict(sorted(integrations.items())),
        "decoders": dict(sorted(decoders.items())),
        "rules": dict(sorted(rule_out.items())),
    }


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    out = argv[2] if len(argv) > 2 else OUT
    data = build(argv[1])
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=None, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        fh.write("\n")
    print("stock5 index: %d integration(s), %d decoder(s), %d rule(s), offset %s -> %s (%d bytes)" % (
        len(data["integrations"]), len(data["decoders"]), len(data["rules"]), data["source"]["offset"], out,
        os.path.getsize(out)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
