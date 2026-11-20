#!/usr/bin/env python3
"""Generate ``rmig/data/wazuh4-base.json`` from a snapshot of the 5.x catalog.

Usage::

    python3 scripts/build_base.py --catalog <snapshot dir> \\
        --source "<catalog label>" [--out rmig/data/wazuh4-base.json]

    python3 scripts/build_base.py --refresh    # rebuild the predecoder only

The snapshot directory has ``integrations/``, ``decoders/``, ``kvdbs/`` and
``policies/`` with one JSON document per asset (``payload.document``). The
script takes the policy's root decoder and the KVDBs it uses, renames them with
the ``wazuh4-`` prefix and rewrites every reference by name (``parents``, KVDB
names in helper calls). It also records the title, category and ``enabled``
flag of every standard integration, which ``build`` needs for rules over stock
content.

Below the root it adds ``wazuh4-predecoder``, written here and not taken from
the catalog: it repeats the 4.x pre-decoding (``OS_CleanMSG``), so the header
fields and the text that migrated decoders and rules read are the ones 4.x
had. The 5.x syslog decoder is not used: it splits headers differently (for
example it does not take ``CEF`` as the program name of ``host CEF:0|...``).

Stock 4.x parents are not in this file: ``build`` recreates them at run time
from the user's 4.x ruleset (``rmig.translate.engine.stock_parents``).
Deterministic; no network access.

Helper names: the snapshot may predate the #41150 renames (``kvdb_get``,
``parse_key_value``...). Every decoder is rewritten to the current 5.0 names
(:func:`rmig.translate.helpers.to_current`, table in
``rmig/data/helper-renames-41150.json``), the tool's only internal dialect;
``build --engine-helpers 5.0-rc1`` turns them back at the end.
"""

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from rmig.fsutil import listdir_sorted  # noqa: E402
from rmig.jsonio import dumps, write_text  # noqa: E402
from rmig.translate import helpers as H  # noqa: E402
from rmig.translate.patterns import helper_quote  # noqa: E402

GENERATED_BY = "scripts/build_base.py"
DEFAULT_OUT = os.path.join(os.path.dirname(HERE), "rmig", "data", "wazuh4-base.json")
PREFIX = "wazuh4-"
CORE_INTEGRATION = "wazuh-core"
DROP_META = ("date", "modified")


def _docs(catalog, kind):
    d = os.path.join(catalog, kind)
    out = {}
    for name in listdir_sorted(d):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(d, name), "r", encoding="utf-8") as fh:
            doc = json.load(fh)["payload"]["document"]
        out[doc["id"]] = doc
    return out


def _decoder_name(name):
    m = re.match(r"^decoder/(.+)/(\d+)$", name)
    if not m:
        raise ValueError("unexpected decoder name %r" % name)
    return "decoder/%s%s/%s" % (PREFIX, m.group(1), m.group(2))


def _kvdbs_used(doc, titles):
    used = set()
    text = json.dumps(doc, sort_keys=True)
    for t in titles:
        if re.search(r"(?<![A-Za-z0-9_.-])%s(?![A-Za-z0-9_.-])" % re.escape(t), text):
            used.add(t)
    return used


def _rewrite(value, renames):
    if isinstance(value, dict):
        return {_rewrite(k, renames): _rewrite(v, renames) for k, v in value.items()}
    if isinstance(value, list):
        return [_rewrite(v, renames) for v in value]
    if isinstance(value, str):
        for old in sorted(renames, key=len, reverse=True):
            value = re.sub(r"(?<![A-Za-z0-9_./-])%s(?![A-Za-z0-9_.-])" % re.escape(old), renames[old], value)
        return value
    return value


def _clean(doc):
    doc = json.loads(json.dumps(doc))
    doc.pop("id", None)
    meta = doc.get("metadata", {})
    for k in DROP_META:
        meta.pop(k, None)
    return doc


# -- 4.x pre-decoding ----------------------------------------------------------
#
# ``OS_CleanMSG`` (wazuh@4.14.10:src/analysisd/cleanevent.c:26-352) splits the
# syslog header off a log line before any decoder runs: ``program_name``,
# ``hostname`` and the text the decoders and rules see (``lf->log``). The
# predecoder below repeats it with RE2, check by check and in the same order,
# so that ``process.name``, ``observer.hostname`` and ``message`` hold what 4.x
# would have had. ``observer.hostname`` is set only for the manager's own
# events (agent 000), since 4.x replaces the header hostname with the agent
# name for an agent's event. Differences: positions are characters, not bytes
# (only a non-ASCII header differs; the "Mär" repair is not repeated); an AIX
# header with neither ``: `` nor ``[pid]: `` after the program name keeps the
# text after the hostname as the log (4.x leaves the program name unterminated
# there); an ASL line takes Sender and Message even after its Host entry.

HOST = r"[()\-./0-9@A-Z_a-z]"  # isValidChar: hostname_map (src/os_regex/os_regex_maps.c)
ALNUM = r"[0-9A-Za-z]"
AIX = r"%s*\|[a-z]%s*:%s* " % (HOST, ALNUM, ALNUM)

# Timestamps that start the syslog branch, in the order of the C test. One
# capture: the text after the timestamp. Minimum lengths are the ``loglen > n``
# guards (loglen counts the final NUL).
SYSLOG_TIMESTAMPS = [
    ("a", r"^.{3} .{2} .{2}:.{2}:.{2} (.+)$"),                       # Dec 29 10:00:01
    ("b", r"^.{4}-.{2}-.{2} .{2}:.{2}:.{2},.{4}(.*)$"),              # 2015-04-16 21:51:02,805
    ("c1", r"^.{4}-.{2}-.{2}T.{2}:.{2}:.{5}:.{2} (.{7}.*)$"),        # 2007-06-14T15:48:55-04:00
    ("c2", r"^.{4}-.{2}-.{2}T.{2}:.{2}:.{2}\..{6}:.{3}(.{3}.*)$"),   # 2022-12-19T15:02:53.288+00:00
    ("c3", r"^.{4}-.{2}-.{2}T.{2}:.{2}:.{2}\..{6}.{3}:.{3}(.*)$"),   # 2009-05-22T09:36:46.214994-07:00
    ("c4", r"^.{4}-.{2}-.{2}T.{2}:.{2}:.{2}\..{12}(.+)$"),
    ("d", r"^[0-9].{3} .{3} .{2} .{2}:.{2}:.{2} (.*)$"),             # 2015 Dec 29 10:00:01
    ("e", r"^[0-9].{3}-.{2}-.{2} .{2}:.{2}:.{2}\..{6}[-+].{4} (.+)$"),  # 2021-04-21 10:16:09.404756-0700
]

# Other formats: only the timestamp is removed (in the C order).
OTHER_TIMESTAMPS = [
    ("xferlog", r"^.{3} .{3} .{2} .{2}:.{2}:.{2} .{4} (. .+)$"),     # Mon Apr 17 18:27:14 2006 1 ...
    ("snort", r"^.{2}/.{2}-.{2}:.{2}:.{2}\..{6} .(.+)$"),            # 01/28-09:13:16.240702  [**]
    ("suricata", r"^.{2}/.{2}/.{4}-.{2}:.{2}:.{2}\..{6} .(.*)$"),    # 01/28/1979-09:13:16.240702  [**]
    ("apache", r"^\[.{3} .{3} .{2} .{2}:.{2}:.{2} .{4}\].(.*)$"),    # [Fri Feb 11 18:06:35 2004] [warn]
]
ASL = r"^\[T.{3} .{4}\..{2}\..{2} .{2}:.{7}"                          # [Time 2006.12.28 15:53:55 UTC] ...
SQUID = r"^(1)[0-9]{3}.{6}\..{2}[0-9] (?:.{6} .{10}|.{7} .{9})"      # 1140804070.368  11623 ...


def _ex(field, pattern):
    # (?s): "." also takes a newline (an event can hold several lines), as the C checks fixed byte positions
    return "regex_extract($%s, %s)" % (field, helper_quote("(?s)" + pattern))


def _when(*conds):
    return [{f: ("exists()" if present else "not_exists()")} for f, present in conds]


def predecoder(root_name, name):
    """The 5.x decoder that repeats the 4.x pre-decoding (see above)."""
    n = []
    # 1. syslog timestamps: the first one that matches gives the text after it
    n.append({"map": [{"_w4.ts.%s" % k: _ex("event.original", rx)} for k, rx in SYSLOG_TIMESTAMPS]})
    for k, _rx in SYSLOG_TIMESTAMPS:
        n.append({"check": _when(("_w4.ts.%s" % k, True), ("_w4.rest", False)),
                  "map": [{"_w4.rest": "$_w4.ts.%s" % k}]})
    # 2. one optional space, then the hostname (or a Solaris program name)
    n.append({"check": _when(("_w4.rest", True)), "map": [
        {"_w4.r": _ex("_w4.rest", r"^ ?(.*)$")},
    ]})
    n.append({"check": _when(("_w4.r", True)), "map": [
        {"_w4.solaris.prog": _ex("_w4.r", r"^(%s*): " % HOST)},
        {"_w4.solaris.log": _ex("_w4.r", r"^%s*: (.*)$" % HOST)},
        {"_w4.host": _ex("_w4.r", r"^(%s*) " % HOST)},
        {"_w4.after": _ex("_w4.r", r"^%s* (.*)$" % HOST)},
    ]})
    # 3. program name after the hostname: p_name:, p_name[pid]:, p_name[pid] , AIX
    n.append({"check": _when(("_w4.after", True)), "map": [
        {"_w4.p1.prog": _ex("_w4.after", r"^(%s*):" % HOST)},
        {"_w4.p1.log": _ex("_w4.after", r"^%s*: ?(.*)$" % HOST)},
        {"_w4.p2.prog": _ex("_w4.after", r"^(%s*)\[[0-9]+\](?:: ?| )" % HOST)},
        {"_w4.p2.log": _ex("_w4.after", r"^%s*\[[0-9]+\](?:: ?| )(.*)$" % HOST)},
        {"_w4.p3.prog": _ex("_w4.after", r"^%s(%s*)(?:: |\[[0-9]+\]: )" % (AIX, HOST))},
        {"_w4.p3.log": _ex("_w4.after", r"^%s%s*(?:: |\[[0-9]+\]: )(.*)$" % (AIX, HOST))},
        {"_w4.p4.prog": _ex("_w4.after", r"^%s(%s*)" % (AIX, HOST))},
    ]})
    for src in ("solaris", "p1", "p2", "p3"):
        n.append({"check": _when(("_w4.%s.log" % src, True), ("_w4.log", False)), "map": [
            {"_w4.prog": "$_w4.%s.prog" % src},
            {"_w4.log": "$_w4.%s.log" % src},
            {"_w4.pieces": "true"},
        ]})
    n.append({"check": _when(("_w4.p4.prog", True), ("_w4.prog", False)), "map": [{"_w4.prog": "$_w4.p4.prog"}]})
    n.append({"check": _when(("_w4.after", True), ("_w4.log", False)), "map": [{"_w4.log": "$_w4.after"}]})
    # 4.x keeps the header hostname only for events of the manager itself: for an agent's event
    # (location "[id] (name) ...") it is replaced by the agent name (cleanevent.c:543-585)
    n.append({"map": [{"_w4.local": _ex("wazuh.agent.id", r"^(000)$")}]})
    n.append({"check": _when(("wazuh.agent.id", False)), "map": [{"_w4.local": "true"}]})
    n.append({"check": _when(("_w4.solaris.log", False), ("_w4.after", True), ("_w4.local", True)), "map": [
        {"observer.hostname": "$_w4.host"},
    ]})
    n.append({"check": _when(("_w4.r", True), ("_w4.log", False)), "map": [{"_w4.log": "$_w4.r"}]})
    # 4. [ID xx facility.severity] after a recognised program name
    n.append({"check": _when(("_w4.pieces", True)), "map": [
        {"_w4.id": _ex("_w4.log", r"^\[ID [^\]]*\].(.*)$")},
    ]})
    n.append({"check": _when(("_w4.id", True)), "map": [{"_w4.log": "$_w4.id"}]})
    # 5. other formats, only when no syslog timestamp matched
    n.append({"check": _when(("_w4.rest", False)), "map":
              [{"_w4.other.%s" % k: _ex("event.original", rx)} for k, rx in OTHER_TIMESTAMPS] + [
                  {"_w4.asl_header": _ex("event.original", "^(%s)" % ASL[1:])},
                  {"_w4.squid": _ex("event.original", SQUID)},
              ]})
    for k, _rx in OTHER_TIMESTAMPS:
        n.append({"check": _when(("_w4.other.%s" % k, True), ("_w4.log", False)),
                  "map": [{"_w4.log": "$_w4.other.%s" % k}]})
    n.append({"check": _when(("_w4.asl_header", True), ("_w4.log", False)), "map": [
        {"_w4.log": _ex("event.original", r"^.{25}(.*)$")},
        {"_w4.asl.msg": _ex("event.original", r"\[Message ([^\]]*)")},
        {"_w4.prog": _ex("event.original", r"\[Sender ([^\]]*)\]")},
        {"_w4.asl.host": _ex("event.original", r"\[Host ([^\]]*)\]")},
    ]})
    n.append({"check": _when(("_w4.asl.msg", True)), "map": [{"_w4.log": "$_w4.asl.msg"}]})
    n.append({"check": _when(("_w4.asl.host", True), ("_w4.local", True)), "map": [{"observer.hostname": "$_w4.asl.host"}]})
    n.append({"check": _when(("_w4.squid", True), ("_w4.log", False)), "map": [
        {"_w4.log": _ex("event.original", r"^.{14} *(.*)$")},
    ]})
    # 6. the fields every migrated decoder and rule reads
    n.append({"check": _when(("_w4.log", True)), "map": [{"message": "$_w4.log"}]})
    n.append({"check": _when(("_w4.log", False)), "map": [{"message": "$event.original"}]})
    n.append({"check": _when(("_w4.prog", True)), "map": [{"process.name": "$_w4.prog"}]})
    return {
        "name": name,
        "enabled": True,
        "metadata": {
            "title": name.split("/")[1],
            "description": "Wazuh 4.x pre-decoding (OS_CleanMSG): syslog header, hostname and program name, as "
                           "analysisd 4.14 splits them before decoding. Every migrated root decoder hangs from it.",
            "documentation": "",
            "references": ["https://github.com/wazuh/wazuh/blob/v4.14.10/src/analysisd/cleanevent.c"],
            "supports": [],
        },
        "parents": [root_name],
        "normalize": n,
    }


def _assemble(root_doc, root_stock_name, kvdb_entries, standard, snapshot, source):
    root_name = root_doc["name"]
    pre_name = "decoder/%spredecoder/0" % PREFIX
    return {
        "version": 2,
        "source": source,
        "snapshot": snapshot,
        "generated_by": GENERATED_BY,
        "engine_helpers": H.CURRENT,
        "integration": {"title": PREFIX + "base", "category": "unclassified", "stock_integration": CORE_INTEGRATION},
        "root": root_name,
        "predecoder": pre_name,
        "decoders": [
            {"stock_name": root_stock_name, "resource": root_doc},
            {"stock_name": "4.x pre-decoding", "resource": predecoder(root_name, pre_name)},
        ],
        "kvdbs": kvdb_entries,
        "standard_integrations": dict(sorted(standard.items())),
    }


def build(catalog, source):
    integrations = _docs(catalog, "integrations")
    decoders = _docs(catalog, "decoders")
    kvdbs = _docs(catalog, "kvdbs")
    policies = _docs(catalog, "policies")
    if len(policies) != 1:
        raise ValueError("expected one policy in %s, found %d" % (catalog, len(policies)))
    policy = next(iter(policies.values()))
    root = decoders[policy["root_decoder"]]
    core = [i for i in integrations.values() if i["metadata"]["title"] == CORE_INTEGRATION]
    if not core:
        raise ValueError("no %s integration in the snapshot" % CORE_INTEGRATION)
    if root["id"] not in core[0].get("decoders", []):
        raise ValueError("%s is not in %s" % (root["name"], CORE_INTEGRATION))

    kv_titles = {k["metadata"]["title"]: k for k in kvdbs.values()}
    used = sorted(_kvdbs_used(root, kv_titles))
    renames = {root["name"]: _decoder_name(root["name"])}
    renames.update({t: PREFIX + t for t in used})
    root_doc = H.to_current(_rewrite(_clean(root), renames))
    root_doc["metadata"]["title"] = root_doc["name"].split("/")[1]
    out_kvdbs = []
    for t in used:
        doc = _clean(kv_titles[t])
        doc["metadata"]["title"] = PREFIX + t
        out_kvdbs.append({"stock_title": t, "resource": doc})

    standard = {}
    for i in integrations.values():
        title = i["metadata"]["title"]
        standard[title] = {"category": i["category"], "enabled": bool(i.get("enabled"))}

    manifest_path = os.path.join(catalog, "manifest.json")
    snapshot = {}
    if os.path.isfile(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as fh:
            man = json.load(fh)
        snapshot = {k: man.get(k) for k in ("context", "offset", "ndjson_sha256", "snapshot_at") if k in man}
    return _assemble(root_doc, root["name"], out_kvdbs, standard, snapshot, source)


def refresh(path):
    """Rebuild the part that does not come from the catalog (the predecoder)
    on top of an existing base file."""
    with open(path, "r", encoding="utf-8") as fh:
        old = json.load(fh)
    root = [d for d in old["decoders"] if d["resource"]["name"] == old["root"]][0]
    used = _kvdbs_used(root["resource"], {k["resource"]["metadata"]["title"]: k for k in old["kvdbs"]})
    kvdbs = [k for k in old["kvdbs"] if k["resource"]["metadata"]["title"] in used]
    return _assemble(root["resource"], root["stock_name"], kvdbs, old["standard_integrations"],
                     old.get("snapshot", {}), old["source"])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--catalog", help="snapshot directory with integrations/, decoders/, kvdbs/, policies/")
    ap.add_argument("--source", help="provenance label written in the output (with --catalog)")
    ap.add_argument("--refresh", action="store_true",
                    help="keep the catalog parts of --out and rebuild only the predecoder")
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    if not args.refresh and not (args.catalog and args.source):
        ap.error("--catalog and --source are required unless --refresh is given")
    try:
        data = refresh(args.out) if args.refresh else build(args.catalog, args.source)
    except (OSError, ValueError, KeyError, H.HelperError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    write_text(args.out, dumps(data))
    print("root %s, predecoder %s, %d kvdb(s), %d standard integration(s) -> %s" % (
        data["root"], data["predecoder"], len(data["kvdbs"]),
        len(data["standard_integrations"]), args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
