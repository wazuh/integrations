"""The 5.x package in memory, in the shape of the ``out/`` contract."""

from .. import feeds as F
from .. import model4 as m
from .. import reasons as R
from . import helpers as H
from . import meta
from . import recipes as RC
from .decoders import decoder_name
from .patterns import helper_quote, to_re2

JSON_GATE_PREMATCH = r'^{\s*"'  # ruleset/decoders/0006-json_decoders.xml:19

DETECTOR_MAX_RULES = 50
BASE_KEY = "wazuh4-base"
BASE_FILE = "rmig/data/wazuh4-base.json"


class Package:
    def __init__(self):
        self.integrations = {}   # key -> dict (see assemble)
        self.monitors = {}       # rule id -> body
        self.recipes = {}        # file name -> text
        self.detectors = {}      # file name -> doc
        self.mapping = []        # rows
        self.missing_lists = []  # list paths whose content was not at hand
        self.root = None
        self.decoder_count = 0
        self.engine_helpers = H.DEFAULT
        self.helper_problems = []  # base decoders with a helper the target engine lacks
        self.load_rank = {}        # key -> 4.x load position of its root decoder

    def ordered_keys(self):
        """wazuh4-base, then the integrations in the 4.x load order of their root decoder, then the rules-only
        ones by name. The 5.x engine tries sibling decoders in the order of the policy's integrations, and
        4.x tries root decoders in load order: the first one that matches wins in both."""
        keys = sorted((k for k in self.integrations if k != BASE_KEY),
                      key=lambda k: (k not in self.load_rank, self.load_rank.get(k, 0), k))
        return ([BASE_KEY] if BASE_KEY in self.integrations else []) + keys


def _codes(acc):
    return sorted(acc.codes)


def _fidelity(codes):
    return R.fidelity_of(codes)


def _integration_doc(key, kind, category, stock_integration, description, date):
    lid = meta.local_id("integration", key)
    return {
        "local_id": lid,
        "kind": kind,
        "stock_integration": stock_integration,
        "resource": {
            "metadata": meta.metadata(key, lid, description, (), date),
            "category": category,
            "enabled": True,
        },
    }


def _new_integration(pkg, key, kind, category, stock_integration, description, date):
    if key not in pkg.integrations:
        pkg.integrations[key] = {
            "doc": _integration_doc(key, kind, category, stock_integration, description, date),
            "kvdbs": {},     # title -> doc
            "decoders": [],  # docs, parents first
            "rules": {},     # rule id -> doc
        }
    return pkg.integrations[key]


def _custom_category(tr, name):
    entry = tr.decisions.get("integrations", {}).get(name) or tr.clf.wanted["integrations"].get(name) or {}
    return entry.get("category") or "other"


def assemble(tr):
    pkg = Package()
    clf = tr.clf
    date = tr.date
    snapshot = tr.base.get("source", "")

    # ---- decoders ------------------------------------------------------------
    emitted_dec = {}
    for name, group in tr.dec.groups.items():
        first = group.uids[0]
        if group.resource is None or tr.state(first) != R.AUTO or group.resource["parent"] is None:
            continue
        emitted_dec[name] = group
    # label blocks of the emitted rules
    labels = {}  # decoder name -> {tag: blocks}
    for uid, r in tr.rules.items():
        if not tr.emitted(uid):
            continue
        for tag, (dname, blocks) in r.build.labels.items():
            if dname is None:
                continue
            if dname in tr.feeds:
                labels.setdefault(dname, {})[tag] = blocks
                continue
            for target in [dname] + tr.dec.descendants(dname):
                if target in emitted_dec:
                    labels.setdefault(target, {})[tag] = blocks
        for tag, per in r.build.field_labels.items():
            for target, blocks in per.items():
                if target in emitted_dec or target in tr.feeds:
                    labels.setdefault(target, {})[tag] = blocks

    def depth(name):
        return len(tr.dec.ancestors(name))

    load_pos = {uid: i for i, uid in enumerate(clf.load.dec_nodes)}
    order = sorted(emitted_dec, key=lambda n: (depth(n), clf.items[emitted_dec[n].uids[0]]["file"],
                                              clf.items[emitted_dec[n].uids[0]]["line"]))
    for name in order:
        group = emitted_dec[name]
        first = clf.items[group.uids[0]]
        top = tr.dec.top_name(name)
        key = "%s%s" % (meta.PREFIX, meta.slug(top))
        top_item = clf.items[tr.dec.groups[top].uids[0]]
        integ = _new_integration(pkg, key, "custom", _custom_category(tr, top), None,
                                 "Migrated from the Wazuh 4.x decoder %s (%s:%d) and the rules over it." % (
                                     top, top_item["file"], top_item["line"]), date)
        integ["source_name"] = top
        if key not in pkg.load_rank:
            pkg.load_rank[key] = load_pos[tr.dec.groups[top].uids[0]]
        dname = decoder_name(name)
        lid = meta.local_id("decoder", dname)
        refs = ["Migrated from Wazuh 4.x decoder %s (%s)" % (name, first["file"])]
        resource = {
            "name": dname,
            "enabled": True,
            "metadata": meta.metadata(dname.split("/")[1], lid,
                                      "Migrated from Wazuh 4.x decoder %s (%s:%d)." % (name, first["file"], first["line"]),
                                      refs, date),
            "parents": [group.resource["parent"]],
        }
        if group.resource["checks"]:
            resource["check"] = " AND ".join(group.resource["checks"])
        normalize = list(group.resource["normalize"])
        for tag in sorted(labels.get(name, {})):
            normalize.extend(labels[name][tag])
        if normalize:
            resource["normalize"] = normalize
        codes = sorted({c for u in group.uids if tr.state(u) == R.AUTO for c in clf.acc[u].codes})
        doc = {
            "local_id": lid,
            "source": {"kind": "decoder", "id": name, "file": first["file"], "line": first["line"]},
            "fidelity": _fidelity(codes),
            "reasons": codes,
            "resource": resource,
        }
        integ["decoders"].append(doc)
        pkg.decoder_count += 1
        if not first["parent"]:
            clf.acc[group.uids[0]].add("RM-P-SECOND-POLICY", "the build adds the wazuh4-base root to the custom policy")

    # ---- feeds ---------------------------------------------------------------
    emitted_feeds = _feeds(tr, pkg, labels, date)

    # ---- base ----------------------------------------------------------------
    if emitted_dec or emitted_feeds:
        base = tr.base
        integ = _new_integration(pkg, BASE_KEY, "base", base["integration"]["category"], None,
                                 "Base of the migrated decoders: the root decoder, recreated from the standard %s "
                                 "integration (%s), and the 4.x pre-decoding of the syslog header."
                                 % (base["integration"]["stock_integration"], snapshot),
                                 date)
        base_docs = []
        for entry in base["decoders"]:
            res = _base_resource(entry["resource"], "decoder", "%s of wazuh-core" % entry["stock_name"], snapshot, date)
            base_docs.append({
                "local_id": res["metadata"]["references"][0].split(":", 1)[1],
                "source": {"kind": "base", "id": entry["stock_name"], "file": BASE_FILE, "line": 1},
                "fidelity": R.EXACT,
                "reasons": [],
                "resource": res,
            })
        used = sorted({clf.items[g.uids[0]]["parent"] for g in emitted_dec.values()
                       if clf.items[g.uids[0]]["parent"] and clf.items[g.uids[0]]["parent"] not in tr.dec.groups
                       and clf.items[g.uids[0]]["parent"] in base.get("stock_parents", {})})
        for pname in used:
            entry = base["stock_parents"][pname]
            res = _base_resource(entry["resource"], "decoder", "4.x decoder %s (%s)" % (pname, entry["origin"]),
                                 base.get("stock_parents_source", ""), date)
            base_docs.append({
                "local_id": res["metadata"]["references"][0].split(":", 1)[1],
                "source": {"kind": "base", "id": pname, "file": BASE_FILE, "line": 1},
                "fidelity": R.EXACT,
                "reasons": [],
                "resource": res,
            })
        if any(f.json for f in emitted_feeds):
            base_docs.append(_json_gate(tr, date))
        integ["decoders"] = base_docs + integ["decoders"]
        for entry in base["kvdbs"]:
            res = _base_resource(entry["resource"], "kvdb", "%s of wazuh-core" % entry["stock_title"], snapshot, date)
            integ["kvdbs"][res["metadata"]["title"]] = {
                "local_id": res["metadata"]["references"][0].split(":", 1)[1],
                "source": {"kind": "base", "id": entry["stock_title"], "file": BASE_FILE, "line": 1},
                "fidelity": R.EXACT,
                "reasons": [],
                "resource": res,
            }
        pkg.root = {"integration": BASE_KEY, "local_id": meta.local_id("decoder", base["root"])}

    # ---- rules, kvdbs ----------------------------------------------------------
    for uid in sorted(tr.rules, key=lambda u: (clf.items[u]["file"], clf.items[u]["line"])):
        if not tr.emitted(uid):
            continue
        r = tr.rules[uid]
        item = clf.items[uid]
        src = r.src
        if src.kind == "stock":
            integ = _new_integration(pkg, src.key, "on-stock",
                                     tr.std_info(src.stock_integration)["category"],
                                     src.stock_integration,
                                     "Rules migrated from Wazuh 4.x over the standard integration %s." % src.stock_integration,
                                     date)
        else:
            integ = pkg.integrations.get(src.key)
            if integ is None:
                continue  # its decoders are not emitted: the propagation keeps it out
        codes = _codes(clf.acc[uid])
        integ["rules"][item["id"]] = {
            "local_id": r.local_id,
            "source": {"kind": "rule", "id": item["id"], "file": item["file"], "line": item["line"]},
            "fidelity": _fidelity(codes),
            "reasons": codes,
            "resource": r.resource,
        }
        for path, title in r.build.kvdbs.items():
            if title in integ["kvdbs"]:
                continue
            content = tr.list_content(path)
            li = tr.list_item(path)
            if content is None:
                pkg.missing_lists.append(path)
                content = {}
            lid = meta.local_id("kvdb", title)
            lcodes = _codes(clf.acc[m.uid(li)]) if li else []
            integ["kvdbs"][title] = {
                "local_id": lid,
                "source": {"kind": "list", "id": path, "file": li["file"] if li else path, "line": 1},
                "fidelity": _fidelity(lcodes),
                "reasons": lcodes,
                "resource": {
                    "metadata": meta.metadata(title, lid, "Migrated from the Wazuh 4.x CDB list %s." % path,
                                              ["Migrated from Wazuh 4.x list %s" % path], date),
                    "content": dict(sorted(content.items())),
                    "enabled": True,
                },
            }

    # ---- monitors and recipes ----------------------------------------------------
    for uid in sorted(clf.items, key=lambda u: (clf.items[u]["file"], clf.items[u]["line"], u)):
        item = clf.items[uid]
        if tr.state(uid) != R.RECIPE:
            continue
        mon, mnotes = None, []
        acc = clf.acc[uid]
        if item["kind"] == m.RULE and "RM-R-FREQUENCY" in acc.codes and "RM-R-CORRELATION" not in acc.codes \
                and any(not d.startswith("from ") for d in acc.codes["RM-R-FREQUENCY"]):
            mon, mnotes = RC.monitor(tr, uid)
            if mon is not None:
                pkg.monitors[item["id"]] = mon
        partial = None
        r = tr.rules.get(uid)
        if r is not None and r.resource is not None:
            partial = r.resource
        name = RC.recipe_name(item)
        if name + ".md" in pkg.recipes:
            name = "%s-%d" % (name, item["line"])
        pkg.recipes[name + ".md"] = RC.render(tr, uid, mon, mnotes, partial)

    # ---- detectors -----------------------------------------------------------------
    for key in pkg.ordered_keys():
        integ = pkg.integrations[key]
        rules = [integ["rules"][rid]["local_id"] for rid in sorted(integ["rules"], key=lambda x: int(x))]
        cat = integ["doc"]["resource"]["category"]
        for n in range(0, len(rules), DETECTOR_MAX_RULES):
            k = n // DETECTOR_MAX_RULES + 1
            fname = "%s.json" % key if k == 1 else "%s-%d.json" % (key, k)
            pkg.detectors[fname] = {"name": "%s-%d" % (key, k), "integration": key, "category": cat,
                                    "index": "wazuh-events-v5-%s" % cat,
                                    "rules": rules[n:n + DETECTOR_MAX_RULES]}

    # ---- engine helper dialect (last step) ------------------------------------------
    pkg.engine_helpers = tr.engine_helpers
    for key in pkg.ordered_keys():
        for doc in pkg.integrations[key]["decoders"]:
            doc["resource"] = H.to_dialect(doc["resource"], tr.engine_helpers)
            bad = H.unavailable(doc["resource"], tr.engine_helpers)
            if bad:  # items were checked before the propagation: only the base can get here
                pkg.helper_problems.append("%s (%s): %s" % (doc["resource"]["name"], key, ", ".join(bad)))

    # ---- mapping ---------------------------------------------------------------------
    for item in sorted(clf.inv["rules"], key=lambda it: (it["file"], it["line"])):
        uid = m.uid(item)
        acc = clf.acc[uid]
        r = tr.rules.get(uid)
        emitted = tr.emitted(uid) and r is not None and r.key in pkg.integrations
        codes = sorted(acc.codes) or ["RM-X-TRANSLATED"]
        pkg.mapping.append({
            "rule_id_4x": item["id"] or "",
            "state": R.state_of(codes),
            "reasons": codes,
            "integration": r.key if r is not None and r.key else "",
            "resource_title": r.resource["metadata"]["title"] if emitted else "",
            "local_id": r.local_id if emitted else "",
            "server_id": "",
        })
    return pkg


FEED_RANK = 10 ** 6  # feed integrations come after every migrated decoder; the one that takes every JSON event, last


def _feed_category(tr, feed):
    for f in feed.roots:
        entry = tr.decisions.get("feeds", {}).get(f["root_id"]) or {}
        if entry.get("category"):
            return entry["category"]
    return "other"


def _feeds(tr, pkg, labels, date):
    """Integrations and decoders of the feeds that have an emitted rule."""
    clf = tr.clf
    out = []
    used = {r.src.feed for u, r in tr.rules.items() if tr.emitted(u) and r.src is not None and r.src.feed}
    for label in sorted(tr.feeds, key=lambda k: (tr.feeds[k].catchall, k)):
        feed = tr.feeds[label]
        if label not in used:
            continue
        if not feed.json and feed.check is None:
            continue  # cannot happen: such a root is DECISION (RM-R-FEED-NO-SELECTOR)
        first = clf.items[feed.roots[0]["root_uid"]]
        ids = ", ".join(f["root_id"] for f in feed.roots[:10]) + (
            " and %d more" % (len(feed.roots) - 10) if len(feed.roots) > 10 else "")
        integ = _new_integration(pkg, feed.key, "custom", _feed_category(tr, feed), None,
                                 "Feed of Wazuh 4.x root rule(s) %s and the rules over them." % ids, date)
        pkg.load_rank[feed.key] = FEED_RANK + (1 if feed.catchall else 0)
        lid = meta.local_id("decoder", feed.dname)
        resource = {
            "name": feed.dname,
            "enabled": True,
            "metadata": meta.metadata(feed.dname.split("/")[1], lid,
                                      "Generated for the Wazuh 4.x feed of root rule(s) %s (%s:%d)." % (
                                          ids, first["file"], first["line"]),
                                      ["Generated for Wazuh 4.x root rule(s) %s (%s)" % (ids, first["file"])], date),
            "parents": [F.JSON_GATE if feed.json else tr.base["predecoder"]],
        }
        if feed.check:
            resource["check"] = feed.check
        normalize = tr.feed_normalize(feed) if feed.json else []
        for tag in sorted(labels.get(label, {})):
            normalize.extend(labels[label][tag])
        if normalize:
            resource["normalize"] = normalize
        codes = ["RM-D-DUAL-DOCUMENT", "RM-R-FEED"]
        if feed.json:
            codes.append("RM-D-FEED-JSON")
        if feed.check and "wazuh.protocol.location" in feed.check:
            codes.append("RM-R-FEED-LOCATION")
        integ["decoders"].append({
            "local_id": lid,
            "source": {"kind": "feed", "id": feed.name, "file": first["file"], "line": first["line"]},
            "fidelity": _fidelity(codes),
            "reasons": sorted(codes),
            "resource": resource,
        })
        pkg.decoder_count += 1
        for f in feed.roots:
            clf.acc[f["root_uid"]].add("RM-P-SECOND-POLICY", "the build adds the wazuh4-base root to the custom policy")
            clf.acc[f["root_uid"]].add("RM-D-DUAL-DOCUMENT", "events of feed %s are indexed by the custom policy too%s" % (
                feed.name, " (every JSON event without a program name)" if feed.takes_every_json else ""))
        out.append(feed)
    return out


def _json_gate(tr, date):
    """The 4.x stock JSON decoder (ruleset/decoders/0006-json_decoders.xml:18), parent of the JSON feeds."""
    snapshot = tr.base.get("stock_parents_source", "")
    resource = {
        "name": F.JSON_GATE,
        "enabled": True,
        "metadata": {
            "description": "Wazuh 4.x stock decoder json recreated as the parent of the migrated JSON feeds: no program "
                           "name, the message starts with {\"; the JSON goes to %s." % F.JSON_VAR,
            "documentation": "",
            "references": [],
            "supports": [],
            "title": "wazuh4-json",
        },
        "parents": [tr.base["predecoder"]],
        # the 4.x prematch ^{\s*" read as OS_Regex (\s is a space there, not any white space)
        "check": "not_exists($process.name) AND regex_match($message, %s)" % helper_quote(
            to_re2("osregex", JSON_GATE_PREMATCH).pattern()),
        "normalize": [{"map": [{F.JSON_VAR: "parse_json($message)"}]}],
    }
    res = _base_resource(resource, "decoder", "4.x decoder json (ruleset/decoders/0006-json_decoders.xml:18)",
                         snapshot, date)
    return {
        "local_id": res["metadata"]["references"][0].split(":", 1)[1],
        "source": {"kind": "base", "id": "json", "file": BASE_FILE, "line": 1},
        "fidelity": R.EXACT,
        "reasons": [],
        "resource": res,
    }


def _base_resource(resource, kind, stock_name, snapshot, date):
    import copy
    res = copy.deepcopy(resource)
    title = res["metadata"]["title"] if kind == "kvdb" else res["name"]
    lid = meta.local_id(kind, title)
    old_refs = [r for r in res["metadata"].get("references", []) if r]
    res["metadata"]["author"] = meta.MARKER_AUTHOR
    res["metadata"]["references"] = meta.marker_references(
        lid, ["Recreated from the standard %s (%s)" % (stock_name, snapshot)] + old_refs)
    if date:
        res["metadata"]["date"] = date
    return res
