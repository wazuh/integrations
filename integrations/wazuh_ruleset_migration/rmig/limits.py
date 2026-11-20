"""Limits of the 5.0 indexer that the migrated content can exceed.

Content manager (dynamic cluster settings, defaults): at most 200 rules, 200
decoders, 100 integrations and 100 KVDBs in the draft space, counted over the
whole space (what is already there too). Security Analytics: at most 50 rules
per detector and 10 user-created detectors per cluster. A decoder body above
50000 bytes is refused with HTTP 413 ("Request body exceeds maximum allowed
size of 50000 bytes for type 'decoder'", seen live with FortiGate 7 decoders);
no setting is known for it.

``plan`` and ``build`` report the counts (``report.json`` ``build.limits``);
``apply`` stops before any write when the draft space would exceed one.
Every value can be changed with ``--engine-limit NAME=N`` after the cluster
setting is raised.
"""

import json

# name -> (default, cluster setting or None, what is counted, action)
LIMITS = {
    "max_rules": (200, "plugins.content_manager.max_rules", "rules in the draft space"),
    "max_decoders": (200, "plugins.content_manager.max_decoders", "decoders in the draft space"),
    "max_integrations": (100, "plugins.content_manager.max_integrations", "integrations in the draft space"),
    "max_kvdbs": (100, "plugins.content_manager.max_kvdbs", "KVDBs in the draft space"),
    "max_rules_per_detector": (50, "plugins.security_analytics.max_rules_per_detector", "rules in one detector"),
    "max_detectors": (10, "plugins.security_analytics.max_detectors", "user-created detectors in the cluster"),
    "decoder_body_bytes": (50000, None, "bytes in the body of one decoder create"),
}
NAMES = tuple(LIMITS)
DRAFT = ("max_rules", "max_decoders", "max_integrations", "max_kvdbs")
# a server id of the content manager (UUID): the size of the "integration" field of a decoder create
_ID = "0" * 36


class LimitError(ValueError):
    pass


def parse(values):
    """``["max_rules=500", ...]`` -> ``{"max_rules": 500}``."""
    out = {}
    for v in values or []:
        name, sep, n = v.partition("=")
        name = name.strip()
        if not sep or name not in LIMITS:
            raise LimitError("--engine-limit %r: use NAME=N with NAME one of %s" % (v, ", ".join(NAMES)))
        try:
            out[name] = int(n)
        except ValueError:
            raise LimitError("--engine-limit %r: N must be a whole number" % v)
        if out[name] < 1:
            raise LimitError("--engine-limit %r: N must be 1 or more" % v)
    return out


def values(overrides=None):
    vals = {k: LIMITS[k][0] for k in NAMES}
    vals.update(overrides or {})
    return vals


def decoder_body_bytes(resource):
    """Bytes of the body ``apply`` sends to create this decoder: the client's
    serialization (sorted keys, UTF-8) of ``{"integration": <id>, "resource": ...}``."""
    body = {"integration": _ID, "resource": resource}
    return len(json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8"))


def action(name):
    setting = LIMITS[name][1]
    if name == "decoder_body_bytes":
        return "no cluster setting is known for this limit: shorten the decoder or migrate it by hand"
    if name in ("max_rules_per_detector", "max_detectors"):
        return "raise `%s` with PUT _cluster/settings, or activate in parts" % setting
    return "raise `%s` with PUT _cluster/settings, or migrate in parts" % setting


def exceeded(name, value, limit, scope):
    return {"limit": name, "setting": LIMITS[name][1], "value": value, "max": limit, "scope": scope,
            "action": action(name)}


def check(integrations, detectors, overrides=None):
    """``integrations``: ``[(key, rules, decoders, kvdbs, [decoder resources])]`` in order;
    ``detectors``: ``[(name, integration key, rule count)]``. Returns the ``limits`` block."""
    lim = values(overrides)
    rows = []
    over = []
    totals = {"integrations": 0, "rules": 0, "decoders": 0, "kvdbs": 0, "detectors": len(detectors)}
    per_det = {}
    for name, key, n in detectors:
        per_det.setdefault(key, []).append((name, n))
    for key, rules, decoders, kvdbs, resources in integrations:
        sizes = [(decoder_body_bytes(r), r.get("name", "")) for r in resources]
        largest = max(sizes) if sizes else (0, "")
        row = {"key": key, "rules": rules, "decoders": decoders, "kvdbs": kvdbs,
               "detectors": len(per_det.get(key, [])), "largest_decoder_bytes": largest[0],
               "largest_decoder": largest[1], "exceeded": []}
        for name, count in (("max_rules", rules), ("max_decoders", decoders), ("max_kvdbs", kvdbs)):
            if count > lim[name]:
                row["exceeded"].append(exceeded(name, count, lim[name], key))
        for size, dname in sizes:
            if size > lim["decoder_body_bytes"]:
                e = exceeded("decoder_body_bytes", size, lim["decoder_body_bytes"], key)
                e["decoder"] = dname
                row["exceeded"].append(e)
        for dname, n in per_det.get(key, []):
            if n > lim["max_rules_per_detector"]:
                e = exceeded("max_rules_per_detector", n, lim["max_rules_per_detector"], key)
                e["detector"] = dname
                row["exceeded"].append(e)
        rows.append(row)
        # a draft limit exceeded by one integration is exceeded in total too: listed once, below
        over.extend(e for e in row["exceeded"] if e["limit"] not in DRAFT)
        totals["integrations"] += 1
        totals["rules"] += rules
        totals["decoders"] += decoders
        totals["kvdbs"] += kvdbs
    for name, count in (("max_integrations", totals["integrations"]), ("max_rules", totals["rules"]),
                        ("max_decoders", totals["decoders"]), ("max_kvdbs", totals["kvdbs"]),
                        ("max_detectors", totals["detectors"])):
        if count > lim[name]:
            over.append(exceeded(name, count, lim[name], "total"))
    return {"values": lim, "overridden": sorted(overrides or {}), "totals": totals, "integrations": rows,
            "exceeded": over}


def from_package(package, overrides=None):
    integ = []
    for key in package.ordered_keys():
        i = package.integrations[key]
        integ.append((key, len(i["rules"]), len(i["decoders"]), len(i["kvdbs"]),
                      [d["resource"] for d in i["decoders"]]))
    dets = [(d["name"], d["integration"], len(d["rules"])) for _f, d in sorted(package.detectors.items())]
    return check(integ, dets, overrides)


def describe(e):
    """One line for stdout and report.md."""
    what = LIMITS[e["limit"]][2]
    where = "in total" if e["scope"] == "total" else "in %s" % e["scope"]
    if e.get("decoder"):
        where += " (decoder %s)" % e["decoder"]
    if e.get("detector"):
        where += " (detector %s)" % e["detector"]
    return "%d %s %s, limit %d: %s" % (e["value"], what, where, e["max"], e["action"])


def warnings(block):
    """stdout lines for ``plan`` and ``build``."""
    if not block:
        return []
    return ["warning: engine limit: %s" % describe(e) for e in block["exceeded"]]


def markdown(block):
    if not block:
        return []
    out = ["## Engine limits", ""]
    v = block["values"]
    out.append("Limits of the 5.0 indexer (cluster defaults%s): content manager draft space %d rules, %d decoders, "
               "%d integrations, %d KVDBs; Security Analytics %d rules per detector, %d user-created detectors; "
               "%d bytes per decoder body. Draft and detector limits count what is already in the draft space and "
               "the cluster too: `apply` stops before writing if the draft space would exceed one."
               % (", changed with `--engine-limit`: %s" % ", ".join("`%s`" % n for n in block["overridden"])
                  if block["overridden"] else "",
                  v["max_rules"], v["max_decoders"], v["max_integrations"], v["max_kvdbs"],
                  v["max_rules_per_detector"], v["max_detectors"], v["decoder_body_bytes"]))
    out.append("")
    t = block["totals"]
    out.append("This build: %d integration(s), %d rule(s), %d decoder(s), %d KVDB(s), %d detector(s), plus what is "
               "already in the draft space and the cluster." % (
                   t["integrations"], t["rules"], t["decoders"], t["kvdbs"], t["detectors"]))
    out.append("")
    if block["integrations"]:
        out.append("| Integration | Rules | Decoders | KVDBs | Detectors | Largest decoder body (bytes) | Exceeds |")
        out.append("|---|---:|---:|---:|---:|---:|---|")
        for r in block["integrations"]:
            ex = ", ".join(sorted({"`%s`" % e["limit"] for e in r["exceeded"]})) or "-"
            out.append("| `%s` | %d | %d | %d | %d | %d | %s |" % (
                r["key"], r["rules"], r["decoders"], r["kvdbs"], r["detectors"], r["largest_decoder_bytes"], ex))
        out.append("")
    if block["exceeded"]:
        for e in block["exceeded"]:
            out.append("- %s" % describe(e))
    else:
        out.append("No limit is exceeded by this build alone.")
    out.append("")
    return out
