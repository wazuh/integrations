"""Classify the CDB lists before migrating them.

Classes: ``stock`` (a stock 4.14 list: not migrated, as before), ``ioc`` (threat intelligence: the 5.x IoC feeds of
the ``wazuh-ioc`` integration cover that kind of indicator), ``business`` (allowlists, users, assets: a KVDB, as
before). Deterministic, in this order:

1. stock content (``RM-L-STOCK``);
2. usage in the rules: a positive lookup on an IP, domain, URL or hash field in an alerting rule is IoC use; a
   negated lookup, a level 0 rule, or a user, host or asset field is business use;
3. content shape: at least 90 % of the keys are IPs, prefixes, domains, URLs or hashes;
4. name hint (``malicious``, ``ioc``, ``allow``, ``known`` ...), only to break a tie;
5. anything else is ``business`` with a report line (``unsure``).

The class never changes the translation by itself: an IoC list is still migrated to a KVDB until
``decisions.json`` (``lists``) says ``"action": "ioc-feed"``. Customers cannot add entries to the 5.x IoC feeds
(``virustotal-migration.md``), and the entries of the list that no feed has cannot be checked offline.

Sources: the research note (feed types and the ``wazuh-ioc`` rules on
``wazuh.threat.enrichments.indicator.type``), ``cdb-to-kvdb-migration.md`` and ``virustotal-migration.md``.
"""

import ipaddress
import re

from ..parse.lists import split_entry

IOC_FIELD = "wazuh.threat.enrichments.indicator.type"
SHAPE_IOC_SHARE = 0.9
STOCK_IOC = ("etc/lists/malicious-ioc/malicious-ip", "etc/lists/malicious-ioc/malicious-domains",
             "etc/lists/malicious-ioc/malware-hashes")
STOCK_IOC_TYPES = {"etc/lists/malicious-ioc/malicious-ip": ["connection"],
                   "etc/lists/malicious-ioc/malicious-domains": ["url_domain"],
                   "etc/lists/malicious-ioc/malware-hashes": ["hash_md5", "hash_sha1", "hash_sha256"]}
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)([A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,63}\.?$")
_IOC_NAME = re.compile(r"(ioc|malicious|malware|blocklist|block-list|blacklist|black-list|threat|^ti[-_]|[-_]ti[-_]|"
                       r"tor[-_]|c2|feodo|botnet|abuse|phish|mining|bad[-_]?ip|spam|ransom)", re.I)
_BUSINESS_NAME = re.compile(r"(allow|white|trusted|known|private|rfc[-_]?1918|internal|corporate|users?$|accounts?|"
                            r"hosts?$|hostnames?|assets?|ports?$|vendors?|employees?|admins?|service|exclu|exception|"
                            r"cities|countries|aps$|macs$)", re.I)
_IP_FIELD = re.compile(r"^(src|dst|source|destination|client|server|remote|local|target)?_?ip$|ipaddress|ip_?addr|"
                       r"^(source|destination|client|server|remote)_?address$", re.I)
_URL_FIELD = re.compile(r"(url|uri|domain|query|fqdn|referr?er)", re.I)
_AD_DOMAIN_FIELD = re.compile(r"(domainname$|^(subject|target|user|account|logon|caller|client)_?domain$)", re.I)
_HASH_FIELD = re.compile(r"(md5|sha1|sha256|hash)", re.I)
_BUSINESS_FIELD = re.compile(r"(user|account|logon|host|computer|workstation|machine|asset|port|process|image|"
                             r"command|path|file|group|city|country|mac|ssid|channel|name$)", re.I)


def key_kind(key):
    k = key.strip().strip('"')
    if not k:
        return "other"
    if k.endswith(".") and k[:-1].replace(".", "").isdigit():
        return "prefix"
    if "/" in k and "://" not in k:
        try:
            ipaddress.ip_network(k, strict=False)
            return "cidr"
        except ValueError:
            pass
    try:
        ipaddress.ip_address(k)
        return "ip"
    except ValueError:
        pass
    host, sep, port = k.rpartition(":")
    if sep and port.isdigit():
        try:
            ipaddress.ip_address(host.strip("[]"))
            return "ip_port"
        except ValueError:
            pass
    if _HEX.match(k) and len(k) in (32, 40, 64):
        return {32: "md5", 40: "sha1", 64: "sha256"}[len(k)]
    if "://" in k:
        return "url"
    if _DOMAIN.match(k):
        return "domain"
    return "other"


def list_shape(data):
    """Counts of key kinds of a CDB list (``key_kind``) over every entry."""
    text = data.replace(b"\r\n", b"\n").decode("utf-8", "replace")
    out = {}
    for line in text.split("\n"):
        kv = split_entry(line)
        if kv is None:
            continue
        kind = key_kind(kv[0])
        out[kind] = out.get(kind, 0) + 1
    return dict(sorted(out.items()))


FEED_OF_KIND = {"ip": "connection", "prefix": "connection", "cidr": "connection", "ip_port": "connection",
                "domain": "url_domain", "url": "url_full", "md5": "hash_md5", "sha1": "hash_sha1",
                "sha256": "hash_sha256"}


def _field_kind(field):
    """Kind of a 4.x field name, from its last component (``win.eventdata.targetUserName`` -> targetUserName)."""
    full = (field or "").strip()
    if not full:
        return None
    f = full.rsplit(".", 1)[-1]
    if _HASH_FIELD.search(f):
        return "hash"
    if _IP_FIELD.search(f):
        return "ip"
    if _AD_DOMAIN_FIELD.search(f):
        return "business"  # Windows logon domain (targetDomainName), not a DNS domain
    if _URL_FIELD.search(f):
        return "url"
    if _BUSINESS_FIELD.search(f):
        return "business"
    return None


def _use_verdict(use):
    """('ioc' | 'business' | None, why) of one <list> use."""
    if use["lookup"].startswith("not_"):
        return "business", "negated lookup %s" % use["lookup"]
    if not use["level"]:
        return "business", "level 0 rule %s" % use["rule"]
    fk = _field_kind(use["field"])
    if fk in ("ip", "url", "hash"):
        return "ioc", "rule %s alerts (level %d) on a match of %s" % (use["rule"], use["level"], use["field"])
    if fk == "business":
        return "business", "rule %s looks up %s" % (use["rule"], use["field"])
    return None, None


def _name_hint(name):
    base = name.rsplit("/", 1)[-1]
    ioc = bool(_IOC_NAME.search(base))
    bus = bool(_BUSINESS_NAME.search(base))
    if ioc and not bus:
        return "ioc"
    if bus and not ioc:
        return "business"
    return None


def _feed_types(shape, uses):
    types = []
    for kind, n in sorted(shape.items(), key=lambda kv: (-kv[1], kv[0])):
        t = FEED_OF_KIND.get(kind)
        if t and t not in types:
            types.append(t)
    if not types:
        for u in uses:
            fk = _field_kind(u["field"])
            t = {"ip": "connection", "url": "url_domain", "hash": "hash_sha256"}.get(fk)
            if t and t not in types:
                types.append(t)
    return types


def classify_one(li, uses, stock):
    """``{"class", "why", "unsure", "feed_types", "warnings", "shape"}`` for one list item."""
    shape = li.get("shape") or {}
    entries = sum(shape.values()) or li.get("entries", 0)
    res = {"class": None, "why": [], "unsure": None, "feed_types": [], "warnings": [], "shape": shape,
           "entries": li.get("entries", 0)}
    if stock:
        res["class"] = "stock"
        res["why"].append(stock)
        return res
    verdicts = [v for v in (_use_verdict(u) for u in uses) if v[0]]
    usage = None
    if verdicts:
        kinds = {v[0] for v in verdicts}
        usage = kinds.pop() if len(kinds) == 1 else "mixed"
        res["why"].extend(v[1] for v in verdicts[:3])
    ioc_keys = sum(n for k, n in shape.items() if k in FEED_OF_KIND)
    shape_v = "ioc" if entries and ioc_keys >= SHAPE_IOC_SHARE * entries else None
    if shape_v:
        res["why"].append("%d of %d keys are IPs, domains, URLs or hashes" % (ioc_keys, entries))
    name = _name_hint(li["name"])
    if name:
        res["why"].append("name hint: %s" % name)
    if usage == "mixed":
        res["unsure"] = "the rules use it both as threat intelligence and as an allowlist"
    elif usage in ("ioc", "business"):
        if name and name != usage:
            res["unsure"] = "usage says %s, the name says %s" % (usage, name)
        else:
            res["class"] = usage
    elif shape_v == "ioc":
        if name == "business":
            res["unsure"] = "indicator-shaped keys, but the name says business"
        elif name == "ioc":
            res["class"] = "ioc"
        else:
            res["unsure"] = "indicator-shaped keys and no use or name that tells IoC from allowlist"
    else:
        res["unsure"] = "no use, shape or name decides" + (" (name hint %s only)" % name if name else "")
    if res["class"] is None:
        res["class"] = "business"
    if res["class"] == "ioc":
        res["feed_types"] = _feed_types(shape, uses)
        if shape.get("ip") or shape.get("prefix") or shape.get("cidr"):
            res["warnings"].append("4.x keys are IP addresses; 5.x connection indicators are ip:port, so a feed "
                                   "match depends on the port")
        if shape.get("prefix") or shape.get("cidr"):
            res["warnings"].append("%d network prefix or CIDR key(s): the feeds have no ranges; keep them in a KVDB "
                                   "(in_cidr)" % (shape.get("prefix", 0) + shape.get("cidr", 0)))
        if shape.get("other"):
            res["warnings"].append("%d key(s) are not indicators of a feed type" % shape["other"])
    return res


def uses_by_list(clf):
    """list path -> [{rule, level, field, lookup, line}] in rule load order."""
    out = {}
    for it in clf.inv["rules"]:
        for li in it.get("lists", []):
            out.setdefault(li["path"], []).append({"rule": it["id"], "level": it.get("level") or 0,
                                                   "field": li["field"], "lookup": li["lookup"],
                                                   "file": it["file"], "line": li["line"]})
    return out


def refresh_evidence(inv, name):
    """Blocks of ossec.conf whose command writes or names the list file (a script that refreshes it)."""
    base = name.rsplit("/", 1)[-1]
    out = []
    for conf in inv.get("conf_files", []):
        for b in conf["blocks"]:
            if b["kind"] not in ("wodle", "command", "localfile"):
                continue
            if b["kind"] == "wodle" and (b["attrs"].get("name") or "").lower() != "command":
                continue
            texts = [t for tag, t, _a in b["elements"] if tag.lower() in ("command", "executable", "extra_args")]
            hit = [t for t in texts if name in t or (len(base) >= 4 and re.search(r"(^|[/\s'\"])%s($|[\s'\";])"
                                                                                   % re.escape(base), t))]
            if hit:
                out.append({"file": conf["file"], "line": b["line"], "kind": b["kind"], "command": hit[0]})
    return out


def classify_lists(clf):
    """Class of every list item, and of the stock IoC lists the rules reference. Keyed by list name."""
    uses = uses_by_list(clf)
    out = {}
    for li in clf.inv["lists"]:
        codes = clf.acc[_uid(li)].codes
        stock = "; ".join(codes["RM-L-STOCK"]) if "RM-L-STOCK" in codes else None
        res = classify_one(li, uses.get(li["name"], []), stock)
        if stock and li["name"] in STOCK_IOC_TYPES:
            res["feed_types"] = list(STOCK_IOC_TYPES[li["name"]])
        res["file"] = li["file"]
        res["uses"] = uses.get(li["name"], [])
        res["refresh"] = refresh_evidence(clf.inv, li["name"])
        out[li["name"]] = res
    for path in sorted(uses):
        if path in out or path not in STOCK_IOC_TYPES:
            continue
        out[path] = {"class": "stock", "why": ["stock 4.14 IoC list"], "unsure": None,
                     "feed_types": list(STOCK_IOC_TYPES[path]), "warnings": [], "shape": {}, "entries": 0,
                     "file": path, "uses": uses[path], "refresh": refresh_evidence(clf.inv, path)}
    return dict(sorted(out.items()))


def _uid(li):
    from .. import model4 as m
    return m.uid(li)


def wanted_entry(name, res):
    """The decisions.json entry (section ``lists``) of an IoC list: a question with a default."""
    return {"class": res["class"], "action": None, "default_action": "kvdb", "feed_types": res["feed_types"],
            "used_by": ["rule:%s" % u["rule"] for u in res["uses"]], "seen_in": "%s:1" % res["file"]}


def kvdb_update_step(name, kvdb_title, integration):
    return ("A script refreshes %s in 4.x. 5.x does not read etc/lists: change the script to update the KVDB %s "
            "of integration %s in the draft space of the Content Manager and promote it to test and custom, as "
            "rmig apply does (cdb-to-kvdb-migration.md)." % (name, kvdb_title, integration))
