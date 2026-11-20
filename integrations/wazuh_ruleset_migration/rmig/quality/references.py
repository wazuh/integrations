"""The alerting blocks of ``ossec.conf`` (read only) and what replaces them in 5.x.

Every ``<active-response>``, ``<integration>``, ``<email_alerts>``, ``<alerts>``, ``<reports>``, ``<global>`` and
``<localfile>`` block becomes one reference: the 4.x block, the 5.x mechanism, the monitor query (rule ids rewritten
with the mapping of the build, levels as 5.x level keywords, groups as the tag ``wazuh4.group.<group>`` of the migrated rules) and a manual checklist. What
has no 5.x equivalent is flagged. 5.x has no import API for channels or monitors: nothing is created.

Sources: the migration guides of wazuh/wazuh ``docs/guide/migration/`` (see GUIDES) and, for the active response
filter, ``wazuh@4.14:src/analysisd/rules_match.c`` (``Rule_AddAR``).
"""

from ..parse.ossec_conf import MASK, SECRET_TAG
from ..textsafe import md, plain
from ..translate.meta import COMPLIANCE_PREFIXES, group_tag, level_keyword

GUIDE_BASE = "https://github.com/wazuh/wazuh/blob/main/docs/guide/migration/"
GUIDES = {
    "active-response": "active-response.md",
    "integration": "integratord-notifications.md",
    "virustotal": "virustotal-migration.md",
    "email": "mail-forwarding-reporting.md",
    "manager": "manager-configuration-migration.md",
    "rules": "rules-4x-to-5x.md",
    "cdb": "cdb-to-kvdb-migration.md",
    "agent-groups": "agent-groups-migration.md",
    "syslog-output": "remote-syslog-output.md",
    "syslog-input": "syslog-input-4x-to-5x.md",
    "sca": "sca-policies-4x-to-5x.md",
    "openscap": "ciscat-openscap-to-sca.md",
    "osquery": "osquery-to-it-hygiene.md",
    "agentless": "agentless-4x-to-5x.md",
    "vulnerability": "vulnerability-detection-cti-feeds.md",
}

FINDINGS_INDEX = "wazuh-findings-v5-*"  # as the frequency monitors (translate/recipes.py)
BANDS = ("informational", "low", "medium", "high", "critical")
BAND_EDGES = (1, 4, 7, 10, 14)
# active-response.md "Default scripts": folded into block-ip; restart-wazuh moves to the Control Module
AR_BLOCK_IP = ("firewall-drop", "firewalld-drop", "pf", "npf", "ipfw", "netsh", "route-null", "host-deny",
               "route-null.exe", "netsh.exe")
AR_CONTROL = ("restart-wazuh", "restart-wazuh.exe", "restart.sh", "restart.cmd")
GLOBAL_EMAIL = ("email_notification", "smtp_server", "email_from", "email_to", "email_maxperhour",
                "email_log_source", "email_idsname", "email_reply_to")


def guide(key):
    return GUIDE_BASE + GUIDES[key]


def levels_from(n):
    """5.x level keywords that cover 4.x ``level >= n``, and whether the set is wider than 4.x."""
    first = BANDS.index(level_keyword(n))
    return list(BANDS[first:]), n not in BAND_EDGES


def _get(block, tag):
    for t, text, _a in block["elements"]:
        if t.lower() == tag:
            return text
    return None


def _all(block, tag):
    return [text for t, text, _a in block["elements"] if t.lower() == tag]


def _ids(text):
    return [x.strip() for x in (text or "").replace(" ", "").split(",") if x.strip()]


def _groups(text):
    out = []
    for part in (text or "").replace("|", ",").split(","):
        part = part.strip().strip("^$")
        if part and part not in out:
            out.append(part)
    return out


def block_xml(block):
    """The 4.x block as XML, secrets masked."""
    name = block["attrs"].get("name")
    head = "<%s%s>" % (block["kind"], ' name="%s"' % name if name else "")
    lines = [head]
    for tag, text, attrs in block["elements"]:
        value = MASK if SECRET_TAG.match(tag.rsplit(".", 1)[-1]) and text else text
        at = "".join(' %s="%s"' % (k, v) for k, v in sorted(attrs.items()))
        lines.append("  <%s%s>%s</%s>" % (tag, at, value, tag))
    lines.append("</%s>" % block["kind"])
    return "\n".join(lines)


class RuleIndex:
    """4.x rule id -> what the migration made of it."""

    def __init__(self, mapping, monitors, stock, winpack, items):
        self.rows = {}
        for row in mapping:
            rid = row["rule_id_4x"]
            cur = self.rows.get(rid)
            if cur is None or (not cur["resource_title"] and row["resource_title"]) or \
                    (cur["state"] == "NOT_APPLICABLE" and row["state"] != "NOT_APPLICABLE" and not cur["resource_title"]):
                self.rows[rid] = row
        self.monitors = set(monitors)
        self.stock = stock
        self.winpack = winpack
        self.groups = {}  # group -> {integration keys of emitted custom rules}
        for row in mapping:
            if not row["resource_title"]:
                continue
            for it in items.get(row["rule_id_4x"], []):
                for g in it.get("groups", []):
                    self.groups.setdefault(g.strip(), set()).add(row["integration"])

    def resolve(self, rid):
        row = self.rows.get(rid)
        if row is not None and rid in self.monitors:
            return {"id": rid, "kind": "monitor", "monitor": "monitors/%s.json" % rid,
                    "text": "frequency rule: its monitor monitors/%s.json raises the alert, not a finding" % rid,
                    "flag": "points at a monitor: add the action to the trigger of monitors/%s.json" % rid}
        if row is not None and row["resource_title"]:
            title = row["resource_title"]
            ref = {"id": rid, "kind": "custom", "title": title, "integration": row["integration"],
                   "tag": "wazuh4.rule.%s" % rid, "local_id": row["local_id"]}
            if "{{" in title:
                ref["flag"] = "the 5.x title has a placeholder: match the tag wazuh4.rule.%s, not the title" % rid
            return ref
        if row is not None:
            return {"id": rid, "kind": "not-migrated", "state": row["state"],
                    "flag": "custom rule %s is %s: no 5.x rule yet (see its item in the report)" % (rid, row["state"])}
        if rid in self.stock.rules_by_id:
            e = self.stock.rules_by_id[rid][0]
            ref = {"id": rid, "kind": "stock", "stock_location": "ruleset/rules/%s:%d" % (e["file"], e["line"]),
                   "flag": "stock rule %s: 5.x ships its own rules; find the 5.x rule that detects the same and match "
                           "its wazuh.rule.title" % rid}
            if self.winpack.knows("rule:%s" % rid):
                ref["windows"] = [dict(a) if isinstance(a, dict) else a for a in self.winpack.alternatives("rule:%s" % rid)][:5]
                ref["flag"] += " (Windows pack: integration windows; the conditions of the 4.x rule are listed)"
            return ref
        return {"id": rid, "kind": "unknown", "flag": "rule %s is neither custom nor stock 4.14 content" % rid}


def _query_parts(idx, rule_ids, level, groups, flags):
    """(should clauses for the rule ids, level clause, group clause) as OpenSearch query filters."""
    refs = [idx.resolve(r) for r in rule_ids]
    id_clauses = []
    for ref in refs:
        if ref["kind"] == "custom":
            id_clauses.append({"term": {"tags": ref["tag"]}})
        if ref.get("flag"):
            flags.append(ref["flag"])
    level_clause = None
    if level:
        try:
            n = int(level)
        except ValueError:
            flags.append("level %r is not a number" % level)
            n = None
        if n:
            kws, wider = levels_from(n)
            level_clause = {"terms": {"wazuh.rule.level": kws}}
            if wider:
                flags.append("level %d is inside the %s band: 5.x keyword %s also takes 4.x levels %d-%d" % (
                    n, kws[0], kws[0], BAND_EDGES[BANDS.index(kws[0])], n - 1))
    group_clause = None
    gref = []
    if groups:
        tags = []
        for g in groups:
            found = idx.groups.get(g)
            stock_n = sum(1 for r in idx.stock.rules if g in [x.strip() for x in r.get("groups", [])])
            gref.append({"group": g, "integrations": sorted(found or []), "stock_rules": stock_n})
            if found and any(g.startswith(prefix) for prefix, _k in COMPLIANCE_PREFIXES):
                flags.append("group %s is a compliance group: migrated rules carry it in compliance, not as a tag; "
                             "the query leaves it out" % g)
            elif found:
                tags.append(group_tag(g))
            if stock_n:
                flags.append("group %s has %d stock 4.x rule(s): 5.x stock rules do not carry 4.x groups; add their "
                             "wazuh.integration.name or wazuh.rule.title by hand" % (g, stock_n))
            if not found and not stock_n:
                flags.append("group %s: no migrated or stock rule carries it" % g)
        if tags:
            # the tag of the migrated rules (rmig.translate.meta.groups_to_tags), not wazuh.integration.name:
            # the integration also holds rules without the group
            group_clause = {"terms": {"tags": tags}}
        flags.append("4.x read the group as a pattern on the group string; the tool matched whole group names")
    return refs, id_clauses, level_clause, group_clause, gref


def _and_query(block, flags, ids, lvl, grp, id_tag, group_elem):
    """Query of a block whose filters must all hold. When a filter that is set has no 5.x form, no query: the
    other filters alone would match more than 4.x."""
    missing = []
    if _get(block, id_tag) and not ids:
        missing.append(id_tag)
    if _get(block, group_elem) and grp is None:
        missing.append(group_elem)
    if _get(block, "level") and lvl is None:
        missing.append("level")
    if missing:
        flags.append("no monitor query: %s has no 5.x form, and the other filters alone would match more than 4.x; "
                     "write the query by hand" % ", ".join(missing))
        return None
    must = [c for c in (lvl, grp) if c]
    return _bool(should=ids or None, must=must or None) if (ids or must) else None


def _bool(should=None, must=None):
    q = {}
    if must:
        q["filter"] = must
    if should:
        q["should"] = should
        q["minimum_should_match"] = 1
    return {"bool": q}


def _ar(block, idx, commands):
    flags, checklist = [], []
    cmd_name = _get(block, "command")
    cmd = commands.get(cmd_name)
    executable = _get(cmd, "executable") if cmd else None
    refs, ids, lvl, grp, gref = _query_parts(idx, _ids(_get(block, "rules_id")), _get(block, "level"),
                                             _groups(_get(block, "rules_group")), flags)
    # Rule_AddAR: level AND group when both are set, else level OR group; rules_id is always OR
    should = list(ids)
    if _get(block, "level") and _get(block, "rules_group"):
        if lvl and grp:
            should.append(_bool(must=[lvl, grp]))
        else:
            flags.append("level AND rules_group: one of them has no 5.x form, so that part of the query is not "
                         "written (the level alone would match more than 4.x)")
    else:
        should += [c for c in (lvl, grp) if c]
        if _get(block, "rules_group") and grp is None:
            flags.append("rules_group has no 5.x form: the query leaves it out")
    query = _bool(should=should) if should else None
    location = (_get(block, "location") or "local").lower()
    if location == "server":
        flags.append("location server: 5.x has no manager-side execution (active-response.md, Location = server)")
    if _get(block, "repeated_offenders"):
        flags.append("repeated_offenders has no 5.x equivalent (active-response.md)")
    if cmd is None:
        flags.append("command %s is not defined in a <command> block" % cmd_name)
    elif executable in AR_BLOCK_IP:
        executable = "block-ip (5.x folds %s into it)" % executable
    elif executable in AR_CONTROL:
        flags.append("%s moves to the Control Module in 5.x: not an active response" % executable)
    else:
        flags.append("custom AR script %s: rewrite it for the 5.x JSON stdin contract (command enable/disable, WCS "
                     "fields)" % executable)
    if cmd is not None and _get(cmd, "timeout_allowed"):
        checklist.append("timeout_allowed has no replacement: reversal comes from Type Stateful + Stateful timeout")
    timeout = _get(block, "timeout")
    checklist[:0] = [
        "Explore > Active Responses: create the channel (name, executable %s%s)" % (
            executable or "?", ", extra arguments %s" % _get(cmd, "extra_args") if cmd and _get(cmd, "extra_args") else ""),
        "Type %s%s" % ("Stateful" if timeout else "Stateless", ", Stateful timeout %ss" % timeout if timeout else ""),
        "Location %s%s" % ({"local": "Local", "defined-agent": "Defined agent", "all": "All"}.get(location, location),
                           ", Agent ID %s" % _get(block, "agent_id") if _get(block, "agent_id") else ""),
        "Alerting: create a monitor of type Active Response on %s with the query below" % FINDINGS_INDEX,
        "Trigger: add the action Add active response, pointing at the channel",
    ]
    if (_get(block, "disabled") or "").lower() == "yes":
        checklist.append("the 4.x block was disabled: create the channel with enabled false")
    return {"mechanism": "Active Response channel + Alerting monitor of type Active Response", "guide": guide("active-response"),
            "combination": "4.x Rule_AddAR: (level AND rules_group) when both are set, else level OR rules_group; "
                           "OR rules_id. No AR for level 0 rules or the no_ar option",
            "rules": refs, "groups": gref, "query": query, "flags": flags, "checklist": checklist,
            "command": {"name": cmd_name, "executable": executable}}


def _integration(block, idx):
    flags, checklist = [], []
    name = (_get(block, "name") or "").strip()
    refs, ids, lvl, grp, gref = _query_parts(idx, _ids(_get(block, "rule_id")), _get(block, "level"),
                                             _groups(_get(block, "group")), flags)
    query = _and_query(block, flags, ids, lvl, grp, "rule_id", "group")
    if _get(block, "event_location"):
        flags.append("event_location has no direct 5.x field: pick wazuh.protocol.location, file.path or "
                     "wazuh.agent.name (integratord-notifications.md)")
    if _get(block, "options"):
        flags.append("options: write them in the trigger action message or the channel (no 5.x field)")
    if _get(block, "alert_format"):
        checklist.append("alert_format has no match: the channel message sets the format")
    low = name.lower()
    if low == "virustotal":
        return {"mechanism": "enrichment, not a notification: see the VirusTotal guide", "guide": guide("virustotal"),
                "combination": "", "rules": refs, "groups": gref, "query": None,
                "flags": ["virustotal is an enrichment in 4.x: 5.x replaces it (virustotal-migration.md)"] + flags,
                "checklist": ["Follow virustotal-migration.md"]}
    kind = {"slack": "Slack", "pagerduty": "PagerDuty", "shuffle": "Shuffle", "jira": "Jira"}.get(low)
    if kind is None:
        flags.append("integration %s is a custom script: use a webhook channel; the script does not run in 5.x" % name)
        kind = "Webhook"
    checklist[:0] = [
        "Notifications: create a %s channel%s" % (kind, " with the webhook URL of hook_url (not copied here)"
                                                  if _get(block, "hook_url") else ""),
        "Alerting: create a monitor on %s with the query below, one query per 4.x filter" % FINDINGS_INDEX,
        "Trigger: add a notification action to the channel",
    ]
    if _get(block, "api_key"):
        checklist.append("api_key: put it in the channel URL or headers (not copied here)")
    return {"mechanism": "Notifications channel (%s) + Alerting monitor" % kind, "guide": guide("integration"),
            "combination": "4.x integratord: every filter set must hold (AND); not verified from source",
            "rules": refs, "groups": gref, "query": query, "flags": flags, "checklist": checklist}


def _email(block, idx):
    flags = []
    refs, ids, lvl, grp, gref = _query_parts(idx, _ids(_get(block, "rule_id")), _get(block, "level"),
                                             _groups(_get(block, "group")), flags)
    query = _and_query(block, flags, ids, lvl, grp, "rule_id", "group")
    if _get(block, "event_location"):
        flags.append("event_location has no direct 5.x field")
    for opt in ("do_not_delay", "do_not_group", "format"):
        if any(t.lower() == opt for t, _x, _a in block["elements"]):
            flags.append("%s has no 5.x equivalent" % opt)
    to = _all(block, "email_to")
    return {"mechanism": "Email sender + recipient group + Notifications channel + Alerting monitor",
            "guide": guide("email"),
            "combination": "4.x maild: every filter set must hold (AND); not verified from source",
            "rules": refs, "groups": gref, "query": query, "flags": flags,
            "checklist": ["Notifications > Email Senders: the SMTP sender of <global> smtp_server/email_from",
                          "Notifications > Email Recipient Groups: %d address(es) of email_to" % len(to),
                          "Notifications: an Email channel with that sender and group",
                          "Alerting: a monitor on %s with the query below and an action to the channel" % FINDINGS_INDEX]}


def _alerts(block, idx):
    flags, checklist = [], []
    for tag, text, _a in block["elements"]:
        if tag.lower() in ("log_alert_level", "email_alert_level"):
            try:
                kws, wider = levels_from(int(text))
            except ValueError:
                continue
            flags.append("%s %s has no 5.x equivalent (<alerts> is removed: startup error in 5.0)" % (tag, text))
            checklist.append("%s %s: in 5.x every rule produces a finding; filter monitors or dashboards on "
                             "wazuh.rule.level in %s%s" % (tag, text, ", ".join(kws),
                                                            " (wider: the band starts below %s)" % text if wider else ""))
        else:
            flags.append("%s has no 5.x equivalent" % tag)
    return {"mechanism": "removed in 5.0; no replacement", "guide": guide("manager"), "combination": "",
            "rules": [], "groups": [], "query": None, "flags": flags,
            "checklist": checklist + ["Remove <alerts> from wazuh-manager.conf (startup error)"]}


def _global(block, idx):
    flags, checklist = [], []
    tags = [t.lower() for t, _x, _a in block["elements"]]
    email = [t for t in tags if t in GLOBAL_EMAIL]
    if email:
        checklist.append("Email options (%s): Notifications > Email Senders and Recipient Groups "
                         "(mail-forwarding-reporting.md)" % ", ".join(sorted(set(email))))
    if "white_list" in tags:
        flags.append("white_list (active response whitelist) is ignored in 5.0: no equivalent")
    other = sorted({t for t in tags if t not in GLOBAL_EMAIL and t not in ("white_list", "agents_disconnection_time")})
    if other:
        flags.append("removed in 5.0, startup error if left: %s" % ", ".join(other))
    if email:
        flags.append("email options are removed in 5.0, startup error if left: %s" % ", ".join(sorted(set(email))))
    checklist.append("Keep only <agents_disconnection_time> in <global> of wazuh-manager.conf")
    return {"mechanism": "only agents_disconnection_time stays; email moves to Notifications",
            "guide": guide("manager"), "combination": "", "rules": [], "groups": [], "query": None,
            "flags": flags, "checklist": checklist}


def _reports(block, idx):
    flags = []
    refs, ids, lvl, grp, gref = _query_parts(idx, _ids(_get(block, "rule")), _get(block, "level"),
                                             _groups(_get(block, "group")), flags)
    query = _and_query(block, flags, ids, lvl, grp, "rule", "group")
    for opt in ("srcip", "user", "location", "type"):
        if _get(block, opt):
            flags.append("filter %s: add it to the saved search of the report by hand" % opt)
    return {"mechanism": "Reporting: report definition on a saved search", "guide": guide("email"),
            "combination": "", "rules": refs, "groups": gref, "query": query, "flags": flags,
            "checklist": ["Discover: a saved search over %s with the query below" % FINDINGS_INDEX,
                          "Reporting > Report Definition: name %s, daily, that saved search" % (_get(block, "title") or "?"),
                          "Notification channel: the email_to address(es)"]}


def _localfiles(blocks):
    """All <localfile> blocks of one file as one reference: they only name the feeds."""
    feeds = [{"location": _get(b, "location") or _get(b, "command") or "?", "log_format": _get(b, "log_format"),
              "line": b["line"]} for b in blocks]
    return {"mechanism": "agent side; a manager <localfile> is ignored in 5.0", "guide": guide("manager"),
            "combination": "", "rules": [], "groups": [], "query": None, "flags": [],
            "checklist": ["Feed %s (%s, line %d): collect it with the agent; its events carry "
                          "wazuh.protocol.location" % (f["location"], f["log_format"] or "?", f["line"]) for f in feeds],
            "feeds": feeds}


HANDLERS = {"active-response": _ar, "integration": _integration, "email_alerts": _email, "alerts": _alerts,
            "global": _global, "reports": _reports}


def analyze(inv, mapping, monitors, stock, winpack):
    """References of every alerting block of the ossec.conf files in the inventory."""
    items = {}
    for it in inv["rules"]:
        items.setdefault(it["id"], []).append(it)
    idx = RuleIndex(mapping, monitors, stock, winpack, items)
    out = []
    for conf in inv.get("conf_files", []):
        commands = {}
        for b in conf["blocks"]:
            if b["kind"] == "command" and _get(b, "name"):
                commands.setdefault(_get(b, "name"), b)
        for b in conf["blocks"]:
            handler = HANDLERS.get(b["kind"])
            if handler is None:
                continue
            if b["kind"] == "active-response":
                ref = handler(b, idx, commands)
            else:
                ref = handler(b, idx)
            if b["kind"] == "global" and not ref["flags"] and len(ref["checklist"]) == 1:
                continue  # a <global> with nothing to say
            label = _get(b, "name") or _get(b, "command") or ""
            ref.update({"n": len(out) + 1, "kind": b["kind"], "file": conf["file"], "line": b["line"],
                        "label": label, "xml": block_xml(b)})
            out.append(ref)
        local = [b for b in conf["blocks"] if b["kind"] == "localfile"]
        if local:
            ref = _localfiles(local)
            ref.update({"n": len(out) + 1, "kind": "localfile", "file": conf["file"], "line": local[0]["line"],
                        "label": "%d feed(s)" % len(local), "xml": "\n".join(block_xml(b) for b in local)})
            out.append(ref)
    return out


def file_name(ref):
    from ..translate.meta import safe_name
    label = safe_name(ref["label"])[:40] if ref["label"] and ref["kind"] != "localfile" else ""
    return "%02d-%s%s" % (ref["n"], ref["kind"], "-" + label if label else "")


def render_md(ref):
    import json
    w = []
    w.append("# %s block (%s:%d)" % (ref["kind"], ref["file"], ref["line"]))
    w.append("")
    w.append("5.x mechanism: %s. Guide: [%s](%s)." % (ref["mechanism"], ref["guide"].rsplit("/", 1)[-1], ref["guide"]))
    w.append("")
    w.append("## 4.x block")
    w.append("")
    fence = "````" if "```" in ref["xml"] else "```"  # a value holding ``` cannot close the block
    w.append(fence + "xml")
    w.append(plain(ref["xml"]))
    w.append(fence)
    w.append("")
    if ref.get("combination"):
        w.append("4.x filter: %s." % ref["combination"])
        w.append("")
    if ref["rules"]:
        w.append("## Rule references")
        w.append("")
        w.append("| 4.x rule | Kind | 5.x |")
        w.append("|---|---|---|")
        for r in ref["rules"]:
            five = r.get("title") and "`%s` (tag `%s`, integration `%s`)" % (r["title"], r["tag"], r["integration"]) \
                or r.get("monitor") and "monitor `%s`" % r["monitor"] or r.get("flag", "")
            w.append("| %s | %s | %s |" % (r["id"], r["kind"], md(five)))
        w.append("")
    if ref.get("groups"):
        w.append("Groups: %s." % "; ".join("%s -> %s (stock 4.x rules: %d)" % (
            g["group"], ", ".join("`%s`" % i for i in g["integrations"]) or "no integration", g["stock_rules"])
            for g in ref["groups"]))
        w.append("")
    if ref.get("query") is not None:
        w.append("## Monitor query (index `%s`)" % FINDINGS_INDEX)
        w.append("")
        w.append("```json")
        w.append(json.dumps({"query": ref["query"]}, sort_keys=True, indent=2))
        w.append("```")
        w.append("")
    if ref["flags"]:
        w.append("## Not mapped")
        w.append("")
        for f in ref["flags"]:
            w.append("- %s" % f)
        w.append("")
    w.append("## Checklist (by hand: 5.x has no import API for channels and monitors)")
    w.append("")
    for c in ref["checklist"]:
        w.append("- [ ] %s" % c)
    w.append("")
    w.append("Not live-verified.")
    return "\n".join(w) + "\n"
