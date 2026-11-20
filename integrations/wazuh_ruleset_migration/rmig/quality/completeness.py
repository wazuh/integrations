"""What the migration does not do, and why, in one place.

Dashboards and saved searches (out of scope), agent groups, ``ossec.conf`` settings outside the ruleset (with the
guide that covers each one), and the monitors and channels to create by hand.
"""

from .references import guide

# top-level ossec.conf section -> (guide key, what to do). Sections the tool reads itself are left out.
SECTIONS = {
    "global": ("manager", "keep only agents_disconnection_time; email options move to Notifications"),
    "alerts": ("manager", "remove: startup error in 5.0; no replacement"),
    "command": ("active-response", "remove: startup error in 5.0; recreate as Active Response channels"),
    "active-response": ("active-response", "recreate as channel + monitor (see ossec.conf references)"),
    "integration": ("integration", "recreate as Notifications channel + monitor (see ossec.conf references)"),
    "email_alerts": ("email", "recreate as email channel + monitor (see ossec.conf references)"),
    "reports": ("email", "recreate as a report definition"),
    "syslog_output": ("syslog-output", "see the guide"),
    "remote": ("manager", "review the options the guide lists; syslog input has its own guide"),
    "auth": ("manager", "review the options the guide lists"),
    "cluster": ("manager", "review the options the guide lists"),
    "indexer": ("manager", "review the options the guide lists"),
    "vulnerability-detection": ("vulnerability", "5.x uses the CTI feeds"),
    "vulnerability-detector": ("vulnerability", "5.x uses the CTI feeds"),
    "sca": ("sca", "see the guide"),
    "wodle": ("manager", "open-scap and cis-cat: SCA guide; osquery: IT hygiene guide; syscollector and command: agent side"),
    "agentless": ("agentless", "see the guide"),
    "localfile": ("manager", "remove from the manager; collect on the agents"),
    "syscheck": ("manager", "agent side in 5.0: remove from the manager"),
    "rootcheck": ("manager", "agent side in 5.0: remove from the manager"),
    "logging": ("manager", "review the options the guide lists"),
    "ruleset": ("rules", "migrated by this tool; remove from wazuh-manager.conf (startup error)"),
}


def analyze(inv, package, refs, mapping):
    sections = {}
    for conf in inv.get("conf_files", []):
        for tag, n in conf["sections"].items():
            sections[tag] = sections.get(tag, 0) + n
    settings = []
    for tag in sorted(sections):
        g, what = SECTIONS.get(tag, ("manager", "not covered by a guide the tool knows: review it by hand"))
        settings.append({"section": tag, "count": sections[tag], "guide": guide(g), "action": what})
    emitted = sorted({r["rule_id_4x"] for r in mapping if r["resource_title"]}, key=lambda x: (len(x), x))
    monitors = []
    for rid in sorted(package.monitors if package is not None else [], key=lambda x: (len(x), x)):
        monitors.append({"what": "frequency rule %s" % rid, "where": "out/monitors/%s.json" % rid})
    for r in refs:
        if r["kind"] in ("active-response", "integration", "email_alerts", "reports"):
            monitors.append({"what": ("%s %s (%s:%d)" % (r["kind"], r["label"], r["file"], r["line"])).replace("  ", " "),
                             "where": "out/references/"})
    return {
        "dashboards": {"custom_rules_with_5x_rule": len(emitted)},
        "agent_groups": list(inv.get("agent_groups", [])),
        "conf_read": bool(inv.get("conf_files")),
        "settings": settings,
        "monitors": monitors,
        "agent_groups_guide": guide("agent-groups"),
    }


def render(c, w, esc):
    w("## Not migrated, and why")
    w("")
    w("| What | Why | What to do |")
    w("|---|---|---|")
    w("| Dashboards, visualizations and saved searches | Out of scope: the tool migrates the ruleset | Rewrite their "
      "queries: 4.x `rule.id` -> tag `wazuh4.rule.<id>` or `wazuh.rule.title` (`out/mapping.csv`, %d custom rule(s) "
      "with a 5.x rule), `rule.level` -> `wazuh.rule.level` keyword, `rule.groups` -> tag `wazuh4.group.<group>`, "
      "`data.*` -> the WCS fields of `decisions.json` (`fields`), index `wazuh-alerts-*` -> `wazuh-findings-v5-*` |"
      % c["dashboards"]["custom_rules_with_5x_rule"])
    if c["agent_groups"]:
        groups = ", ".join("`%s`" % g for g in c["agent_groups"][:20]) + (
            " and %d more" % (len(c["agent_groups"]) - 20) if len(c["agent_groups"]) > 20 else "")
        w("| Agent groups (%d in `etc/shared/`: %s) | Not part of the ruleset | Copy the group folders to the 5.x "
          "manager before the agents enroll ([agent-groups-migration.md](%s)) |" % (
              len(c["agent_groups"]), groups, c["agent_groups_guide"]))
    else:
        w("| Agent groups | Not part of the ruleset; no `etc/shared/` in the source | If the manager has groups, see "
          "[agent-groups-migration.md](%s) |" % c["agent_groups_guide"])
    w("")
    if c["settings"]:
        w("`ossec.conf` settings outside the ruleset (the tool reads them, it does not migrate them):")
        w("")
        w("| Section | Blocks | What to do | Guide |")
        w("|---|---:|---|---|")
        for s in c["settings"]:
            w("| `<%s>` | %d | %s | [%s](%s) |" % (s["section"], s["count"], esc(s["action"]),
                                                  s["guide"].rsplit("/", 1)[-1], s["guide"]))
        w("")
    elif not c["conf_read"]:
        w("No `ossec.conf` in the source: its settings were not read.")
        w("")
    if c["monitors"]:
        w("Monitors to create by hand (5.x has no import API for them):")
        w("")
        for mon in c["monitors"]:
            w("- %s: `%s`" % (esc(mon["what"]), mon["where"]))
        w("")
