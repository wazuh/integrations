# Cisco FTD Access-List Deny Decoders - Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Decoder Placement Constraint](#decoder-placement-constraint)
    * [Installing the Decoders (Drop-In Replacement)](#installing-the-decoders-drop-in-replacement)
    * [Alternative: Merge Only the Added Blocks](#alternative-merge-only-the-added-blocks)
* [Rules](#rules)

### Introduction

This integration extends the stock Wazuh Cisco FTD decoders so that access-list
deny events (message **106023**) with the standard `%FTD-` prefix decode fully.
Blocked and denied firewall traffic otherwise decodes inconsistently, so some
fields are missing or truncated on the resulting alerts.

Two related gaps cause this: interface names containing hyphens (`LAN-INT`,
`DMZ-INT`) that a `\w+` pattern cannot match, and ICMP denies that carry no port
and so do not fit a port-bearing pattern.

**This integration ships decoders only.** The stock Cisco FTD rules already
alert on these messages; the improved decoding simply gives those alerts
complete, correctly-separated fields (`cisco.access_group`, `cisco.icmp_type`,
hyphenated interfaces, ports). See [Rules](#rules).

> The `%FTD-session-` prefix variant is handled by the separate
> **cisco_ftd_session** integration. Switch and router authentication is handled
> by **cisco_ios**.

### Prerequisites

- A Wazuh manager receiving syslog from Cisco FTD appliances, over `<remote>`
  syslog or a log collector on an agent.
- Sufficient privileges on the manager to edit files under `/var/ossec/`.
- No third-party software or Python dependencies. This integration is decoder
  XML only. Installing it as a drop-in replacement under `etc/decoders/` (the
  recommended path below) is upgrade-safe.

### Installation and Configuration

#### Decoder Placement Constraint

**Wazuh commits the first child decoder whose `<prematch>` matches, even when
its `<regex>` then fails to extract anything.** A child placed after a matching
sibling never runs, and the stock `cisco-ftd` parent has generic children, some
without a `<prematch>`, that would otherwise claim 106023 events first.

In the file shipped here this is **already handled**: `cisco-ftd-acl-deny` and
`cisco-ftd-acl-deny-icmp` sit immediately after the parent, above every generic
child. You only need to preserve that ordering yourself if you hand-merge the
blocks (see the alternative below).

#### Installing the Decoders (Drop-In Replacement)

`ruleset/decoders/cisco_ftd_decoders.xml` is a **complete replacement** for the
stock Cisco FTD decoder file: the stock decoder set with the two deny decoders
already merged in at the correct position. Because it keeps the stock decoder
names, the stock Cisco FTD rules keep working against it.

Confirm the stock decoder filename on your release first (it carries a numeric
prefix), together with the stock rules file that depends on it:

```bash
ls /var/ossec/ruleset/decoders/ | grep -i cisco-ftd   # e.g. 0062-cisco-ftd_decoders.xml
ls /var/ossec/ruleset/rules/    | grep -i cisco-ftd   # e.g. 0905-cisco-ftd_rules.xml
```

**Order matters.** You cannot just add the replacement alongside the stock
decoder: both define the same parent (`cisco-ftd`), so with the stock file still
present that parent name is duplicated and the manager errors out. A stock
decoder also cannot be excluded while the stock rules that depend on it are
still loaded. So the sequence is: **exclude the stock decoder and its rules
first, then add the replacement decoder, then re-include the rules.**

**From the Wazuh dashboard** (recommended for Wazuh Cloud and other managed or
as-is deployments):

1. **Exclude the stock decoder and its rules.** Server Management -> Settings ->
   Edit configuration; in the `<ruleset>` block add both exclusions, then save
   and restart the manager:

   ```xml
   <ruleset>
     <!-- Default ruleset -->
     <decoder_dir>ruleset/decoders</decoder_dir>
     <rule_dir>ruleset/rules</rule_dir>
     <decoder_exclude>ruleset/decoders/0062-cisco-ftd_decoders.xml</decoder_exclude>
     <rule_exclude>ruleset/rules/0905-cisco-ftd_rules.xml</rule_exclude>
     ...
     <!-- User-defined ruleset -->
     <decoder_dir>etc/decoders</decoder_dir>
     <rule_dir>etc/rules</rule_dir>
   </ruleset>
   ```

2. **Add the replacement decoder.** Server Management -> Decoders -> Manage
   decoders files -> Add new decoders file. Name it `cisco_ftd_decoders.xml`,
   paste the contents of this integration's decoder file, and save (stored under
   `etc/decoders/`). Restart the manager. With the stock decoder excluded there
   is no duplicate `cisco-ftd` parent.
3. **Re-include the rules.** Back in Settings, remove the `<rule_exclude>` line
   so the stock FTD rules load again - this time against your replacement
   decoder - keeping the `<decoder_exclude>`. Save and restart.

**From the backend (CLI):** the same three phases, editing
`/var/ossec/etc/ossec.conf` and the filesystem directly:

1. Add both `<decoder_exclude>` and `<rule_exclude>` to the `<ruleset>` block,
   then restart.
2. Copy the replacement decoder in, then restart:

   ```bash
   cp ruleset/decoders/cisco_ftd_decoders.xml /var/ossec/etc/decoders/
   chown wazuh:wazuh /var/ossec/etc/decoders/cisco_ftd_decoders.xml
   chmod 660 /var/ossec/etc/decoders/cisco_ftd_decoders.xml
   ```
3. Remove the `<rule_exclude>` (keep the `<decoder_exclude>`), then restart:

   ```bash
   systemctl restart wazuh-manager
   # or: /var/ossec/bin/wazuh-control restart
   ```

Trade-off: your copy no longer receives upstream decoder improvements or new
message support. Review it against the stock file after each upgrade, and
re-merge if Wazuh adds FTD decoders you want.

#### Alternative: Merge Only the Added Blocks

If you prefer to leave the stock file managed by Wazuh, copy just the two
`cisco-ftd-acl-deny` / `cisco-ftd-acl-deny-icmp` blocks out of the shipped file
and paste them into `/var/ossec/ruleset/decoders/0062-cisco-ftd_decoders.xml`,
immediately after the `cisco-ftd` parent and **above** any generic child. Back
the stock file up first, then restart the manager. This edits the stock file in
place, so no exclusion is needed - but a manager upgrade replaces files under
`/var/ossec/ruleset/`, so the merge must be re-applied afterwards.

```bash
cp /var/ossec/ruleset/decoders/0062-cisco-ftd_decoders.xml{,.bak}
```

### Rules

**This integration ships no rules.** The stock Wazuh Cisco FTD ruleset
(`0905-cisco-ftd_rules.xml`) already alerts on `%FTD-` messages, including
106023 denies, keyed on the `cisco-ftd` decoder. The decoders here do not change
which alerts fire; they only ensure the fields on those alerts
(`cisco.access_group`, `cisco.icmp_type`/`cisco.icmp_code`, hyphenated
interfaces, separated ports) are complete and correct.

Nothing extra to install: once the decoder is in place and the manager
restarted, the existing FTD rules pick up the improved fields automatically.
