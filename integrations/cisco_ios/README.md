# Cisco NX-OS / IOS-XE Authentication Decoders - Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Decoder Placement Constraint](#decoder-placement-constraint)
    * [Installing the Decoders (Drop-In Replacement)](#installing-the-decoders-drop-in-replacement)
    * [Alternative: Merge Only the Added Blocks](#alternative-merge-only-the-added-blocks)
    * [Installing the Rules](#installing-the-rules)

### Introduction

This integration extends the stock Wazuh Cisco IOS decoders to cover **Cisco
NX-OS (Nexus)** and **IOS-XE** authentication and user-administration events.
Login results and account-management events are wrapped in `SYSTEM_MSG` with a
body that differs from the classic IOS formats, so the stock Cisco IOS decoders
do not extract the username, source address or outcome. The result is that
switch authentication activity becomes first-class alerts with usable fields,
rather than raw text in `archives.log`.

> Cisco FTD firewall denies are handled by the separate **cisco_ftd** and
> **cisco_ftd_session** integrations.

### Prerequisites

- A Wazuh manager receiving syslog from Cisco Nexus switches or IOS-XE devices,
  over `<remote>` syslog or a log collector on an agent.
- Sufficient privileges on the manager to edit files under `/var/ossec/`.
- No third-party software or Python dependencies. This integration is decoder
  and rule XML only. Installing the decoders as a drop-in replacement under
  `etc/decoders/` (the recommended path below) is upgrade-safe.

### Installation and Configuration

#### Decoder Placement Constraint

**Wazuh commits the first child decoder whose `<prematch>` matches, even when
its `<regex>` then fails to extract anything.** A child placed after a matching
sibling never runs. This matters here because:

- `cisco-ios-default` has **no** `<prematch>`, so it matches every message that
  reaches it. Anything placed after it is dead code.
- `cisco-ios-login` (prematch `Login \w+`) and `cisco-ios-auth` (prematch
  `Authentication \w+`), on releases that ship them, also match the NX-OS
  wordings and then fail to extract.

In the file shipped here this is **already handled**: the `cisco-nxos-*`
decoders sit above `cisco-ios-default` (and above `cisco-ios-login` /
`cisco-ios-auth` where present). Each `<prematch>` is specific enough that it
does not collide with the classic IOS formats. You only need to preserve that
ordering yourself if you hand-merge the blocks (see the alternative below).

> Note on the NX-OS timestamp: it is year-first and preceded by the switch
> hostname (`NEXUS-SW-01: 2026 Jun 26 07:34:55 UTC: %AUTHPRIV-6-SYSTEM_MSG: ...`).
> The stock `cisco-ios` parent prematch is unanchored and matches from the month
> token onwards, so the leading hostname and year are ignored for parent
> selection. No change to the parent decoder is required.

#### Installing the Decoders (Drop-In Replacement)

`ruleset/decoders/cisco_ios_decoders.xml` is a **complete replacement** for the
stock Cisco IOS decoder file: the stock decoder set with the six `cisco-nxos-*`
decoders already merged in at the correct position. Because it keeps the stock
decoder names, the stock Cisco IOS rules keep working against it.

Confirm the stock decoder filename on your release first (it carries a numeric
prefix), together with the stock Cisco IOS rules file that depends on it:

```bash
ls /var/ossec/ruleset/decoders/ | grep -i cisco-ios   # e.g. 0065-cisco-ios_decoders.xml
ls /var/ossec/ruleset/rules/    | grep -i cisco        # the stock Cisco IOS rules file
```

**Order matters.** You cannot just add the replacement alongside the stock
decoder: both define the same parent (`cisco-ios`), so with the stock file still
present that parent name is duplicated and the manager errors out. A stock
decoder also cannot be excluded while the stock rules that depend on it are
still loaded. So the sequence is: **exclude the stock decoder and its rules
first, then add the replacement decoder, then re-include the rules.**

**From the Wazuh dashboard** (recommended for Wazuh Cloud and other managed or
as-is deployments):

1. **Exclude the stock decoder and its rules.** Server Management -> Settings ->
   Edit configuration; in the `<ruleset>` block add both exclusions (use the
   rules filename from the grep above), then save and restart the manager:

   ```xml
   <ruleset>
     <!-- Default ruleset -->
     <decoder_dir>ruleset/decoders</decoder_dir>
     <rule_dir>ruleset/rules</rule_dir>
     <decoder_exclude>ruleset/decoders/0065-cisco-ios_decoders.xml</decoder_exclude>
     <rule_exclude>ruleset/rules/0215-cisco-ios_rules.xml</rule_exclude> <!-- confirm exact name via the grep above -->
     ...
     <!-- User-defined ruleset -->
     <decoder_dir>etc/decoders</decoder_dir>
     <rule_dir>etc/rules</rule_dir>
   </ruleset>
   ```

2. **Add the replacement decoder.** Server Management -> Decoders -> Manage
   decoders files -> Add new decoders file. Name it `cisco_ios_decoders.xml`,
   paste the contents of this integration's decoder file, and save (stored under
   `etc/decoders/`). Restart the manager. With the stock decoder excluded there
   is no duplicate `cisco-ios` parent.
3. **Re-include the rules.** Back in Settings, remove the `<rule_exclude>` line
   so the stock IOS rules load again - this time against your replacement
   decoder - keeping the `<decoder_exclude>`. Save and restart.

**From the backend (CLI):** the same three phases, editing
`/var/ossec/etc/ossec.conf` and the filesystem directly:

1. Add both `<decoder_exclude>` and `<rule_exclude>` to the `<ruleset>` block,
   then restart.
2. Copy the replacement decoder in, then restart:

   ```bash
   cp ruleset/decoders/cisco_ios_decoders.xml /var/ossec/etc/decoders/
   chown wazuh:wazuh /var/ossec/etc/decoders/cisco_ios_decoders.xml
   chmod 660 /var/ossec/etc/decoders/cisco_ios_decoders.xml
   ```
3. Remove the `<rule_exclude>` (keep the `<decoder_exclude>`), then restart:

   ```bash
   systemctl restart wazuh-manager
   # or: /var/ossec/bin/wazuh-control restart
   ```

Trade-off: your copy no longer receives upstream decoder improvements or new
message support. Review it against the stock file after each upgrade, and
re-merge if Wazuh adds IOS decoders you want.

#### Alternative: Merge Only the Added Blocks

If you prefer to leave the stock file managed by Wazuh, copy just the six
`cisco-nxos-*` blocks out of the shipped file and paste them into
`/var/ossec/ruleset/decoders/0065-cisco-ios_decoders.xml`, **above**
`cisco-ios-default` (and above `cisco-ios-login` / `cisco-ios-auth` where
present). Back the stock file up first:

```bash
cp /var/ossec/ruleset/decoders/0065-cisco-ios_decoders.xml{,.bak}
```

Trade-off: a manager upgrade replaces files under `/var/ossec/ruleset/`, so the
merge must be re-applied afterwards. Keep this file alongside your
change-management notes so the re-apply is mechanical.

#### Installing the Rules

This integration's own rules (`cisco_ios_rules.xml`) have no ordering hazard;
they select on `if_sid` and field values, and chain off the stock Cisco IOS
rule `4715`, so they need the stock IOS rules loaded (re-included in step 3
above).

**From the Wazuh dashboard:** Server Management -> Rules -> Manage rules files
-> Add new rules file. Name it `cisco_ios_rules.xml`, paste the contents, and
save. Restart the manager.

**From the backend (CLI):**

```bash
cp ruleset/rules/cisco_ios_rules.xml /var/ossec/etc/rules/
chown wazuh:wazuh /var/ossec/etc/rules/cisco_ios_rules.xml
chmod 660 /var/ossec/etc/rules/cisco_ios_rules.xml
```

Then restart the manager:

```bash
systemctl restart wazuh-manager
# or: /var/ossec/bin/wazuh-control restart
```
