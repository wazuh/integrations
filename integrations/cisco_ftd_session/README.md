# Cisco FTD Session-Prefix Deny Decoders - Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Installing the Decoders](#installing-the-decoders)
    * [Enabling Alerts via the Stock FTD Rules](#enabling-alerts-via-the-stock-ftd-rules)
* [Rules](#rules)

### Introduction

Some Cisco FTD builds emit access-list deny events (message **106023**) with a
`%FTD-session-` prefix instead of the standard `%FTD-` prefix:

```
%FTD-session-4-106023: Deny tcp src LAN-INT:192.0.2.124/65191 dst LAN-EXT:198.51.100.157/80 by access-group "CSM_FW_ACL_"
```

The stock Cisco FTD parent decoder only matches `%FTD-<severity>-<id>`, so these
session-prefixed messages fall through undecoded and are visible only in the
archives. This integration adds a dedicated `cisco-ftd-session` parent decoder
plus TCP/UDP and ICMP deny children, so the same denied traffic is decoded with
full fields.

**This integration ships decoders only.** The decoders emit `product.name=FTD`,
exactly as the stock Cisco FTD decoders do, so a one-line change to the stock
FTD ruleset makes its existing rules alert on session-prefixed events too - no
duplicate rules to maintain. See [Rules](#rules).

> The standard `%FTD-` prefix is handled by the separate **cisco_ftd**
> integration. Switch and router authentication is handled by **cisco_ios**.

### Prerequisites

- A Wazuh manager receiving syslog from Cisco FTD appliances that emit the
  `%FTD-session-` prefix, over `<remote>` syslog or a log collector on an agent.
- Sufficient privileges on the manager to edit files under `/var/ossec/`.
- The stock Cisco FTD ruleset (`0905-cisco-ftd_rules.xml`) present, since
  alerting reuses it (see [Rules](#rules)).
- No third-party software or Python dependencies. This integration is decoder
  XML only.

### Installation and Configuration

#### Installing the Decoders

This is a new decoder file with no stock counterpart, so - unlike the
**cisco_ftd** and **cisco_ios** integrations - nothing needs to be excluded. It
simply loads alongside the stock decoders.

**From the Wazuh dashboard** (recommended for Wazuh Cloud and other managed or
as-is deployments): Server Management -> Decoders -> Manage decoders files ->
Add new decoders file. Name it `cisco_ftd_session_decoders.xml`, paste the
contents of this integration's decoder file, and save. Restart the manager.

**From the backend (CLI):**

```bash
cp ruleset/decoders/cisco_ftd_session_decoders.xml /var/ossec/etc/decoders/
chown wazuh:wazuh /var/ossec/etc/decoders/cisco_ftd_session_decoders.xml
chmod 660 /var/ossec/etc/decoders/cisco_ftd_session_decoders.xml
```

Either way it survives manager upgrades, since it lives under `etc/` rather than
`ruleset/`.

#### Enabling Alerts via the Stock FTD Rules

The decoders here emit `product.name=FTD`, but the stock Cisco FTD base rule
(id `91500`) keys on the decoder name (`cisco-ftd`), which does not match the
`cisco-ftd-session` parent. Changing that base rule to key on the `product.name`
field instead makes the entire stock FTD ruleset fire for both prefixes - the
stock `cisco-ftd` decoders and the `cisco-ftd-session` decoders here both emit
`product.name=FTD`, so standard-prefix behaviour is unchanged:

```xml
<rule id="91500" level="0">
  <!-- was: <decoded_as>cisco-ftd</decoded_as> -->
  <field name="product.name">FTD</field>
  <description>Cisco FTD messages grouped.</description>
</rule>
```

**Recommended (upgrade-safe): own a copy of the rules file.** Rather than edit
the stock file in place - which a manager upgrade overwrites - take ownership of
it the same way the decoder integrations do:

1. Copy the stock FTD rules file into `etc/rules/`, and apply the 91500 change
   above to the copy:

   ```bash
   cp /var/ossec/ruleset/rules/0905-cisco-ftd_rules.xml /var/ossec/etc/rules/
   chown wazuh:wazuh /var/ossec/etc/rules/0905-cisco-ftd_rules.xml
   chmod 660 /var/ossec/etc/rules/0905-cisco-ftd_rules.xml
   # then edit rule 91500 in the copy: decoded_as cisco-ftd -> field product.name = FTD
   ```

2. Exclude the stock rules file so only your copy loads (the IDs are identical,
   so both cannot load at once). Server Management -> Settings -> Edit
   configuration, in the `<ruleset>` block:

   ```xml
   <rule_exclude>ruleset/rules/0905-cisco-ftd_rules.xml</rule_exclude>
   ```

3. Restart the manager.

Because your copy lives under `etc/rules/` and the stock file is excluded, the
change survives upgrades. Review the copy against the stock file after each
upgrade so you pick up new FTD rules.

**Quick alternative (not upgrade-safe):** edit rule 91500 directly in
`/var/ossec/ruleset/rules/0905-cisco-ftd_rules.xml` and restart. This is a
default rules file (read-only in the dashboard's rules editor), so make the edit
on the backend. A manager upgrade overwrites it, so re-apply afterwards.

### Rules

**This integration ships no rules.** Alerting reuses the stock Cisco FTD ruleset
via the rule 91500 change above. Once 91500 matches `product.name=FTD`, every
stock FTD rule that fires for a `%FTD-` deny also fires for the equivalent
`%FTD-session-` deny, because both decode to the same fields (`action`,
`protocol`, `srcip`, `cisco.access_group`, and so on). Owning a copy of the
rules file (the recommended path above) keeps that change through upgrades.

If you would rather not reuse the stock ruleset at all, ship a small custom
rules file keyed on `decoded_as cisco-ftd-session` (a base rule plus deny / ICMP
/ frequency rules in the user-defined 110000 block) - fully self-contained, but
it only covers the 106023 deny case rather than the whole FTD ruleset.
