# Cisco FTD and NX-OS Decoders - Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [What This Fixes](#what-this-fixes)
* [Extracted Fields](#extracted-fields)
* [Installation and Configuration](#installation-and-configuration)
    * [Decoder Placement Constraint](#decoder-placement-constraint)
    * [Method A: Merge Into the Stock Decoder Files](#method-a-merge-into-the-stock-decoder-files)
    * [Method B: Exclude and Replace the Stock File](#method-b-exclude-and-replace-the-stock-file)
    * [Installing the Rules](#installing-the-rules)
* [Rules Reference](#rules-reference)
* [Integration Testing](#integration-testing)
* [Troubleshooting](#troubleshooting)
* [Provenance and Maintenance](#provenance-and-maintenance)
* [Sources](#sources)

---

### Introduction

This integration adds decoders and rules for two Cisco log sources that the
stock Wazuh ruleset does not fully cover:

- **Cisco FTD access-list denies (message 106023).** Blocked and denied firewall
  traffic was decoding inconsistently or not at all, leaving it visible only in
  the archives rather than as alerts. Three separate gaps caused this: a
  `%FTD-session-` message prefix the stock parent decoder rejects, interface
  names containing hyphens that a `\w+` pattern cannot match, and ICMP denies
  that carry no port and so do not fit the port-bearing pattern.
- **Cisco NX-OS (Nexus) and IOS-XE authentication and user administration.**
  Login results and account-management events are wrapped in `SYSTEM_MSG` with
  a body that differs from the classic IOS formats, so the stock Cisco IOS
  decoders do not extract the username, source address or outcome.

The result is that denied firewall traffic and switch authentication activity
both become first-class alerts with usable fields, rather than raw text in
`archives.log`.

---

### Prerequisites

- A Wazuh manager receiving syslog from Cisco FTD appliances, Nexus switches, or
  IOS-XE devices, over `<remote>` syslog or a log collector on an agent.
- Sufficient privileges on the manager to edit files under `/var/ossec/`.
- Familiarity with the fact that editing files in `/var/ossec/ruleset/` means
  re-applying changes after a manager upgrade. See
  [Method B](#method-b-exclude-and-replace-the-stock-file) for the upgrade-safe
  alternative.
- No third-party software or Python dependencies. This integration is decoder
  and rule XML only.

---

### What This Fixes

| Log characteristic | Stock behaviour | With these decoders |
| --- | --- | --- |
| `%FTD-session-4-106023: ...` | Parent prematch expects `%FTD-<sev>-<id>`, so the message is not decoded at all. | A dedicated `cisco-ftd-session` parent handles the prefix. |
| Interface names such as `LAN-INT`, `DMZ-INT` | A `\w+` interface pattern stops at the hyphen, so extraction fails or truncates. | Interfaces are matched with `[^:\s]+`, so hyphens and other non-word characters are preserved. |
| `Deny icmp src ... (type 8, code 0)` | ICMP carries no port, so the port-bearing pattern cannot match. | Dedicated ICMP decoders capture `cisco.icmp_type` and `cisco.icmp_code` instead of ports. |
| `Deny tcp src LAN-INT:192.0.2.5/443 ...` | Greedy address matching can swallow the port. | Addresses are matched with `[^/\s]+` so the port is always captured separately. |
| NX-OS `Login failed for user ...` | `cisco-ios-login` prematch matches, but its regex targets the classic IOS format and extracts nothing. | `cisco-nxos-login` extracts `login_status` and `dstuser`. |
| NX-OS `PAM: Authentication failure for illegal user ... from <ip>` | `cisco-ios-auth` prematch matches, regex does not, so the source address is lost. | `cisco-nxos-pam-illegaluser` extracts `dstuser` and `srcip`, enabling brute-force correlation. |
| NX-OS `change user '<u>' password`, `add '<u>' to group '<g>'` | Falls through to `cisco-ios-default`, which extracts only facility, severity and mnemonic. | Dedicated decoders extract the affected user, group and expiry values. |

---

### Extracted Fields

Cisco FTD 106023 decoders:

| Field | Example | Notes |
| --- | --- | --- |
| `action` | `Deny` | |
| `protocol` | `tcp`, `udp`, `icmp` | |
| `src_interface` / `dst_interface` | `LAN-INT`, `DMZ-INT` | Hyphens preserved. |
| `srcip` / `dstip` | `192.0.2.124` | |
| `srcport` / `dstport` | `65191` | TCP and UDP only. |
| `cisco.icmp_type` / `cisco.icmp_code` | `8` / `0` | ICMP only. |
| `cisco.access_group` | `CSM_FW_ACL_` | ACL that dropped the traffic. |
| `cisco.severity` | `4` | Syslog severity from the message tag. |
| `cisco.message_id` | `106023` | Cisco message ID. |

Cisco NX-OS decoders:

| Field | Example | Notes |
| --- | --- | --- |
| `cisco.facility` | `AUTHPRIV`, `DAEMON` | |
| `cisco.severity` | `5` | |
| `cisco.mnemonic` | `SYSTEM_MSG` | |
| `login_status` | `failed`, `success` | Interactive login outcome. |
| `auth_status` | `opened`, `closed` | `pam_unix` session events. |
| `dstuser` | `jdoe.adm` | Account acted upon. May be masked by the device. |
| `srcuser` | `jdoe.adm` | Account owning a `pam_unix` session. |
| `srcip` | `198.51.100.191` | Source of a PAM authentication failure. |
| `cisco.group` | `network-admin` | Role or group the account was added to. |
| `cisco.old_expiration` / `cisco.new_expiration` | `2026-06-27` | Account expiry change. |

---

### Installation and Configuration

#### Decoder Placement Constraint

Read this before installing. It determines whether the decoders work at all.

**Wazuh commits the first child decoder whose `<prematch>` matches, even when
its `<regex>` then fails to extract anything.** A child placed after a matching
sibling never runs. This has two consequences here:

- `cisco-ios-default` has **no** `<prematch>`, so it matches every message that
  reaches it. Anything placed after it is dead code.
- `cisco-ios-login` (prematch `Login \w+`) and `cisco-ios-auth` (prematch
  `Authentication \w+`) also match the NX-OS wordings, then fail to extract.

The NX-OS decoders in this integration must therefore be placed **above**
`cisco-ios-login`, `cisco-ios-auth` and `cisco-ios-default`. Likewise, the FTD
decoders must be placed above any generic child of the `cisco-ftd` parent. Each
`<prematch>` supplied here is specific enough that it does not collide with the
classic IOS formats.

Ordering across files follows load order: `ruleset/decoders/` is loaded in
filename order, then `etc/decoders/`. A file dropped into `etc/decoders/`
therefore always loads **last**, which is why simply copying these files there
is not sufficient on its own.

The `cisco-ftd-session` parent is the one exception. It is a new top-level
decoder that only ever sees messages the stock `cisco-ftd` parent declined, so
it can live anywhere.

#### Method A: Merge Into the Stock Decoder Files

This is the straightforward path and the one these files were developed against.
Confirm the stock filenames on your release first, since they carry a numeric
prefix:

```bash
ls /var/ossec/ruleset/decoders/ | grep -i -E 'cisco-(ios|ftd)'
```

On current releases these are `0016-cisco-ios_decoders.xml` and
`0066-cisco-ftd_decoders.xml`. Back them up, then merge:

```bash
cp /var/ossec/ruleset/decoders/0016-cisco-ios_decoders.xml{,.bak}
cp /var/ossec/ruleset/decoders/0066-cisco-ftd_decoders.xml{,.bak}
```

- Insert the contents of `ruleset/decoders/cisco_nxos_auth_decoders.xml` into
  `0016-cisco-ios_decoders.xml`, immediately **before** the `cisco-ios-login`
  decoder block.
- Insert the contents of `ruleset/decoders/cisco_ftd_deny_decoders.xml` into
  `0066-cisco-ftd_decoders.xml`, **before** any child decoder of `cisco-ftd`
  that lacks a `<prematch>`.

Trade-off: a manager upgrade replaces files under `/var/ossec/ruleset/`, so the
merge must be re-applied afterwards. Keep the two files from this integration
alongside your change-management notes so the re-apply is mechanical.

#### Method B: Exclude and Replace the Stock File

Upgrade-safe, at the cost of taking ownership of the whole file. Copy the stock
file into `etc/decoders/`, merge the blocks from this integration into it at the
positions described above, and tell the manager to ignore the original:

```bash
cp /var/ossec/ruleset/decoders/0016-cisco-ios_decoders.xml \
   /var/ossec/etc/decoders/cisco-ios_decoders.xml
# merge in cisco_nxos_auth_decoders.xml, then:
chown wazuh:wazuh /var/ossec/etc/decoders/cisco-ios_decoders.xml
chmod 660 /var/ossec/etc/decoders/cisco-ios_decoders.xml
```

Then add the exclusion to `/var/ossec/etc/ossec.conf`, inside `<ossec_config>`:

```xml
<ossec_config>
    ...
  <ruleset>
    <decoder_exclude>ruleset/decoders/0016-cisco-ios_decoders.xml</decoder_exclude>
  </ruleset>
    ...
</ossec_config>
```

Repeat for the FTD file if you need the same guarantee there.

Trade-off: your copy no longer receives upstream decoder improvements or new
message support. Review it against the stock file after each upgrade.

#### Installing the Rules

Rules have no equivalent ordering hazard, because they select on `decoded_as`,
`if_sid` and field values rather than on first-match position. Copy them
straight into the custom rules directory:

```bash
cp ruleset/rules/cisco_ftd_deny_rules.xml /var/ossec/etc/rules/
cp ruleset/rules/cisco_nxos_auth_rules.xml /var/ossec/etc/rules/
chown wazuh:wazuh /var/ossec/etc/rules/cisco_ftd_deny_rules.xml /var/ossec/etc/rules/cisco_nxos_auth_rules.xml
chmod 660 /var/ossec/etc/rules/cisco_ftd_deny_rules.xml /var/ossec/etc/rules/cisco_nxos_auth_rules.xml
```

Then restart the manager:

```bash
systemctl restart wazuh-manager
# or: /var/ossec/bin/wazuh-control restart
```

---

### Rules Reference

Rule IDs occupy the 110000 block, which is inside the range reserved for
user-defined rules. Change them if that block is already in use on your manager.

| Rule ID | Level | Fires when |
| --- | --- | --- |
| 110000 | 0 | Base: message decoded by `cisco-ftd-session`. Classification only. |
| 110001 | 0 | Base: message decoded by `cisco-ftd`. Classification only. |
| 110010 | 5 | Traffic denied by an access-group, any protocol. |
| 110011 | 5 | ICMP denied by an access-group, with type and code. |
| 110012 | 10 | 10 or more denies from the same source within 120 seconds. |
| 110020 | 0 | Base: message decoded by `cisco-ios`. Classification only. |
| 110021 | 5 | NX-OS interactive login failed. |
| 110022 | 3 | NX-OS interactive login succeeded. |
| 110023 | 6 | NX-OS PAM authentication failure for an unknown user, with source IP. |
| 110024 | 8 | NX-OS account password changed. |
| 110025 | 8 | NX-OS account added to a role or group. |
| 110026 | 5 | NX-OS account expiry changed. |
| 110027 | 3 | NX-OS `pam_unix` session opened or closed. |
| 110028 | 10 | 6 or more PAM authentication failures from the same source within 120 seconds. |

The two frequency rules, 110012 and 110028, should be tuned to your environment
before you rely on them. A chatty but benign host will otherwise produce level
10 alerts.

---

### Integration Testing

`sample-logs.log` in this directory contains an anonymized sample of every
format the decoders handle. Test each one with `wazuh-logtest`:

```bash
/var/ossec/bin/wazuh-logtest
```

#### Test 1: FTD TCP deny with the session prefix and hyphenated interfaces

Input:

```
Jul 10 11:04:18 192.0.2.1  : : %FTD-session-4-106023: Deny tcp src LAN-INT:192.0.2.124/65191 dst LAN-EXT:198.51.100.157/80 by access-group "CSM_FW_ACL_" [0x0, 0x0]
```

Expected: decoder `cisco-ftd-session`, rule 110010 at level 5, with
`src_interface` extracted in full as `LAN-INT` rather than truncated at the
hyphen, and `srcport` separate from `srcip`.

#### Test 2: FTD ICMP deny

Input:

```
Jul 10 11:09:19 192.0.2.1  : : %FTD-session-4-106023: Deny icmp src DMZ-INT:192.0.2.23 dst LAN-EXT:198.51.100.5 (type 8, code 0) by access-group "CSM_FW_ACL_" [0x0, 0x0]
```

Expected: rule 110011 at level 5, with `cisco.icmp_type` of `8`,
`cisco.icmp_code` of `0`, and no port fields.

#### Test 3: NX-OS PAM authentication failure

Input:

```
NEXUS-SW-01: 2026 Jun 26 08:00:15 UTC: %DAEMON-3-SYSTEM_MSG: error: PAM: Authentication failure for illegal user ***** from 198.51.100.191 - dcos_sshd[20518]
```

Expected: decoder `cisco-nxos-pam-illegaluser`, rule 110023 at level 6, with
`srcip` of `198.51.100.191`. If you instead see the event attributed to
`cisco-ios-auth` or `cisco-ios-default` with no `srcip`, the decoders were
placed too low in the file. Revisit
[Decoder Placement Constraint](#decoder-placement-constraint).

#### Test 4: NX-OS account management

Input:

```
NEXUS-SW-01: 2026 Jun 26 06:47:39 UTC: %AUTHPRIV-6-SYSTEM_MSG: add 'jdoe.adm' to group 'network-admin' - usermod[11063]
```

Expected: decoder `cisco-nxos-user-addgroup`, rule 110025 at level 8, with
`dstuser` of `jdoe.adm` and `cisco.group` of `network-admin`.

#### Confirming alerts end to end

Once logtest is correct, verify that live traffic produces alerts:

```bash
tail -f /var/ossec/logs/alerts/alerts.json | grep -E '"id":"1100(1|2)[0-9]"'
```

---

### Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Denied traffic still only in `archives.log` | Rules not loaded, or the base rule did not match. Confirm the decoder name in logtest first, then check the rules landed in `/var/ossec/etc/rules/`. |
| Decoder shows as `cisco-ios-default` with only facility and severity | The NX-OS decoders sit below `cisco-ios-default`. Move them above it. |
| Decoder matched but fields are empty | A sibling decoder with a broader `<prematch>` claimed the event first. Move the specific decoders higher. |
| `src_interface` truncated at the first hyphen | The stock decoder is still winning. Confirm your merge is in the loaded file, not only in a copy under `etc/decoders/`. |
| Nothing decodes after a manager upgrade | Upgrade replaced `/var/ossec/ruleset/`. Re-apply Method A, or move to Method B. |
| `wazuh-analysisd` fails to start after the change | XML error or duplicate rule ID. Check `/var/ossec/logs/ossec.log` and validate with `/var/ossec/bin/wazuh-logtest -t`. |

---

### Provenance and Maintenance

- **Original source**: The stock Wazuh Cisco IOS decoders
  (originally authored by Daniel Cid, updated by Wazuh Inc., Copyright (C) 2015
  Wazuh Inc. and Copyright (C) 2009 Trend Micro Inc.) and the stock Wazuh Cisco
  FTD decoders. This integration supplies additional decoder and rule blocks
  that extend them; it does not redistribute the stock files.
- **Adapted by**: Leon Fuller.
- **Tested versions**: Wazuh manager 4.x. Cisco FTD syslog message 106023 in
  both the `%FTD-` and `%FTD-session-` forms; Cisco NX-OS (Nexus 9000 series)
  and IOS-XE `SYSTEM_MSG` authentication and user-administration messages.
- **Maintainer**: Leon Fuller.
- **Support boundary**: Community-maintained and provided as is. Not covered by
  Wazuh commercial support.

All addresses, hostnames and usernames in this directory are anonymized. IPv4
addresses use the documentation ranges reserved by RFC 5737.

---

### Sources

- <https://documentation.wazuh.com/current/user-manual/ruleset/decoders/index.html>
- <https://documentation.wazuh.com/current/user-manual/ruleset/custom.html>
- <https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/ruleset.html>
- <https://documentation.wazuh.com/current/user-manual/ruleset/testing.html>
- <https://www.cisco.com/c/en/us/td/docs/security/firepower/Syslogs/b_fptd_syslog_guide.html>
- <https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html>
- <https://datatracker.ietf.org/doc/html/rfc5737>
