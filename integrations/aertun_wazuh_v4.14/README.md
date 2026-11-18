# Aertun-Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Installing Aertun](#installing-aertun)
    * [Initial Aertun Configuration](#initial-aertun-configuration)
    * [Installing Wazuh (if applicable)](#installing-wazuh-if-applicable)
    * [Initial Wazuh Configuration (if applicable)](#initial-wazuh-configuration-if-applicable)
    * [Using the Integration Files](#using-the-integration-files)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)
* [Provenance and Maintenance](#provenance-and-maintenance)

---

### Introduction

[Aertun](https://github.com/Aertun/Aertun) checks security work and signs the
result. A detection rule, an AI analyst's verdict, a vendor's claim or a
vulnerability report is run against evidence its author did not write, and
the outcome is a signed in-toto statement: proven, refuted or inconclusive.

This integration connects it to Wazuh in both directions.

1. **Wazuh alerts into Aertun, sealed as they arrive.** `custom-aertun.py`
   sends each alert to an Aertun webhook feed, signed as a
   [Standard Webhooks](https://www.standardwebhooks.com) delivery. Aertun
   stores it through its `wazuh/alerts` mapping, beside its other sources. On
   a feed added with `--seal`, it also commits the alert's digest to its
   hash-chained audit log, within 30 seconds of arrival, in one entry for each
   batch of alerts. Later, `aertun proof sealed --alert FILE` signs that
   the alert, exactly as Wazuh wrote it, existed by then. Once a log head that
   covers it is anchored in Bitcoin, that time is no longer anybody's word.
   This matters when somebody later asks when you knew.
2. **A blind test of the Wazuh deployment itself.** `aertun mdr` runs
   emulations at random times from a plan committed before any ran, joins
   Wazuh's alerts on the hosts the plan names, and signs how often Wazuh
   alerted within a time you set. The result has exact bounds.
3. **Aertun's audit log into Wazuh.** A Wazuh agent on the Aertun host tails
   the audit log, which is one JSON object per line. `aertun_rules.xml` raises
   alerts on what a security team watches for: an AI agent's kill switch, a
   signed check refuted, a peer deployment that signed a second history of its
   log, repeated refusals, privilege granted and revoked, legal holds, trusted
   signers and declared incidents.

---

### Prerequisites

* Wazuh manager 4.14.x. Tested on 4.14.10. The rules are 4.x XML; Wazuh 5.0
  moves rules to a new format and is not covered (see the gaps under
  Integration Testing).
* Aertun 0.2.0 or later, reachable from the manager over https. Aertun listens
  on loopback; put it behind a TLS proxy (its `deploy/Caddyfile` does this).
* Python 3.8 or later on the manager, standard library only. Wazuh's bundled
  interpreter (`/var/ossec/framework/python`, Python 3.10 on 4.14.10) runs it.
* An Aertun administrator token, to add the feed.
* Network: the manager reaches Aertun on 443/tcp. For the audit log, a Wazuh
  agent on the Aertun host reaches the manager as usual (1514/tcp).

---

### Installation and Configuration

#### Installing Aertun

Download a release and check it before running it. Every release is a single
static binary with a build attestation:

```bash
gh release download v0.2.0 --repo Aertun/Aertun --pattern 'aertun-linux-amd64*'
gh attestation verify aertun-linux-amd64 --repo Aertun/Aertun
```

Or run the signed image, `ghcr.io/aertun/aertun:0.2.0`. To set up the store,
its Owner, a token for the command line and the TLS proxy, follow
[deploy/README.md](https://github.com/Aertun/Aertun/blob/main/deploy/README.md).

#### Initial Aertun Configuration

Add a feed for Wazuh's alerts. `--seal` commits each one's digest to the
audit log within 30 seconds of its arrival, in one entry for each batch
(a full batch at once):

```bash
aertun config set admin.base_url https://aertun.example.com
aertun inbound add webhook wazuh --mapping wazuh/alerts --seal
```

It prints the feed's URL, `https://aertun.example.com/feeds/wazuh`, and its
signing secret, `whsec_...`. The secret is shown once and is never stored
in the clear; keep it for the manager's `<integration>` block.

`wazuh/alerts` is one of the mappings Aertun ships (`aertun source list`).
Each alert becomes an OCSF detection. Its actor is `data.srcuser`, its target `data.dstuser` and
its device `agent.name`, and it carries the source IP and any file-integrity
hash and path as observables. Rule id, level, groups, MITRE ids, agent,
decoder, location and `full_log` are kept for rules to read: `raw.rule`,
`raw.level`, `raw.groups`, `raw.mitre` and so on.

#### Installing Wazuh (if applicable)

A standard Wazuh installation is assumed:
[installation guide](https://documentation.wazuh.com/current/installation-guide/index.html).

#### Initial Wazuh Configuration (if applicable)

None beyond the integration files below.

#### Using the Integration Files

**Wazuh to Aertun: the script.** On the manager:

```bash
cp custom-aertun.py /var/ossec/integrations/custom-aertun.py
chown root:wazuh /var/ossec/integrations/custom-aertun.py
chmod 750 /var/ossec/integrations/custom-aertun.py
```

If Aertun's certificate is from a private CA, give the manager that CA:

```bash
cp aertun-ca.pem /var/ossec/etc/aertun-ca.pem
chown root:wazuh /var/ossec/etc/aertun-ca.pem && chmod 640 /var/ossec/etc/aertun-ca.pem
```

In `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <integration>
    <name>custom-aertun.py</name>
    <hook_url>https://aertun.example.com/feeds/wazuh</hook_url>
    <api_key>whsec_THE_FEED_SIGNING_SECRET</api_key>
    <level>3</level>
    <alert_format>json</alert_format>
    <!-- Only when Aertun's certificate is from a private CA. -->
    <options>{"ca_file": "/var/ossec/etc/aertun-ca.pem"}</options>
  </integration>
</ossec_config>
```

The integrator runs a script whose name ends in `.py` with Wazuh's own Python,
so no wrapper is needed. The script speaks https only. Each alert goes once:
the delivery id is the manager's name and the alert's id, so a retry is not
stored twice. It retries a connection failure or a 5xx answer up to three
times, and logs failures (never the secret or the alert's contents) to
`/var/ossec/logs/integrations.log`. The options file may also set `timeout`
(seconds, default 10) and `retries` (1 to 5, default 3).

**Aertun to Wazuh: the rules.** On the manager:

```bash
cp ruleset/rules/aertun_rules.xml /var/ossec/etc/rules/aertun_rules.xml
chown wazuh:wazuh /var/ossec/etc/rules/aertun_rules.xml
chmod 660 /var/ossec/etc/rules/aertun_rules.xml
```

On the Aertun host's Wazuh agent, in its `ossec.conf` (the store's path is
the one `aertun --root` names):

```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/srv/aertun/store/audit.jsonl</location>
  </localfile>
</ossec_config>
```

Restart the manager, and the agent: `systemctl restart wazuh-manager`,
`systemctl restart wazuh-agent`.

The rules use IDs 998000 to 998017. Principals are pseudonymised in Aertun's
log itself (`p_` and a digest), so Wazuh receives no person's name from it.
The exception is where an entry's own detail names one, as a grant waiting for
approval does ("make lee@example.com admin on /").

| Rule | Level | Raised when |
| --- | --- | --- |
| 998000 | 0 | any Aertun audit entry (the parent; raises nothing) |
| 998001 | 10 | an AI agent's kill switch was used (`agent.disable`) |
| 998002 | 3 | an AI agent was enabled again |
| 998003 | 10 | a signed check was refuted: any `*.proved` or `vuln.report.refereed` entry with verdict `refuted` |
| 998004 | 12 | a peer deployment signed a second history of its audit log (`inbound.fork`) |
| 998005 | 5 | Aertun refused a command: the caller was not proved or not authorised |
| 998006 | 10 | five refusals of one caller within five minutes |
| 998007 | 8 | a second administrator approved a grant |
| 998008 | 8 | a grant is waiting for a second administrator |
| 998009 | 6 | access was revoked |
| 998010 | 6 | an administrator's token was issued |
| 998011 | 7 | an incident was declared |
| 998012 | 5 | a setting was changed |
| 998013 | 4 | a legal hold was placed on the event store |
| 998014 | 8 | a legal hold was lifted |
| 998015 | 0 | alerts were sealed: level 0 on purpose, see below |
| 998016 | 3 | a vulnerability report was committed to the log |
| 998017 | 8 | a new key's proofs were trusted |

**Rule 998015 must stay below the integration's level.** Wazuh sends its
alerts to Aertun, and Aertun writes `alert.sealed` entries for them. If a
Wazuh alert were raised on that entry, it would be sent back, sealed again,
and so on without end. At level 0, the entry is decoded and nothing is sent.
Other Aertun alerts that reach the integration's level go to Aertun once: they
are stored and sealed, and the seal raises nothing. This was tested with the
audit log shipped continuously while alerts arrived: the counts settled.

---

### Integration Steps

**Wazuh to Aertun.** An alert at or above the integration's level is written
by the integrator to a temporary file. The integrator then runs
`custom-aertun.py FILE API_KEY HOOK_URL [OPTIONS_FILE]`. The script posts the
alert unchanged, with `webhook-id`, `webhook-timestamp` and `webhook-signature`
headers. Aertun checks the signature and refuses a timestamp more than five
minutes off. It stores the alert. On a sealing feed, it commits the alert's digest within
30 seconds, in one `alert.sealed` entry for each batch, in the feed's name. `aertun inbound status wazuh` shows
deliveries, refusals and the last error.

A real alert as Aertun stored it (rule 40112, raised by Wazuh 4.14.10 on
`sshd` lines):

```text
source wazuh/alerts  class detection  device wazuh:wazuh-mgr  target wazuh:root
message "Multiple authentication failures followed by a success."
ip 203.0.113.9  raw.rule 40112  raw.level 12  raw.mitre "T1078 T1110"
raw.groups "syslog attacks"  raw.alert 1794994957.710989
```

To prove later that an alert existed by a time, use the alert exactly as Wazuh
wrote it in `alerts.json`:

```bash
grep '"id":"1794994957.710989"' /var/ossec/logs/alerts/alerts.json > alert.json
aertun auditlog anchor          # sends the log's head to OpenTimestamps
aertun proof sealed --alert alert.json --key release.key --out sealed.proof.json
```

The proof is inconclusive until a Bitcoin block holds an anchored head that
covers the seal, and proven after.

**Measuring Wazuh blind.** Plan emulations, for example Atomic Red Team
tests, on hosts Wazuh watches. Aertun commits the plan's digest before any
emulation runs, and shows each one only as it falls due. After each run,
record it. Then join Wazuh's alerts from the event store and sign the result:

The emulation list is one emulation a line, with the host it runs on,
written as Aertun names Wazuh's agents, `wazuh:AGENT_NAME`:

```text
T1110.001-1 wazuh:web-01
T1059.004-2 wazuh:web-01
T1136.001-3 wazuh:db-01
```

```bash
aertun mdr plan wazuh-q4 --provider wazuh --emulations emulations.txt --count 20 --over 30d
aertun mdr next wazuh-q4
aertun mdr ran wazuh-q4 --item 1 --at 2026-11-20T10:04:00Z
aertun mdr notified wazuh-q4 --source wazuh/alerts
aertun mdr prove wazuh-q4 --sla 30m --tolerance 0.1 --key release.key
```

**Aertun to Wazuh.** The agent reads each new line of the audit log, Wazuh's
JSON decoder decodes it, and the rules above raise alerts with the entry's
fields: `action`, `outcome`, `resource`, `kind`, `verified` and `detail.*`.

```json
{"seq":7,"at":"2026-11-18T09:55:19.648517506Z","prev":"3549c52ddcf0c4a4f3ab9a891177e87e8b6fc1d0d8c7d2a429b9211efcabf1fa","hash":"1377952f30e4aebb555a75beb457e7fe62470a1f4991c4c121608d33fb3c313f","action":"agent.disable","resource":"/agents/triage-bot","source":"p_63bf425f69a2732cfed08a49f3447de9","outcome":"success","principal":"p_16591fb6ad4970723332ee18b8281579","kind":"human","verified":true,"detail":{"agent":"triage-bot","revoked":"0","why":"it closed a real finding"}}
```

raises rule 998001, level 10: "Aertun: the kill switch stopped AI agent
triage-bot."

---

### Integration Testing

**The rules.** `aertun.ini` holds 21 cases, all real audit-log entries from
`sample_logs.txt`. On the manager, after installing the rules:

```bash
/var/ossec/framework/python/bin/python3 check_rules.py aertun.ini
```

```text
pass  Aertun: the kill switch stops an AI agent.
...
21 of 21 cases hold
```

Or one line at a time:

```bash
head -2 sample_logs.txt | tail -1 | /var/ossec/bin/wazuh-logtest
```

**The script.** Raise a test alert. For example, with a `syslog` `localfile`
for `/var/log/test.log`, append ten `sshd` failures and a success:

```bash
for i in $(seq 9); do echo "$(date '+%b %e %H:%M:%S') host sshd[1$i]: Failed password for invalid user oracle from 198.51.100.23 port 5$i ssh2" >> /var/log/test.log; done
echo "$(date '+%b %e %H:%M:%S') host sshd[99]: Accepted password for root from 198.51.100.23 port 52099 ssh2" >> /var/log/test.log
```

Within seconds, `aertun inbound list` shows the deliveries, and
within 30 seconds `aertun alert seal --list` shows an `alert.sealed` entry
holding them. A wrong
`api_key` appears as `refused by Aertun (401)` in
`/var/ossec/logs/integrations.log`, and as a refusal in
`aertun inbound status wazuh`.

**What was verified, on Wazuh 4.14.10 and Aertun 0.2:**

* The `wazuh/alerts` mapping reads all 16 alerts a 4.14.10 manager raised in
  testing, from rules 502, 5403, 5710, 5712, 40112, 19003, 19007, 19008 and
  19009. They are kept as `internal/source/testdata/wazuh-alerts.jsonl` in
  Aertun's repository.
* Integratord enables `custom-aertun.py` by name. Live alerts arrived over
  TLS and were stored; ten raised together were sealed in one audit entry, a
  batch of ten. An alert taken from the manager's `alerts.json` was found by
  `aertun proof sealed` in the batch that sealed it, with its Merkle path
  reaching the root.
* Aertun's test suite runs the script, as the integrator does, against the
  feed over TLS. The alert is delivered and sealed. Sent twice, it is taken
  once. A wrong secret exits 1, plain http exits 2, and an untrusted
  certificate exits 1, with nothing stored.
* All 21 cases in `aertun.ini` hold in `wazuh-logtest`. With the audit log
  shipped live into a `json` `localfile`, the kill switch, the refusals and
  the burst rule, the incident and the setting change were raised as alerts
  in `alerts.json`.
* The feedback loop above was observed in design, fixed by making 998015
  level 0, and checked with the log shipped continuously: no growth after
  the alerts stopped.

**Gaps, stated rather than covered:**

* Wazuh 5.0 is not covered. Its rules are a new YAML format, and as of 5.0-rc
  it has no command-line rule test to verify them with.
* The fork (998004), approved grant (998007) and trusted signer (998017)
  samples were written by Aertun's own test suite, not a live deployment,
  because each needs a second deployment or a second administrator's passkey.
  They are Aertun's real records, field for field.
* The burst rule (998006) counts refusals per pseudonymised principal. Every
  caller whose token is rejected is recorded under the same unverified
  identity, so it counts them together.

---

### Sources

* Aertun: <https://github.com/Aertun/Aertun>. The feed's `--seal` and the
  `wazuh/alerts` mapping arrived in 0.2.0.
* Aertun's sealed-alert proof: `aertun proof sealed`, in its README.
* Wazuh integrator: <https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html>
* Wazuh rules syntax: <https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html>
* Wazuh JSON decoder: <https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html>
* Standard Webhooks: <https://www.standardwebhooks.com>
* RFC 8785, JSON Canonicalization Scheme, which an alert's digest is taken
  over: <https://www.rfc-editor.org/rfc/rfc8785>

---

## Provenance and Maintenance

* **Original source:** written for this integration, in the Aertun
  repository's `integrations/wazuh/`. It is not derived from another
  integration. The script follows the argument convention of Wazuh's own
  integrations: alert file, API key, hook URL, then options.
* **Adapted by:** not adapted; maintained in the Aertun repository, from which
  this copy is taken.
* **Tested versions:** Wazuh manager 4.14.10 (`wazuh/wazuh-manager:4.14.10`),
  with its bundled Python 3.10.21 and the system Python 3.9.25; Aertun 0.2.0.
* **Maintainer:** the Aertun project, <https://github.com/Aertun/Aertun>.
* **Support boundary:** community-maintained by the Aertun project and
  provided as-is. Report problems on the Aertun repository's issues.
