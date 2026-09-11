# Whisper-Wazuh Integration

Enrich Wazuh alerts with relationship context from the [Whisper](https://www.whisper.security)
infrastructure graph — the internet modeled as one connected graph (ASNs, prefixes, DNS, WHOIS,
threat feeds, Tor relays, TLS fingerprints).

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Installing Whisper](#installing-whisper)
    * [Initial Whisper Configuration](#initial-whisper-configuration)
    * [Installing Wazuh (if applicable)](#installing-wazuh-if-applicable)
    * [Initial Wazuh Configuration (if applicable)](#initial-wazuh-configuration-if-applicable)
    * [Using the Integration Files](#using-the-integration-files)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

---

## Introduction

When a Wazuh alert carries a public IP or domain, this integration asks the Whisper graph what it
knows about that indicator and writes the answer back into Wazuh as a new, evidence-graded alert
under `data.whisper.*` — verdict (`known_bad` / `suspicious` / `known_good` / `unknown`), risk score,
threat feeds, ASN + reputation, prefix threat, geo; for domains also DNS / WHOIS / SPF / lookalikes.
The verdict is derived from *evidence* (threat-feed categories + confirmed-malicious node flags),
never copied from the raw score — "trust never overrides threat" — and a bundled rule maps it to a
Wazuh alert level.

It is a Pattern-A `integratord` custom script — stdlib-only Python on the manager's bundled
interpreter — and the graph enrichment is **keyless** (no API key required).

> A *keyed* tier (an agent-activity log source) and an on-demand investigation CLI, plus packaged
> installers, live in the upstream project: <https://github.com/whisper-sec/whisper-wazuh>.

---

## Prerequisites

* **Wazuh Server (manager) 4.x** — tested on 4.14.5.
* The manager's **bundled Python 3.10** — the connector is standard-library only; nothing to
  `pip install`.
* **TLS egress** from the manager to `graph.whisper.online` (the graph API).
* The **Wazuh indexer reachable** from the manager, to install the field-type template.
* **No API key** — the graph enrichment is queried anonymously. (The upstream *keyed* features need a
  Whisper API key; see [Sources](#sources).)

---

## Installation and Configuration

### Installing Whisper

Nothing to install — Whisper is a hosted service. The connector queries the graph at
`https://graph.whisper.online`; you only need TLS egress to it from the manager (see
[Prerequisites](#prerequisites)).

### Initial Whisper Configuration

None. The graph enrichment is keyless, so there is no account, API key, or console setup.

### Installing Wazuh (if applicable)

A standard Wazuh installation is assumed. See the official
[Wazuh installation guide](https://documentation.wazuh.com/current/installation-guide/index.html).

### Initial Wazuh Configuration (if applicable)

No special configuration is required beyond a standard manager.

### Using the Integration Files

This integration ships five files:

| File | Destination | Perms |
|---|---|---|
| `custom-whisper` (shell wrapper) | `/var/ossec/integrations/` | 750 `root:wazuh` |
| `custom-whisper.py` (connector) | `/var/ossec/integrations/` | 750 `root:wazuh` |
| `whisper_client.py` (shared HTTP/TLS client — imported by the connector) | `/var/ossec/integrations/` | 640 `root:wazuh` |
| `whisper_rules.xml` | `/var/ossec/etc/rules/` | 660 `root:wazuh` |
| `whisper-template.json` (indexer field types) | PUT to the indexer | — |

**1. Scripts** (the connector imports `whisper_client.py`, so all three go together):

```bash
cp custom-whisper custom-whisper.py whisper_client.py /var/ossec/integrations/
chown root:wazuh /var/ossec/integrations/custom-whisper /var/ossec/integrations/custom-whisper.py /var/ossec/integrations/whisper_client.py
chmod 750 /var/ossec/integrations/custom-whisper /var/ossec/integrations/custom-whisper.py
chmod 640 /var/ossec/integrations/whisper_client.py
```

**2. Rules:**

```bash
cp whisper_rules.xml /var/ossec/etc/rules/
chown root:wazuh /var/ossec/etc/rules/whisper_rules.xml && chmod 660 /var/ossec/etc/rules/whisper_rules.xml
```

**3. Indexer field types** (analysisd stringifies every value; the template coerces `data.whisper.*`
numbers/booleans back so range queries work):

```bash
curl -sk -u <indexer-user>:<indexer-pass> -XPUT "https://<indexer>:9200/_template/whisper" \
  -H 'Content-Type: application/json' -d @whisper-template.json
```

**4. Register the integration** in the manager's `/var/ossec/etc/ossec.conf`. There is **no
`<api_key>`** — the enrichment is keyless. `<name>` must match the shell wrapper:

```xml
<integration>
  <name>custom-whisper</name>
  <group>sshd</group>          <!-- the rule groups whose alerts get enriched -->
  <alert_format>json</alert_format>
</integration>
```

`<group>` (or `<rule_id>`) is your cost/noise dial: every matching alert that carries a public IP or
domain becomes one graph lookup (deduped by a small cache). Start narrow (e.g. `sshd`) and widen
deliberately. Never point it at a group the enrichment alerts themselves carry.

The callout is synchronous (integratord runs one alert at a time), so the connector keeps a
wall-clock budget per invocation and never lets a slow or unreachable API stall the manager. Two
optional `<options>` knobs tune it: `deadline` (seconds per alert, default `20`; every query's
timeout and retry backoff shrink to what is left) and `max_iocs` (indicators enriched per alert,
default `5`):

```xml
<options>{"deadline": 20, "max_iocs": 5}</options>
```

**5. Restart the manager** after these changes:

```bash
systemctl restart wazuh-manager   # or: /var/ossec/bin/wazuh-control restart
```

---

## Integration Steps

End to end, an enrichment flows like this:

1. A rule fires and the alert lands in a group your `<integration>` filter watches (e.g. `sshd`).
2. `integratord` invokes `custom-whisper` with the alert JSON.
3. The connector extracts a **public IP or domain** from the alert (private / TEST-NET addresses are
   skipped) and queries the Whisper graph — **no API key**.
4. It derives an **evidence-based verdict** and writes a new alert under `data.whisper.*` back onto
   the analysisd queue, linked to the triggering alert via `source_ref`.
5. `whisper_rules.xml` renders the verdict as a Wazuh alert level, and the enrichment alert appears
   in `wazuh-alerts-*`.

The verdict → alert-level mapping (bundled rules):

| Verdict | Meaning | Rule | Level |
|---|---|---|---|
| `known_bad` | confirmed-malicious evidence (C2 / malware / phishing) | 100501 | 12 |
| `known_bad` (CRITICAL) | as above, with a critical graph score | 100505 | 14 |
| `suspicious` | a threat signal without a confirmed-bad category (e.g. Tor / anonymizer) | 100502 | 7 |
| `known_good` | allowlist-vouched, no threat | 100503 | 3 |
| `unknown` | no data at this granularity (no-data ≠ safe) | 100504 | 3 |

---

## Integration Testing

First enable the connector's debug log:

```bash
echo 'integrator.debug=2' >> /var/ossec/etc/local_internal_options.conf
/var/ossec/bin/wazuh-control restart
```

**Test 1 — the rules render a verdict (`wazuh-logtest`).** `wazuh-logtest` loads the ruleset from
disk, so it confirms `whisper_rules.xml` maps a verdict to the right level:

```bash
# suspicious (a Tor exit) → rule 100502, level 7
printf '%s\n' '{"integration":"custom-whisper","whisper":{"ioc":"185.220.101.1","verdict":"suspicious","level":"HIGH"}}' | /var/ossec/bin/wazuh-logtest
#   Phase 3: id '100502'  level '7'  "Whisper: 185.220.101.1 is SUSPICIOUS (HIGH)"

# known_good → rule 100503 (level 3);  known_bad → rule 100501 (level 12)
```

**Test 2 — the connector enriches a live indicator (end to end).** Run the connector against a
single-alert JSON file (argv: `<alert-file> <api_key> <hook_url> debug`; `api_key` is unused for the
keyless graph and can be empty):

```bash
cat > /tmp/alert.json <<'JSON'
{"timestamp":"2026-01-01T00:00:00.000+0000","rule":{"id":"5710","level":5,"groups":["sshd"]},
 "agent":{"id":"000","name":"manager"},"id":"1700000000.1","full_log":"...",
 "data":{"srcip":"185.220.101.1"},"location":"/var/log/auth.log"}
JSON

/var/ossec/integrations/custom-whisper.py /tmp/alert.json '' '' debug
#   whisper: invoke ioc=185.220.101.1 type=ipv4 ...
#   whisper: api url=https://graph.whisper.online ms=...
#   whisper: emit ... payload_bytes=...
```

**Check the results:**

* Connector diagnostics go to `/var/ossec/logs/integrations.log`; manager messages to
  `/var/ossec/logs/ossec.log`; the decoded enrichment event is in
  `/var/ossec/logs/archives/archives.log` when archiving is enabled.
* In the **Wazuh dashboard** (Discover → `wazuh-alerts-*`), search `data.whisper.ioc:185.220.101.1`
  — a new enrichment alert (e.g. rule 100502, *"Whisper: … is SUSPICIOUS (HIGH)"*) appears next to
  the original.

Private / non-global IPs are skipped by design — `grep whisper: /var/ossec/logs/integrations.log`
shows `skip reason=non-global`, and no alert is produced.

---

## Sources

* **Original source:** the upstream Whisper–Wazuh project, from which this integration is packaged —
  <https://github.com/whisper-sec/whisper-wazuh> (full documentation, installers, and the keyed
  agent-activity tier).
* **Adapted by:** Whisper Security.
* **Licence:** this copy is contributed under this repository's licence (AGPL-3.0), like every other
  integration here. The upstream project is MIT-licensed.
* **Tested versions:** Wazuh **4.14.5**; the Whisper graph API (`graph.whisper.online`).
* **Maintainer:** Whisper Security (`security@whisper.security`).
* **Support boundary:** **Vendor-maintained**, best-effort via the upstream repository's issues;
  provided as-is. API keys and tiers for the keyed features: <https://www.whisper.security/pricing>.