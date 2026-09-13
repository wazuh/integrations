# Vestrix-Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
  * [Installing Vestrix](#installing-vestrix)
  * [Initial Vestrix Configuration](#initial-vestrix-configuration)
  * [Installing Wazuh](#installing-wazuh)
  * [Initial Wazuh Configuration](#initial-wazuh-configuration)
  * [Using the Integration Files](#using-the-integration-files)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Included and Omitted Components](#included-and-omitted-components)
* [Provenance and Maintenance](#provenance-and-maintenance)
* [Sources](#sources)

## Introduction

This integration decodes Vestrix JSON physical-security events and applies
Wazuh rules for high-confidence intrusion, missing PACS correlation, sensor
tampering, and a composite authentication-anomaly correlation.

## Prerequisites

* A Wazuh manager. Version 4.14.5 is the only version tested.
* Vestrix producing one-line JSON events containing `"source":"vestrix"`.
* Prevalidated `confidence_level` values from Vestrix.
* An upstream PACS enricher for rule `100202`, if missing-badge correlation is
  required.

Compatibility with earlier Wazuh 4.x versions is untested. Rules `100210` and
`100211` depend on Wazuh 4.14.5 built-in OpenSSH rule IDs `5712` and `5763`.

## Installation and Configuration

### Installing Vestrix

Install Vestrix using the instructions in the
[Vestrix repository](https://github.com/dev-rehaann/VESTRIX). This contribution
contains only the Wazuh decoder and rules; it does not install Vestrix or a log
transport.

### Initial Vestrix Configuration

Configure the Vestrix-to-Wazuh transport to deliver one mapped JSON object per
log record. Each record must contain `"source":"vestrix"`. The Wazuh rules
consume the mapped `confidence_level`; they do not calculate that value.

### Installing Wazuh

A standard Wazuh manager installation is sufficient. Follow the
[official installation guide](https://documentation.wazuh.com/current/installation-guide/index.html)
if Wazuh is not already installed.

### Initial Wazuh Configuration

Configure the manager's existing log collection path to receive the Vestrix
JSON records. No additional API key, Python dependency, or network listener is
provided by this ruleset-only integration.

### Using the Integration Files

From this integration directory, install the decoder and rules in Wazuh's
custom-content directories:

```console
sudo install -m 0640 ruleset/decoders/0585-vestrix_decoders.xml /var/ossec/etc/decoders/0585-vestrix_decoders.xml
sudo install -m 0640 ruleset/rules/1000-vestrix_rules.xml /var/ossec/etc/rules/1000-vestrix_rules.xml
sudo systemctl restart wazuh-manager
```

Preserve any existing local files and apply the owner and group used by other
files in those directories. The default Wazuh configuration loads custom XML
from these directories, so no additional `ossec.conf` entry is required.

## Integration Steps

1. Vestrix classifies a physical-security event and maps it to one JSON record.
2. The configured transport delivers that record to the Wazuh manager.
3. The `vestrix` decoder selects records whose `source` is `vestrix` and uses
   Wazuh's `JSON_Decoder` to extract fields.
4. Rule `100200` groups the event; child rules generate alerts for supported
   intrusion, PACS, tamper, and authentication-correlation conditions.

Example input:

```json
{"class":"intrusion","confidence":0.97,"confidence_level":"high","node_id":"node-07","site_id":"hq-karachi","source":"vestrix","zone_id":"server-room-west"}
```

The example selects decoder `vestrix` and alert rule `100201` at level 10.

## Integration Testing

After installing the XML files, verify the positive detection on the manager:

```console
printf '%s\n' '{"class":"intrusion","confidence":0.97,"confidence_level":"high","node_id":"node-07","site_id":"hq-karachi","source":"vestrix","zone_id":"server-room-west"}' | sudo /var/ossec/bin/wazuh-logtest -U 100201:10:vestrix
```

A successful run ends with `Unit test OK`. The
`ruleset/testing/test.ini` file also contains a positive detection, a negative
non-match, and a regression case for the JSON decoder-name collision.

For events delivered through the configured transport, inspect
`/var/ossec/logs/alerts/alerts.json` or the Wazuh dashboard's Security Events
view and confirm that the expected rule ID and level are present.

## Included and Omitted Components

* Rules and decoder: included.
* Active response: not applicable; alerting/logging only.
* SCA: not applicable to this physical-layer sensor integration.
* Threat intelligence: not currently provided or consumed.
* Dashboard: planned, not yet built.

## Provenance and Maintenance

* Original source: [Vestrix](https://github.com/dev-rehaann/VESTRIX).
* Adapted by: Vestrix contributors.
* Adaptation: packages the tested Vestrix decoder and rules for this repository;
  the decoder, rule, and test logic is unchanged.
* Tested versions: Wazuh 4.14.5 with the Vestrix submission package from
  [commit `fbfed6c`](https://github.com/dev-rehaann/VESTRIX/commit/fbfed6ce494cd06dfcdd2117ad7b9edf1388194a).
* Maintainer: Vestrix project maintainers.
* Support boundary: community-maintained through
  [Vestrix GitHub issues](https://github.com/dev-rehaann/VESTRIX/issues) and
  provided as-is.

## Sources

* [Wazuh integrations repository](https://github.com/wazuh/integrations)
* [Wazuh integrations contribution guide](https://github.com/wazuh/integrations/blob/main/CONTRIBUTING.md)
* [Wazuh custom decoder documentation](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/custom.html)
* [Wazuh custom rule documentation](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
