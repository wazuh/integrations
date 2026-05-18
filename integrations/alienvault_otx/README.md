# AlienVault OTX Integration with Wazuh

<img src="/integrations/alienvault_otx/images/2026-05-01_12-48.png" alt="Dashboard preview" width="800"/>

This integration enriches Wazuh alerts with threat intelligence from AlienVault OTX. For each alert that exceeds the configured severity threshold, the script extracts indicators of compromise (source/destination IPs, domains, SHA‑256 file hashes), queries the OTX `/general` endpoint for each one, and emits an enriched event back into the Wazuh pipeline carrying a per‑IOC verdict (`malicious` / `clean` / `unknown`) plus an overall verdict for the alert as a whole. Custom Wazuh rules then act on those verdicts to produce a tiered alert hierarchy. A bundled OpenSearch Dashboards saved‑objects bundle gives you a ready‑to‑use threat‑intelligence dashboard.

> **Note:** OTX is a community‑driven feed. Indicators on shared infrastructure (cloud‑hosted IPs, mail‑sender ranges, CDN endpoints) often return `clean` even when the underlying activity is malicious in your environment. This integration is best used alongside, not instead of, your other detection signals.


### Table of Contents
* [Prerequisites](#prerequisites)
  * [Obtaining an OTX API key](#obtaining-an-otx-api-key)
    * [Testing connection from Wazuh to AlienVault OTX](#testing-connection-from-wazuh-to-alienvault-otx)
* [AlienVault OTX‑Wazuh Integration](#alienvault-otxwazuh-integration)
  * [Integration Steps](#integration-steps)
    * [Step 1: Add the Python script and rules](#step-1-add-the-python-script-and-rules)
    * [Step 2: Configure the integration in Wazuh](#step-2-configure-the-integration-in-wazuh)
* [Integration Testing](#integration-testing)
  * [Sample test logs](#sample-test-logs)
  * [Check enriched alerts](#check-enriched-alerts)
* [Workflow](#workflow)
* [IOC Extraction](#ioc-extraction)
  * [Field sources covered out of the box](#field-sources-covered-out-of-the-box)
  * [Multi‑indicator handling](#multiindicator-handling)
  * [Sender‑domain filtering](#senderdomain-filtering)
  * [CrowdStrike `IOCValue` dispatch](#crowdstrike-iocvalue-dispatch)
* [Verdict Logic](#verdict-logic)
  * [OTX `validation` override](#otx-validation-override)
* [Custom Rules](#custom-rules)
* [Logging](#logging)
* [Dashboard](#dashboard)
* [Sources](#sources)

## Prerequisites

* `requests` Python library installed for the Wazuh runtime
* Network connectivity from Wazuh Manager to `https://otx.alienvault.com` (HTTPS)
* A free OTX account with API key

### Obtaining an OTX API key

* Sign up at <https://otx.alienvault.com/>
* Navigate to **Settings --> User Settings --> API Integration**
* Copy the OTX Key. It is a 64‑character hex string.

#### Testing connection from Wazuh to AlienVault OTX

From the Wazuh manager, replacing `<YOUR_OTX_KEY>` with your key:

```bash
curl -s -H "X-OTX-API-KEY: <YOUR_OTX_KEY>" \
  "https://otx.alienvault.com/api/v1/user/me" | jq .
```

A successful response returns your OTX user profile.



## AlienVault OTX‑Wazuh Integration

### Integration Steps

#### Step 1: Add the Python script and rules

<details>
<summary>Click to expand integration script configuration steps</summary>

* Place [the Python script](custom-alienvault.py) at `/var/ossec/integrations/custom-alienvault.py`
* Place [the bash wrapper](custom-alienvault) at `/var/ossec/integrations/custom-alienvault`
* Place [the custom rules](alienvault_otx_rules.xml) at `/var/ossec/etc/rules/alienvault_otx_rules.xml`

* Set permissions on the integration files:

```bash
cd /var/ossec/integrations/
sudo chown root:wazuh custom-alienvault* && sudo chmod 750 custom-alienvault*
sudo chown wazuh:wazuh /var/ossec/etc/rules/alienvault_otx_rules.xml
sudo chmod 640 /var/ossec/etc/rules/alienvault_otx_rules.xml
```

* Install the `requests` library into the Wazuh Python runtime:

```bash
/var/ossec/framework/python/bin/pip3 install requests
```

The script writes its log output to the standard Wazuh integrations log at `/var/ossec/logs/integrations.log`, which is already managed by the Wazuh manager - no additional log directory is needed.

</details>

#### Step 2: Configure the integration in Wazuh

<details>
<summary>Click to expand Wazuh integration configuration steps</summary>

Edit `/var/ossec/etc/ossec.conf` and add the integration block:

```xml
<integration>
  <name>custom-alienvault</name>
  <hook_url>https://otx.alienvault.com</hook_url>
  <api_key>YOUR_OTX_API_KEY</api_key>
  <alert_format>json</alert_format>
  <level>5</level>
</integration>
```

* **`hook_url`**: OTX base URL. No trailing slash.
* **`api_key`**: Your OTX API key.
* **`level`**: Minimum alert level for the integration to fire. Tune this to control OTX query volume and stay within rate limits.

Restart the Wazuh manager:

```bash
systemctl restart wazuh-manager
```

</details>



## Integration Testing

### Sample test logs

The repository ships a [sample log file](sample-logs.log) you can append to a Wazuh‑monitored log (for example `/var/log/auth.log` or any path declared via `<localfile>`) to generate alerts that contain known‑malicious indicators. OTX pulse contents change daily, so before relying on a specific IP/domain/hash for testing, verify it has pulses:

```bash
curl -s -H "X-OTX-API-KEY: $OTX_KEY" \
  "https://otx.alienvault.com/api/v1/indicators/IPv4/<IP>/general" | \
  jq '.pulse_info.count'
```

### Check enriched alerts

<details>
<summary>Click to expand event checking steps</summary>

* On the Wazuh dashboard, filter for `data.integration: alienvault_otx`
* Or tail the archives on the manager:

```bash
tail -f /var/ossec/logs/archives/archives.json | grep --line-buffered alienvault_otx | jq .
```

You should see events of the form:

```json
{
  "integration": "alienvault_otx",
  "original_rule": "5712",
  "input_alert": "1777630620.14970618",
  "overall_malicious": true,
  "overall_verdict": "malicious",
  "indicators": {
    "src_ip": {
      "value": "203.0.113.45",
      "malicious": true,
      "verdict": "malicious",
      "confidence": "high",
      "pulse_count": 12,
      "pulse_names": ["Emotet C2", "..."],
      "malware_families": ["Emotet"]
    }
  },
  "original_full_log": "Sep 1 12:34:56 host sshd[123]: Failed password..."
}
```

The `original_full_log` field preserves the raw log line from the source alert so analysts can pivot back to the original event without needing to correlate by alert ID. If preserving the full log is a storage concern in your environment (some `full_log` values can be 5-10 KB), the relevant line in `enrich_alert` is easy to truncate.

</details>



<div align="center">

## Workflow

```mermaid
graph TD
    A[Wazuh Manager] --> B[Invoke custom-alienvault.py]
    B --> C[Collect IOC candidates from alert]
    C --> D[Dedupe, filter private/invalid, cap at 3 per type]
    D --> E[Query OTX /general for each indicator]
    E --> F[Apply OTX validation whitelist check]
    F --> G[Evaluate verdict from pulse_count]
    G --> H[Select worst-verdict block per IOC type]
    H --> I[Build enriched event with original_full_log]
    I --> J[Send to Wazuh queue socket]
    J --> K[Custom rules fire]
```

</div>



## IOC Extraction

Field paths are declared centrally in `SUPPORTED_FIELD_PATHS` at the top of the script. To support a new log source, add the relevant dotted path under the matching IOC type - no other code change is required:

```python
SUPPORTED_FIELD_PATHS = {
    "src_ip": [
        "srcip",
        "data.srcip",
        "data.source_address",
        "data.aws.ClientIP",
        # add new field paths here ...
    ],
    "dst_ip":   [...],
    "domain":   [...],
    "file_hash":[...],
}
```

Additional safeguards before an indicator is sent to OTX:

* **IPs**: only globally‑routable addresses are queried. RFC1918 private space, loopback, link‑local, CGNAT, and reserved/multicast ranges are filtered out as they cannot meaningfully be looked up in a public threat‑intelligence feed.
* **Domains**: scheme/path/port/query are stripped, and the result is rejected if it parses as an IP, contains whitespace, or has no dot.
* **Hashes**: validated against a 64‑character hex pattern. MD5 and SHA‑1 are not extracted because OTX's `/file/` endpoint only resolves SHA‑256.

### Field sources covered out of the box

| Source | Fields |
|---|---|
| Generic Wazuh | `srcip`, `dstip`, `domain`, `data.source_address`, `data.destination_address`, `data.nat_source_ip`, `data.nat_destination_ip` |
| AWS CloudTrail / Wazuh AWS module | `data.aws.ClientIP`, `data.aws.source_ip_address`, `data.aws.sourceIPAddress`, `data.aws.destinationIPAddress` |
| Cloudflare module | `data.aws.ClientIP`, `data.aws.OriginIP` (shares the AWS module schema) |
| Wazuh DNS module | `data.Remote_IP` |
| Windows Sysmon | `data.win.eventdata.ipAddress`, `destinationIp`, `queryName`, `destinationHostname`, `Image`, `hashes` (parsed for SHA‑256) |
| Office 365 / Microsoft Graph | `data.office365.ClientIPAddress`, `ClientIP`, `SenderIp`, plus the structured `data.ms-graph.evidence[]` array (URLs and sender objects) |
| GCP / Azure | `data.gcp.jsonPayload.sourceIP`, `data.azure.properties.ipAddress` |
| Suricata / Zeek | `data.suricata.src_ip`, `data.suricata.dest_ip`, `data.suricata.dns.rrname`, `data.zeek.id_orig_h`, `data.zeek.id_resp_h` |
| Wazuh FIM | `syscheck.sha256_after` |
| VirusTotal integration | `data.virustotal.source.sha256` |
| Osquery | `data.osquery.columns.sha256` |
| CrowdStrike Falcon | `data.event.IOCValue` (dispatched on `IOCType`), `data.event.SHA256String`, `data.event.QuarantineFiles[].SHA256HashData` |

Sources whose data needs structural parsing - Sysmon's comma‑separated `hashes` string, MS Graph `evidence` arrays, CrowdStrike's `QuarantineFiles[]` array, the `IOCType`/`IOCValue` discriminated union - are handled by dedicated extractor functions rather than the path map.

### Multi‑indicator handling

A single Wazuh alert frequently contains multiple candidates for the same IOC type - for example, AWS CloudTrail records both `sourceIPAddress` and `ClientIP`, and a NAT‑traversing flow contributes both `srcip` and `nat_source_ip`. The script:

1. Walks **every** registered path for the IOC type and collects all values.
2. Deduplicates while preserving the path order, so the most authoritative field wins on ties.
3. Filters out RFC1918/loopback/etc. addresses, invalid domains, and non‑SHA‑256 hashes.
4. Caps the surviving candidates at `MAX_QUERIES_PER_TYPE = 3` to stay within OTX rate limits. Dropped values are logged with a `WARNING` naming the specific indicators that were not queried.
5. Queries OTX for every kept candidate and picks the **worst** verdict block as the value for that IOC type in the emitted event. Ranking is `(verdict_score, pulse_count)` where malicious > clean > unknown.

This means the alert shape stays identical to a single‑value enrichment (one block per IOC type), so existing dashboard panels and rules continue to work, but the enrichment itself is robust to alerts that happen to mention several IPs or hashes.

### Sender‑domain filtering

For alerts carrying email evidence (MS Graph `p1Sender` / `p2Sender`, Office 365 `SenderAddress`), the sender domain is only used as a domain IOC when:

* No structural domain (Sysmon `queryName`, URL evidence, etc.) was already found in the alert, **and**
* The sender domain is not in `MAIL_INFRASTRUCTURE_DOMAINS` - the built‑in skip list of major webmail providers (gmail.com, outlook.com, yahoo.com, protonmail.com, icloud.com, aol.com, and their regional variants).

The motivation is concrete: popular mail platforms accumulate OTX pulses because attackers abuse them as phishing lure hosts, but the domains themselves are not malicious infrastructure. Querying them produces false positives that flood the dashboard. Non‑webmail sender domains (e.g. `attacker@suspicious-domain.ru`) are still extracted and queried normally.

### CrowdStrike `IOCValue` dispatch

CrowdStrike's `DetectionSummaryEvent` carries IOCs through a discriminated union: `data.event.IOCValue` is type‑tagged by the sibling `data.event.IOCType` field. The script dispatches on `IOCType`:

| `IOCType` | Routed to |
|---|---|
| `hash_sha256`, `sha256` | `file_hash` |
| `domain` | `domain` |
| `ipv4`, `ipv6` | `dst_ip` (Falcon IOCs typically represent the externally‑observed peer) |
| anything else (`hash_md5`, `hash_sha1`, registry, etc.) | skipped (not OTX‑resolvable) |

If your CrowdStrike pulses tend to record inbound‑attacker IPs rather than outbound peers and you'd prefer `ipv4`/`ipv6` to land in `src_ip`, change one line in `_classify_crowdstrike_ioc`.



## Verdict Logic

For each indicator the script translates the OTX `pulse_info.count`, the number of community pulses referencing the indicator, into a verdict and a confidence tier:

| `pulse_count` | OTX `validation` | `verdict` | `confidence` |
|---|---|---|---|
| any | contains `whitelist`, `false_positive`, `majestic`, `alexa`, or `akamai` | `clean` | `high` |
| 0 | - | `clean` | `high` |
| 1 | - | `malicious` | `low` |
| 2–4 | - | `malicious` | `medium` |
| ≥ 5 | - | `malicious` | `high` |
| query failed / no response | - | `unknown` | `unknown` |

Two top‑level fields summarise the alert: `overall_malicious` (boolean) and `overall_verdict` (`malicious` / `clean` / `partial_unknown`). The first up to five non‑empty pulse names, adversary tags, and malware‑family names are also included to keep the enriched event compact while still actionable.

> **A note on the OTX `reputation` field.** The OTX API documents a `reputation` score on IPv4 indicators, but in practice it consistently returns `0` regardless of how malicious an indicator is, and the field is absent entirely from domain and file responses. This integration therefore keys verdicts solely on `pulse_info.count` and does not surface the reputation field in the enriched alert.

### OTX `validation` override

Some indicators legitimately have a non‑zero `pulse_count` but are explicitly marked by OTX as known‑good: popular domains like `google.com` or `gmail.com` show up in phishing pulses because attackers abuse them, not because the domains themselves are malicious. OTX exposes this in the response's `validation[]` array, with entries whose `source` field takes values like `whitelist`, `false_positive`, `majestic`, `alexa`, or `akamai`.

The script reads this array before evaluating the pulse count. If any entry's source is in `OTX_WHITELIST_VALIDATION_SOURCES`, the indicator is marked `verdict: clean, reason: otx_whitelist_validation` regardless of how many pulses reference it. The raw `pulse_count` is still included in the emitted block for transparency.



## Custom Rules

The bundled rules use IDs in the user range 100010–100024 and chain off the base rule:

| Rule ID | Level | Triggers when |
|---|---|---|
| 100010 / 100017 | 3 | Any AlienVault OTX enrichment event (base) |
| 100019 | 2 | All indicators in the event are clean |
| 100018 | 3 | Event dropped by Wazuh integrator (>60KB) |
| 100011 | 10 | Malicious file hash |
| 100014 | 10 | Malicious destination IP |
| 100015 | 10 | Malicious source IP |
| 100016 | 10 | Malicious domain |
| 100012 | 12 | Malicious file hash + destination IP |
| 100013 | 13 | Malicious file hash + destination IP + source IP |
| 100021–100024 | 12 | High‑confidence malicious indicator (5+ pulses) |



## Logging

The script logs to the standard Wazuh integrations log at `/var/ossec/logs/integrations.log`, alongside any other custom integrations on the same manager. Lines are prefixed with the service name so they can be filtered:

```bash
grep "custom-alienvault" /var/ossec/logs/integrations.log
```

Log format:

```
2026-05-13 11:36:53,385 [INFO] custom-alienvault: Starting; alert=/tmp/alert.json hook_url=https://otx.alienvault.com
2026-05-13 11:36:54,012 [WARNING] custom-alienvault: Capped src_ip at 3 of 4 candidates; dropped: ['13.14.15.16']
2026-05-13 11:36:55,890 [DEBUG] custom-alienvault: src_ip: queried 3 candidates (['1.1.1.1', '45.153.34.132', '176.65.139.134']), selecting worst verdict
```

## Dashboard

The repository ships a saved‑objects bundle, [`wazuh-otx-dashboard.ndjson`](wazuh-otx-dashboard.ndjson), with 14 visualisations and 1 dashboard scoped to `data.integration: alienvault_otx`. Once imported, you get a single‑pane view of all OTX enrichment activity:

| Row | Panels |
|---|---|
| 1 (metrics) | Total Enrichments · Malicious Events · Clean Events · Unique Malicious Source IPs |
| 2 | Overall Verdict Distribution (donut) · Verdict Timeline (stacked area) |
| 3 | Malicious Events by IOC Type (horizontal bar) · Top Adversaries (tag cloud) · Top Malware Families (tag cloud) |
| 4 | Top Malicious Source IPs (table) · Top Malicious Destination IPs (table) |
| 5 | Top Malicious Domains (table) · Top Malicious File Hashes (table) |
| 6 | Top Wazuh Rules Producing Enrichments (full‑width table) |

### Importing the dashboard

<details>
<summary>Click to expand dashboard import steps</summary>

1. Open the Wazuh dashboard in your browser.
2. Navigate to **Stack Management --> Saved Objects**.
3. Click **Import** in the upper‑right.
4. Select `wazuh-otx-dashboard.ndjson`.
5. Choose **Automatically overwrite all conflicts** (or **Request action on conflict** for a fresh import).
6. Click **Import**.
7. Open the **Dashboards** menu - the new dashboard appears as **AlienVault OTX | Threat Intelligence**.

If your index pattern saved‑object ID is anything other than the literal string `wazuh-alerts-*`, the importer will surface a conflicts dialog and let you remap each visualisation.

After the first import, refresh the field list once: **Stack Management --> Index Patterns --> wazuh-alerts-* --> refresh icon**. This ensures the new `data.indicators.*` fields are recognised by the visualisation aggregations.

</details>


### Notes on aggregation field types

The dashboard's IOC tables use **Top Hits** rather than **Max** for the `pulse_count` column. This is deliberate: Wazuh's default index template stores all `data.*` fields as `keyword`, including numeric‑looking strings like `pulse_count`. Top Hits works on any field type and avoids the "invalid for use with the Max aggregation" error that would otherwise appear. If you've customised your index template to give `pulse_count` an explicit `long` mapping, switching the column back to Max in the visualisation editor will give you a true per‑indicator maximum across the time window.



## Sources

<details>
<summary>Click to expand source references</summary>

* AlienVault OTX API reference: <https://otx.alienvault.com/api>
* Wazuh integrator documentation: <https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html>
* Wazuh ruleset rule syntax: <https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html>
* OpenSearch Dashboards saved‑objects API: <https://opensearch.org/docs/latest/dashboards/management/saved-objects/>
* CrowdStrike Falcon Streaming API event dictionary (for `IOCType` values): <https://falcon.crowdstrike.com/documentation>

</details>