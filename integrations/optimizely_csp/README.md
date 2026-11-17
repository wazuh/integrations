# Optimizely campaign CSP detection for Wazuh

## Table of Contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Installation and Configuration](#installation-and-configuration)
- [Integration Steps](#integration-steps)
- [Integration Testing](#integration-testing)
- [Containment](#containment)
- [Sources](#sources)

## Introduction

Rule 100980 alerts at level 10 when a Content Security Policy (CSP) violation identifies a domain or subdomain listed in Report URI's 16 November 2026 Optimizely Web Experimentation investigation. It uses Wazuh's JSON decoder and tags the incident context with ATT&CK T1195.002 (Compromise Software Supply Chain).

`enforce` indicates a browser-reported block under an enforced policy. `report` indicates a report-only violation and provides no evidence of a block. Investigate either signal alongside other telemetry. An alert alone cannot establish that a payload ran or that information left the browser.

## Prerequisites

- Wazuh 4.x manager and, if collecting on another host, an agent with access to the normalized log.
- An existing CSP report collector that can export JSON request bodies or run a transformation. The normalizer accepts legacy `csp-report` objects and Reporting API batches of `csp-violation` records.
- jq 1.7 or compatible. Fixture replay also requires Python 3 and, for offline pattern checks, ripgrep with PCRE2.

## Installation and Configuration

### Initial CSP collector configuration

Send browser CSP reports to a collector you control using your site's reporting configuration. Export the JSON body of each request. Apply the supplied jq filter in the collector's export pipeline. Keep access to the raw reports restricted because they can include URLs and page content. Treat reports from a public collector as untrusted and correlate them with independent telemetry before escalation.

### Using the integration files

1. Check that rule ID `100980` is available on your manager. Copy `ruleset/rules/optimizely_csp_rules.xml` into `/var/ossec/etc/rules/` and confirm the manager loads that rule directory.
2. Create a restricted log file at `/var/log/optimizely-csp.jsonl` on the collecting host and give the local Wazuh service read access. Add this block inside that host's `<ossec_config>`.

   ```xml
   <localfile>
     <location>/var/log/optimizely-csp.jsonl</location>
     <log_format>json</log_format>
   </localfile>
   ```

3. Run `sudo /var/ossec/bin/wazuh-analysisd -t` on the manager and replay the fixtures as described below. Restart the manager after installing the rule. Restart the agent if the collection configuration was added there.

## Integration Steps

For a collector exporting raw JSON bodies to a file, run the following on a fresh batch. For continuous ingestion, apply the same filter to each incoming batch and append its output to the configured log.

```sh
jq -c -f normalize-csp.jq /path/to/exported-csp-bodies.jsonl >> /var/log/optimizely-csp.jsonl
```

The filter emits one line per qualifying report with a destination hostname, disposition and effective directive. It drops inline/eval and other non-HTTP(S) destinations, as well as missing or unknown dispositions. It lowercases hostnames and strips a terminal DNS dot. Rule 100980 matches the host itself or a subdomain on a DNS label boundary.

Search for `rule.id:100980` in Threat Hunting or inspect the manager's `/var/ossec/logs/alerts/alerts.json`. Review the disposition and directive first. Correlate the timestamp and hostname with DNS, secure web gateway, and any available browser or script-integrity telemetry. The normalized log omits the page URL, so use the collector's records if you need it.

Ordinary CDN fetches and payload execution with no matching CSP violation are outside this signal's visibility. Reports may also be missing because of browser support, network delivery, or collector retention. Review the 12 domains against incident intelligence before reusing the list for future campaigns.

## Integration Testing

```sh
xmllint --noout ruleset/rules/optimizely_csp_rules.xml
python3 tests/check.py
sudo python3 tests/check.py --logtest /var/ossec/bin/wazuh-logtest
```

The fixtures represent enforced and report-only policies, routine Optimizely CDN traffic, hostname look-alikes, a domain in a URL path, ambiguous authority, an eval violation, and an unknown disposition. The runner restores defanged fixture hostnames locally for string matching. It makes no requests to those hosts.

XML validation passed, and all nine fixtures passed in both offline and manager-backed checks. The lab used the `wazuh/wazuh-manager:4.14.10` image, which reported Wazuh 4.14.10 and revision `rc2`. Logtest decoded the six emitted events as JSON. Both positives matched rule `100980` at level 10, four controls did not match the campaign rule, and the normalizer discarded three inputs.

The fixture export also passed through the running manager's JSON file input. The manager wrote exactly two campaign alerts to `alerts.json`, one per disposition. The lab exercised the pipeline from exported JSON bodies onward. Browser delivery to a production CSP collector requires separate verification.

To reproduce the manager checks and inspect the two actual alert records, run the disposable lab with Docker, Python 3 and jq:

```sh
bash tests/run-lab.sh
```

[Recorded manager output](tests/manager-results.txt) includes version information, positive and negative logtest cases, and selected fields from the live alerts.

## Containment

1. For sites you control, verify project and experiment script history with Optimizely. If exposure is suspected, temporarily disable the affected snippet on sensitive pages until you confirm a clean version, including cached and self-hosted copies. Preserve evidence and invalidate affected sessions where exposure is suspected.
2. Apply an enforced CSP with narrowly scoped script, outbound connection, and frame destinations. Test dependencies before rollout and remove `'unsafe-eval'` where possible. Review whether `'strict-dynamic'` allows trusted snippets to load arbitrary scripts. A CDN allowlist alone could not stop the compromised snippet.
3. Block the confirmed campaign domains and their subdomains at managed DNS or the secure web gateway. Look back from at least 16 November 2026 04:21 UTC through 23:11 UTC, the observed Optimizely injection and cleanup window, and widen it based on your own logs. Destination blocks cannot undo exposure or stop in-page actions such as address substitution.
4. If payment or authentication pages were exposed, use your incident-response process to scope affected sessions and transactions and coordinate with the relevant teams. Wazuh supplies an alert for investigation. The browser and gateway controls provide enforcement.

## Sources

- [Report URI incident analysis and published indicators](https://report-uri.ghost.io/worlds-largest-brands-infected-with-malware-via-optimizely/#indicators-of-compromise)
- [Optimizely vendor incident status](https://status.optimizely.com/)
- [Wazuh custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [Wazuh logtest](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
- [CSP Level 3 specification](https://www.w3.org/TR/CSP3/)
- [ATT&CK T1195.002](https://attack.mitre.org/techniques/T1195/002/)

### Provenance and maintenance

- **Original source.** Report URI published the domain indicators. The Wazuh rule, normalization filter and test fixtures were written for this integration.
- **Adapted by.** Prepared for the SAMsploit1 contribution with Codex.
- **Tested versions.** Wazuh manager image 4.14.10 (reported revision `rc2`), jq 1.7 and 1.7.1, and PCRE2 10.45.
- **Maintainer.** SAMsploit1.
- **Support boundary.** Community-maintained content, provided as-is.
