# Wazuh Correlation Pack - Wazuh 5.x Integration

This pack adds four threshold detections for SSH and Windows authentication failures in Wazuh 5.x.
It creates scheduled Alerting monitors that count events or distinct target accounts over a defined
time window.

> **Tested versions.** The current version was tested on one Wazuh 5.0.0-rc2 lab. Earlier versions
> were tested on 5.0.0-rc1. Later release candidates and the final 5.0 release have not been tested.
> See [Integration Testing](#integration-testing).

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Installing the pack](#installing-the-pack)
    * [Initial pack configuration](#initial-pack-configuration)
    * [Installing Wazuh (if applicable)](#installing-wazuh-if-applicable)
    * [Initial Wazuh Configuration (if applicable)](#initial-wazuh-configuration-if-applicable)
    * [Using the Integration Files](#using-the-integration-files)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Detections](#detections)
* [Known limitations and differences from 4.x](#known-limitations-and-differences-from-4x)
* [Removal and recovery](#removal-and-recovery)
* [Provenance and maintenance](#provenance-and-maintenance)
* [Sources](#sources)

---

### Introduction

Wazuh 4.x rules could alert when another rule matched several times in a short period, for example
SSH brute force (rules 5712 and 5763). Wazuh 5.x detection rules are Sigma rules that look at one
event at a time, so they cannot express these thresholds. The Wazuh migration guide suggests an
Alerting bucket-level monitor instead. This pack provides four of them:

| Monitor | Raises an alert when |
|---|---|
| `wcp_ssh_bruteforce` | 8 or more failed SSH passwords within 2 minutes |
| `wcp_ssh_password_spray` | 5 or more distinct user names in failed SSH logins within 10 minutes |
| `wcp_windows_failed_logon_burst` | 10 or more failed Windows logons (event 4625) within 2 minutes |
| `wcp_windows_password_spray` | 5 or more distinct failed Windows target accounts within 10 minutes |

Each monitor counts per endpoint (agent) and source IP.

**Where alerts appear.** Alerts appear in **Alerting > Alerts** in the Wazuh dashboard, one per
endpoint and source IP. They are not Wazuh findings, and they do not trigger active responses. You
can send them to a Notifications channel.

The pack contains Sigma rules (`rules/`, `correlations/`) and a small Python tool,
`python3 -m wcp`, that turns each correlation into a monitor. The tool creates, updates and removes
only the pack's own monitors.

---

### Prerequisites

* A Wazuh 5.0.0-rc2 server (manager, indexer and dashboard). The indexer must include the
  `wazuh-indexer-alerting` plugin, which the standard installation includes.
* The stock Wazuh decoders. The pack adds no decoders.
* For SSH: Linux endpoints whose Wazuh agent collects sshd logs. The agent reads the systemd journal
  by default.
* For Windows: endpoints whose Wazuh agent collects the Security event log, with auditing of failed
  logons turned on.
* A machine with Python 3 that can reach the indexer REST API (port 9200). PyYAML is the only
  dependency. After an all-in-one installation the indexer listens only on 127.0.0.1. In that case,
  run the tool on the server or through an SSH tunnel
  ([docs/CONFIGURATION.md](docs/CONFIGURATION.md#connection-and-credentials)).
* An indexer user that can manage Alerting monitors and read `wazuh-events-v5-system-activity`. See
  [docs/CONFIGURATION.md](docs/CONFIGURATION.md#permissions) for the permission list.

---

### Installation and Configuration

#### Installing the pack

Install the tool in a Python virtual environment:

```bash
git clone https://github.com/wazuh/integrations.git
cd integrations/integrations/wazuh_correlation_pack
python3 -m venv ~/.venvs/wazuh-correlation-pack
. ~/.venvs/wazuh-correlation-pack/bin/activate
python -m pip install -r requirements.txt
python -m wcp validate    # checks the rules offline
```

Activate the environment again in each new shell before you run `python -m wcp`. Run the tool from
the pack directory.

#### Initial pack configuration

Put the indexer credentials in a file outside the repository. Never put them in `pack.yml`.

```bash
mkdir -p ~/.config/wazuh_correlation_pack
chmod 700 ~/.config/wazuh_correlation_pack
cat > ~/.config/wazuh_correlation_pack/indexer.env <<'EOF'
WCP_INDEXER_URL=https://127.0.0.1:9200
WCP_INDEXER_USER=<user>
WCP_INDEXER_PASSWORD=<password>
WCP_CA_CERT=/path/to/root-ca.pem
EOF
chmod 600 ~/.config/wazuh_correlation_pack/indexer.env
```

`root-ca.pem` is the indexer's public root certificate. On the server it is
`/etc/wazuh-indexer/certs/root-ca.pem`.

`pack.yml` sets the schedule, the allowed lateness, notifications and exclusions. Keep your own
changes in a separate file and pass it with `--override`:

```bash
python -m wcp --override site.yml plan
```

[docs/CONFIGURATION.md](docs/CONFIGURATION.md) describes every setting, notifications and the
override file.

#### Installing Wazuh (if applicable)

A standard Wazuh installation is assumed:
<https://documentation.wazuh.com/current/installation-guide/index.html>.

#### Initial Wazuh Configuration (if applicable)

* **Linux:** no change is needed if the agent already collects sshd logs. Collect each log only
  once. For example, do not collect both the journal and `/var/log/auth.log`.
* **Windows:** turn on auditing of failed logons, and make sure the agent collects the Security
  event log.
* **Recommended:** set the cluster setting `plugins.alerting.alert_history_enabled` to `true`.
  Otherwise an alert is deleted when it ends, and resolved alerts disappear from Alerting > Alerts.
  The pack does not change cluster settings. `preflight` shows the current value.

#### Using the Integration Files

| Path | Contents |
|---|---|
| `rules/` | Sigma base rules: which events are counted. |
| `correlations/` | Sigma correlation rules: what is counted, the grouping, the window and the threshold. |
| `pack.yml` | Indices, schedule, allowed lateness and notifications. |
| `wcp/` | The deployment tool. |
| `expected/monitors/` | The monitors the tool creates, for review. |
| `samples/`, `tests/`, `evidence/` | Sample logs, tests and recorded test results. |
| `docs/` | Architecture, configuration, testing and troubleshooting. |

Deploy the monitors:

```bash
python -m wcp preflight   # checks the connection, plugin, field mappings and matching events
python -m wcp plan        # shows what would change; changes nothing
python -m wcp apply       # creates or updates the pack's monitors; safe to run again
python -m wcp status      # lists the pack's monitors and their active alerts
```

No Wazuh service restart is needed.

To update the pack, get the new version and run `plan` and `apply` again. Only changed monitors are
updated. Monitors of correlations that were removed from the pack are deleted, unless you pass
`--no-prune`. Monitors that the pack did not create are never changed.

---

### Integration Steps

```
sshd log / Windows Security log
  -> Wazuh agent
  -> Wazuh manager, stock decoders
  -> wazuh-events-v5-system-activity (data stream)
  -> Alerting bucket-level monitor, every minute     [this pack]
  -> one alert per group in Alerting > Alerts        [optional notification]
```

Every minute, each monitor reads the recent matching events and groups them by agent and source IP.
For each group it finds the highest count within any period of the window length (2 or 10 minutes,
measured on event time). It raises an alert for each group that reaches the threshold.

Example: an alert of `[wcp] SSH brute force ...` has the bucket keys `001, 10.231.40.118` (agent ID
and source IP). Its bucket shows the score (`wcp_detail.score`, the number of attempts in the
busiest window), the window start and end, and the agent name.

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) explains the design and the timing.

---

### Integration Testing

#### Quick check after deployment

1. Run `python -m wcp status`. All four monitors show `in_sync=True`.
2. From a test machine, make at least 8 failed SSH password attempts within two minutes against a
   Linux endpoint that runs the agent. Use a test account, never a real administrative account. The
   command below opens three connections. Each one asks for a password three times. Type a wrong
   password every time.
   ```bash
   for i in 1 2 3; do ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password \
     -o NumberOfPasswordPrompts=3 test-account@<endpoint>; done
   ```
3. Within about a minute, **Alerting > Alerts** shows an alert of `[wcp] SSH brute force - ...` with
   the bucket keys `<agent id>, <your IP>`. `python -m wcp status` lists the same group as active.

If nothing appears, see [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

#### Validation on 5.0.0-rc2

The current version was tested in one lab in November 2026: an all-in-one 5.0.0-rc2 server, one
Ubuntu 22.04 agent and one Windows Server 2019 agent. The results below were recorded on the
development branch before publication. The published runtime code, rules and monitors are identical
to the tested ones. [evidence/README.md](evidence/README.md) shows the comparison.

| Test | Result |
|---|---|
| Unit tests (68) and test-harness self-tests (48), from a clean checkout | PASS |
| Monitor queries through the Alerting `_execute` API, 26 cases | PASS 26/26 |
| Windows account identity, 18 scenarios sent through the agent | PASS 134/134 checks |
| SSH and Windows scenarios replayed through the agent | PASS 51/51 and 16/16 checks |
| Decoding of a real, sanitized 4625 capture | PASS |
| Real failed logons collected from the Windows agent (SMB, RDP, local) | PASS |
| Live SSH burst against the monitored endpoint | PASS |
| Lateness against the real Alerting scheduler, 24 cases | PASS 24/24 |
| Install, update, rollback, removal and reinstall | PASS |
| Install and scheduled run by a user with only the documented permissions | PASS |
| Notifications through a webhook | PASS |
| Disabling and re-enabling a monitor; one indexer restart | PASS, with detection gaps (see limitations) |
| `bf_different_endpoints`, `spray_split_endpoints` (need two monitored Linux endpoints) | **deferred** |

The two deferred scenarios check that activity on two different Linux endpoints is not added
together. They passed on 5.0.0-rc1 with an earlier version of the pack (25e52cc). They were not run
on 5.0.0-rc2, because that lab had one Linux endpoint.

More detail:

* [docs/TESTING.md](docs/TESTING.md#recorded-results): which revision each result comes from, the
  individual SSH scenarios, the 5.0.0-rc1 results and the history of the Windows identity rule.
* [docs/VALIDATION_TESTS.md](docs/VALIDATION_TESTS.md): the 5.0.0-rc2 validation tests and how to
  run them.
* [evidence/README.md](evidence/README.md): the recorded runs.

---

### Detections

#### What is counted

* **SSH:** one event per rejected password (`Failed password` or `Failed keyboard-interactive/pam`
  from sshd). One failed password produces several log lines, but only one of them is counted.
  Failed public-key logins are not counted.
* **Windows:** one event per failed logon (event 4625 from the Security log).

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#counting-units-and-duplicates) explains why the pack
counts attempts and not log lines.

#### Grouping

All four monitors group events by agent ID (`wazuh.agent.id`) and source IP (`source.ip`). Activity
on different endpoints, or from different addresses, is never added together. Events without a
source IP are not counted, for example a Windows console logon.

The SSH spray monitor counts distinct `user.name` values on one endpoint.

**Windows accounts.** The Windows spray monitor counts distinct failed target accounts. The pack
builds each account as `domain\user`, in lower case, from the failed target's fields only:

* the user is `user.target.name`;
* the domain is `user.target.domain` when it is set and is not `-`;
* the domain `.` means the local computer, so the pack uses the first label of `host.name`;
* otherwise the domain is unknown, and the account is `?\user`.

The domain of the reporting subject (`user.domain`) is never used. For network logons such as SMB
and RDP, the stock decoders do not set `user.target.domain`, so these accounts have an unknown
domain. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#windows-account-identity) shows the decoded
fields.

**The Windows count is conservative.** In each window, every account with a known domain counts
once. An account with an unknown domain, `?\name`, counts only if no known-domain account with the
same user name is in the window. The pack cannot tell whether `?\bob` and `contoso\bob` are the same
account, so it assumes they are. The count can therefore be lower than the real number of accounts.

| Situation | Result |
|---|---|
| Same user name, different known domains (`CONTOSO\bob`, `FABRIKAM\bob`) | two accounts |
| Different user names, in any domain | different accounts |
| Different letter case (`CONTOSO\Bob`, `contoso\bob`) | one account |
| `.\admin` and `HOST\admin` on the same computer | one account |
| The same failed target with and without a reporting subject (`contoso\bob`, `?\bob`) | one account |
| Same user name in different domains, without a reporting subject (SMB, RDP) | one account, `?\name` |
| A `.` domain without a reporting subject | `?\name`, not the computer |
| A different account with an unknown domain and the same user name as a known-domain account | merged into the known-domain account |
| NetBIOS and DNS names of one domain (`CONTOSO`, `contoso.local`) | two accounts |

This counting fixes the over-count found on 5.0.0-rc2, where one account seen as both
`contoso\bob` and `?\bob` was counted twice. It does not fix the NetBIOS and DNS case above.

#### Timing

The window is measured on the event's own time (`event.start`), not on the indexing time. It is
never widened: eight SSH attempts spread over exactly 2 minutes do not alert.

Each run reads a longer lookback (window + allowed lateness + interval, for example 5 minutes for
SSH brute force). Events that become searchable up to 2 minutes after their event time (the default
allowed lateness) are still counted, as long as the monitor runs on schedule. An alert stays active
while a qualifying set of events remains within the lookback. After a short SSH brute-force burst,
the alert ends about 5 minutes later.

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#timing-model) has the timing calculations and the
measured behaviour.

---

### Known limitations and differences from 4.x

* **Tested versions.** Only 5.0.0-rc2 (current version, one lab) and 5.0.0-rc1 (earlier versions)
  were tested. Later releases may change field names, index names or Alerting defaults. Run
  `preflight` before relying on the pack.
* **Windows account counting** is conservative and can count fewer accounts than there really are.
  The NetBIOS and DNS names of one domain count as two accounts. See [Grouping](#grouping).
* **Duplicate records.** The pack does not remove duplicate log records. If the same record is
  collected twice, it becomes two events. This inflates event counts (SSH brute force, Windows
  burst). It does not inflate a distinct count (both spray monitors), because a repeated user name
  or account is counted once per window. Avoid collecting the same log twice.
* **Not specific to RDP.** The stock decoders do not expose the 4625 logon type. The Windows monitors
  detect failed logons in general.
* **Spraying scope.** The spray monitors look at one source against one endpoint. They do not detect
  spraying from many sources, spraying spread over several endpoints, or slow spraying below the
  threshold.
* **Missed runs are not caught up.** Runs skipped while a monitor is disabled, or while the indexer
  restarts, are lost. Activity that was within the lookback only during those runs is never
  detected. Re-enabling a monitor during an active alert creates a second alert for the same group.
* **Silent permission loss.** If the monitor's user loses read access to the events, scheduled runs
  report no error. New activity is not counted, and an existing alert stays ACTIVE. The error shows
  only in a dry run (`python -m wcp execute`). Check the monitors after changing permissions.
* **Notification restrictions.** By default, the Notifications plugin blocks webhooks to loopback,
  link-local, private (RFC 1918) and TEST-NET addresses (`opensearch.notifications.core.http.host_deny_list`). An
  administrator must change that list before a webhook to an internal receiver can work.
* **Late events.** Events that become searchable after the lookback has passed are not counted, for
  example after a long indexer outage.
* **Clock.** SSH event time comes from the endpoint's syslog timestamp. Only endpoints running in UTC
  were tested.
* **Manual edits.** The next `apply` overwrites manual changes to a pack monitor when the pack
  content changes. Editing a monitor in the dashboard can remove its ownership marker.

The 5.0.0-rc2 behaviour above was observed with alert history off, which is the default.
[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) lists symptoms and fixes.

**Differences from 4.x frequency rules** (documented 4.x behaviour; no 4.x system was tested):

| Wazuh 4.x | This pack |
|---|---|
| Evaluated by the manager as events arrive. | Evaluated by the indexer every minute. On the 5.0.0-rc1 test server, alerts appeared 20-36 s after the last attempt. |
| `timeframe` uses the time the manager received the event. | The window uses the event's own time. |
| `frequency` often counts several log lines per attempt. | Counts one event per attempt. |
| The result is a rule match that can trigger active response. | The result is an Alerting alert. No Wazuh finding, no active response. |

---

### Removal and recovery

```bash
python -m wcp remove          # lists the pack's monitors; changes nothing
python -m wcp remove --yes    # deletes them and their active alerts
python -m wcp rollback --yes  # alternatively, returns to the previously applied version
```

The pack creates only Alerting monitors. It creates no indices, detectors, decoders, notification
channels or cluster settings, so removing the monitors removes the pack completely. Without the
tool, delete the monitors whose names start with `[wcp]` in Alerting > Monitors.

---

### Provenance and maintenance

| Item | Details |
|---|---|
| Original source | The bucket-level monitor approach of the Wazuh rule migration guide (wazuh/wazuh repository, section "Alerting on repeated events"), and the frequency-rule monitor generator of the Wazuh ruleset migration tool, wazuh/integrations PR #134 (`rmig/translate/recipes.py`, AGPL-3.0, Copyright Wazuh Inc.). Both are linked under [Sources](#sources). |
| What was reused | The monitor structure (a bucket-level monitor whose `composite` aggregation plays the role of `same_*`, with a `bucket_selector` trigger on a range relative to `{{period_end}}`) and the mapping of `same_*` options to WCS fields. No code was copied. |
| What was changed | Counts one event per attempt instead of findings. Uses an exact sliding window on event time instead of a fixed range widened to 5 minutes. Adds a separate lateness setting and exact distinct counts. Groups by agent ID instead of agent name. Defines detections as Sigma correlation rules. Adds a deployment tool with ownership markers, update, removal and rollback. Adds tests. |
| Samples | Windows 4625 events from sans-blue-team/DeepBlueCLI (GPL-3.0), sanitized; see `samples/windows/README.md` and `NOTICE`. SSH lines captured on the test endpoints. |
| Adapted by | Olalekan Ajani |
| Tested versions | **Wazuh 5.0.0-rc2**: an all-in-one server on Ubuntu 24.04.5, with wazuh-agent 5.0.0-rc2 on Ubuntu 22.04.5 (OpenSSH 8.9p1) and on Windows Server 2019. **Wazuh 5.0.0-rc1** (earlier versions): manager, indexer and dashboard 5.0.0-rc1 with OpenSearch 3.6.0, and wazuh-agent 5.0.0-rc1 on Ubuntu 22.04.5. **Client**: Python 3.12.3 with PyYAML 6.0.2 and 6.0.4, and Python 3.10.12 with PyYAML 5.4.1. **Not tested**: later release candidates and the final 5.0 release. Details: [evidence/README.md](evidence/README.md). |
| Maintainer | Olalekan Ajani |
| Support boundary | Community-maintained. Provided as is, without warranty, under the repository license (AGPL-3.0). Not supported by Wazuh Inc. Report problems as issues in wazuh/integrations and mention `wazuh_correlation_pack`. |
| Retirement | Intended to be replaced by native Sigma correlation in the Security Analytics plugin (wazuh/wazuh-indexer-security-analytics#119). The files in `rules/` and `correlations/` and the test scenarios can be reused there. |

---

### Sources

* Wazuh rule migration guide 4.x to 5.x (bucket-level monitors, index layout, WCS field mapping):
  <https://github.com/wazuh/wazuh/blob/main/docs/guide/migration/rules-4x-to-5x.md>
* Native Sigma correlation support (tracking issue):
  <https://github.com/wazuh/wazuh-indexer-security-analytics/issues/119>
* Wazuh ruleset migration tool, frequency-rule monitors (wazuh/integrations PR #134):
  <https://github.com/wazuh/integrations/pull/134>
* Sigma correlation rules specification:
  <https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html>
* OpenSearch Alerting, bucket-level monitors and API:
  <https://docs.opensearch.org/latest/observing-your-data/alerting/monitors/>,
  <https://docs.opensearch.org/latest/observing-your-data/alerting/api/>
* OpenSearch scripted metric and cardinality aggregations:
  <https://docs.opensearch.org/latest/aggregations/metric/scripted-metric/>,
  <https://docs.opensearch.org/latest/aggregations/metric/cardinality/>
* Windows event 4625:
  <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625>
* Windows sample capture: <https://github.com/sans-blue-team/DeepBlueCLI> (GPL-3.0)
