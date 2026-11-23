# Wazuh Correlation Pack - Wazuh 5.x Integration

This pack adds four threshold detections for SSH and Windows authentication failures in Wazuh 5.x.
It creates scheduled Alerting monitors that count events or distinct target accounts over a defined
time window.

> **Tested versions.** The current version was tested on one Wazuh 5.0.0-rc2 lab. Earlier versions
> were tested on 5.0.0-rc1. Later release candidates and the final 5.0 release have not been tested.
> Two scenarios that need two monitored Linux endpoints were deferred. See
> [Integration Testing](#integration-testing) for details and [evidence/README.md](evidence/README.md)
> for the recorded results.

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

Wazuh 4.x could raise an alert when a rule matched several times in a short period, for example
rules 5712 and 5763 for SSH brute force. These rules used `frequency`, `timeframe` and `same_*`
options. Wazuh 5.x detection rules are Sigma rules that look at one event at a time, so they cannot
express these thresholds. The Wazuh migration guide suggests a bucket-level monitor of the indexer's
Alerting plugin instead. This pack provides those monitors.

| Monitor | Raises an alert when | Grouped by |
|---|---|---|
| `wcp_ssh_bruteforce` | 8 or more failed SSH password attempts within 2 minutes | agent and source IP |
| `wcp_ssh_password_spray` | 5 or more distinct user names in failed SSH attempts within 10 minutes | agent and source IP |
| `wcp_windows_failed_logon_burst` | 10 or more Windows 4625 events (failed logon) within 2 minutes | agent and source IP |
| `wcp_windows_password_spray` | 5 or more distinct failed target accounts within 10 minutes | agent and source IP |

The pack contains:

* **Sigma rules** in `rules/` and `correlations/`. They use Wazuh Common Schema (WCS) fields. They
  do not depend on the Alerting plugin, so they can be reused when Wazuh supports Sigma
  correlation natively (wazuh/wazuh-indexer-security-analytics#119).
* **A deployment tool**, `python3 -m wcp`. It turns each correlation into one Alerting monitor and
  creates, updates or removes only the pack's own monitors.
* **Tests and recorded results** in `tests/` and `evidence/`.

The result of a detection is an alert in **Alerting > Alerts**, one per group (agent and source
IP). The pack does not create Wazuh findings and does not trigger active responses.

---

### Prerequisites

* A Wazuh server (manager, indexer and dashboard) running 5.0.0-rc2, with OpenSearch 3.6.0 and the
  `wazuh-indexer-alerting` plugin. Version 5.0.0-rc1 was used for earlier versions of the pack.
  Other 5.x versions have not been tested.
* The stock Wazuh decoders. The pack adds no decoders. SSH events use the `system-auth`
  integration and Windows events use the `windows` integration.
* For SSH: Linux endpoints whose agent collects sshd logs. The agent reads the systemd journal by
  default. This was tested with OpenSSH 8.9p1.
* For Windows: endpoints whose agent collects the Security event log, with failed-logon auditing
  turned on. This was tested with a Windows Server 2019 agent.
* A machine with Python 3 and PyYAML that can reach the indexer REST API on port 9200. PyYAML is the
  only dependency. Tested with Python 3.12.3 and PyYAML 6.0.2 on Windows 11, and with Python
  3.10.12 and PyYAML 5.4.1 on Ubuntu 22.04. If the indexer listens only on 127.0.0.1, which is the
  case after an all-in-one installation, run the tool on the server or through an SSH tunnel.
* An indexer user that can manage Alerting monitors and read `wazuh-events-v5-system-activity`.
  [docs/CONFIGURATION.md](docs/CONFIGURATION.md#permissions) lists the permissions. A user with only
  those permissions could install the pack and run it on schedule on 5.0.0-rc2. Whether the list is
  minimal was not checked. Removal and rollback by such a user were not tested.

---

### Installation and Configuration

#### Installing the pack

```bash
git clone https://github.com/wazuh/integrations.git
cd integrations/integrations/wazuh_correlation_pack
python3 -m pip install --user PyYAML
python3 -m wcp validate          # checks all rules offline
```

#### Initial pack configuration

Put the indexer credentials in a file outside the repository. Never put them in `pack.yml`.

```bash
mkdir -p ~/.config/wazuh_correlation_pack && chmod 700 ~/.config/wazuh_correlation_pack
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

The schedule, allowed lateness, notifications and exclusions are set in `pack.yml`. To keep local
changes separate, put them in your own file and pass it with `--override`, for example
`python3 -m wcp --override site.yml plan`. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

#### Installing Wazuh (if applicable)

A standard Wazuh installation is assumed:
<https://documentation.wazuh.com/current/installation-guide/index.html>. The test servers were
all-in-one installations: 5.0.0-rc1 installed with the installation assistant, and 5.0.0-rc2 on
Ubuntu 24.04.5.

#### Initial Wazuh Configuration (if applicable)

* **Linux:** no change is needed if sshd logs reach the agent. Do not collect the same log twice,
  for example through both the journal and `/var/log/auth.log`. Every attempt would then be counted
  twice.
* **Windows:** turn on auditing of failed logons and make sure the agent collects the Security
  event log.
* **Recommended:** set the cluster setting `plugins.alerting.alert_history_enabled` to `true`. On
  5.0.0-rc1 it is `false` by default. Alerts are then deleted when they end, so a resolved alert
  disappears from Alerting > Alerts. The pack does not change cluster settings. `preflight` shows
  the current value.

#### Using the Integration Files

| Path | Contents |
|---|---|
| `rules/*.yml` | Sigma base rules: which events are counted. |
| `correlations/*.yml` | Sigma correlation rules: what is counted, per group, in which window, and the threshold. |
| `pack.yml` | Indices, schedule, allowed lateness and notifications. |
| `wcp/` | The deployment tool (`python3 -m wcp`). |
| `expected/monitors/` | The monitors the tool creates, for review. |
| `samples/` | Sanitized sample logs and where they came from. |
| `tests/` | Unit, API and pipeline tests. `tests/lab/` describes the test lab. |
| `evidence/` | Recorded test results. |
| `docs/` | Architecture, configuration, testing and troubleshooting. |

Deploy the monitors:

```bash
python3 -m wcp preflight   # checks the connection, plugin, field mappings and matching events
python3 -m wcp plan        # shows what would be created, updated or deleted; changes nothing
python3 -m wcp apply       # creates or updates the pack's monitors; safe to run again
python3 -m wcp status      # lists the deployed monitors and their active alerts
```

No Wazuh service restart is needed. The monitors are created through the Alerting API.

To update, get the new version of the pack and run `plan` and `apply` again. Only monitors that
changed are updated. Monitors of correlations that were removed from the pack are deleted unless
you pass `--no-prune`. Monitors that the pack did not create are never touched.

---

### Integration Steps

```
sshd log / Windows Security log
  -> wazuh-agent                                     [stock]
  -> wazuh-manager, stock decoders                   [stock: system-auth, windows]
  -> wazuh-events-v5-system-activity (data stream)   [stock]
  -> Alerting bucket-level monitor, every minute     [this pack]
  -> one alert per group in Alerting > Alerts        [optional notification channel]
```

Every minute, each monitor:

1. reads the matching events whose event time (`event.start`) falls in its lookback period. The
   lookback is the window plus the allowed lateness plus the interval, for example 2 + 2 + 1
   minutes for SSH brute force;
2. groups the events by agent and source IP;
3. finds, for each group, the largest number of events or distinct accounts within any period of
   exactly the window length;
4. raises an alert for each group that reaches the threshold, or keeps an existing alert active.

Example: an alert of monitor `[wcp] SSH brute force ...` has the bucket keys
`001, 10.231.40.118` (agent ID and source IP). The bucket shows `wcp_detail.score` (the number of
attempts in the busiest window), `window_start` and `window_end` (epoch milliseconds),
`events_in_lookback` and the agent name.

Design details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

### Integration Testing

#### Quick check after deployment

1. Run `python3 -m wcp status`. All four monitors show `in_sync=True`.
2. From a test machine, make at least 8 failed SSH password attempts within two minutes against a
   Linux endpoint that runs the agent. Use a test account, never a real administrative account.
   The command below opens three connections, and each one asks for a password three times. Type a
   wrong password every time.
   ```bash
   for i in 1 2 3; do ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password \
     -o NumberOfPasswordPrompts=3 test-account@<endpoint>; done
   ```
3. Within about a minute, **Alerting > Alerts** shows an alert of monitor
   `[wcp] SSH brute force - ...`. Its bucket keys are `<agent id>, <your IP>` and its severity is 2.
   `python3 -m wcp status` lists the same group under `active`.
4. In Discover, on `wazuh-events-v5-system-activity`, the attempts are the documents with
   `event.reason: "Failed password"` and your `source.ip`.

#### Recorded results

[evidence/README.md](evidence/README.md) indexes all recorded runs. It also shows how the
contributed files match the code that was tested and which values were sanitized. The revision IDs
below are commits of the development branch, which is not part of this contribution. The
contributed runtime code, rules and monitors are identical to the tested ones. The only exception is
one documentation comment in `wcp/identity.py`. [docs/TESTING.md](docs/TESTING.md) and
[tests/lab/README.md](tests/lab/README.md) explain how to run the tests.

**Current version on 5.0.0-rc2** (one lab: an all-in-one server, one Ubuntu 22.04 agent and one
Windows Server 2019 agent; November 2026). The Windows password spraying monitor was retested after
its last change (detection revision 6ee2300, `evidence/2026-11-23-rc2-mixed-realm/`). All other
results come from candidate 5c1da90 (`evidence/2026-11-22-rc2-candidate/`). That candidate differs
only in how the Windows spray monitor counts accounts, and the other three monitors are
byte-identical.

| Test | Result |
|---|---|
| Unit tests (68) and test-harness self-tests (48), from a clean checkout | PASS |
| Monitor queries through the Alerting `_execute` API, 26 cases | PASS 26/26 |
| Windows account identity, 18 scenarios with 91 events sent through the agent | PASS 134/134 checks |
| SSH scenarios replayed through the agent | PASS 51/51 checks (16 scenarios) |
| Windows scenarios replayed through the agent | PASS 16/16 checks |
| Decoding of a real, sanitized 4625 capture by the stock pipeline | PASS |
| Real failed logons collected from the Windows agent (SMB, RDP, local logons) | PASS |
| Live SSH burst against the monitored endpoint | PASS |
| Lateness against the real Alerting scheduler, 24 cases | PASS 24/24 |
| Install, update, rollback, removal and reinstall on the cluster | PASS |
| Install and scheduled run by a user with only the documented permissions | PASS |
| Delivery of notifications through a webhook | PASS |
| Disabling and re-enabling a monitor; one indexer restart | PASS, with detection gaps (see limitations) |
| `bf_different_endpoints`, `spray_split_endpoints` (need two monitored Linux endpoints) | deferred |

Before the last change, the Windows spray monitor counted one account twice when it appeared in
both decoded forms. Three real accounts scored 6 and raised a false alert. That failing run is kept
as `evidence/2026-11-23-rc2-mixed-realm/api_monitor_execute_df2ae18_before_fix.json`. An earlier
5.0.0-rc2 run of revision 38ad481 found a different defect in the Windows account identity. It is
kept in `evidence/2026-11-22-rc2/`.

**Earlier versions on 5.0.0-rc1** (historical). On 2026-11-21, revision 25e52cc passed the unit,
API, deployment, live SSH and replay tests (`evidence/2026-11-21-rc1/`). Permissions, notifications
and collection from a Windows agent were not tested on 5.0.0-rc1. Revision 105573d passed the unit,
API and scheduler tests (`evidence/2026-11-22-rc1-105573d/`). The current Windows identity and
counting rules were not tested on 5.0.0-rc1.

SSH brute-force scenarios (threshold: 8 attempts within 2 minutes per agent and source):

| Scenario (replayed unless noted) | Input | Expected | Observed |
|---|---|---|---|
| live burst | 9 real attempts in 28 s | alert, score 9 | alert, score 9 |
| below threshold | 7 attempts in 60 s | no alert | no alert |
| at threshold | 8 attempts in 70 s | alert, score 8 | alert, score 8 |
| above threshold | 12 attempts in 55 s | alert, score 12 | alert, score 12 |
| span equal to the window | 8 attempts, first and last 120 s apart | no alert | no alert |
| span shorter than the window | 8 attempts within 119 s | alert, score 8 | alert, score 8 |
| split beyond the window | 4 + 4 attempts, 150 s apart | no alert | no alert |
| different sources | 5 + 5 attempts from two IPs | no alert | no alert |
| different endpoints | 5 + 5 attempts on two agents | no alert | no alert (5.0.0-rc1 only) |
| log lines versus attempts | 5 attempts with an unknown user: 25 log lines | no alert | no alert |
| the same records collected twice | 4 records, each written twice | alert, score 8 (known limitation) | alert, score 8 |
| late, within the lookback | 8 attempts searchable 143-150 s after their event time | alert | alert |
| late, beyond the lookback | 8 attempts searchable 423-430 s after their event time | no alert | no alert |

On the 5.0.0-rc1 server, a live attempt was searchable 14.5 s after it happened. Alerts appeared
19.6 s and 35.5 s after the last attempt of two bursts.

---

### Detections

Each correlation in `correlations/` refers to a base rule in `rules/`.

#### What is counted

| Base rule | Selection (stock WCS fields) | One event means |
|---|---|---|
| `wcp_ssh_failed_password_attempt` | `process.name` is sshd, sshd-session or sshd-auth, and `event.reason` is `Failed password` or `Failed keyboard-interactive/pam` | one rejected SSH password |
| `wcp_windows_failed_logon` | `event.code` is `4625` and `event.dataset` is `security` | one failed Windows logon |

**SSH attempts, not log lines.** One failed SSH password produces several sshd and PAM log lines.
The stock decoder marks several of them as `event.action: authentication-failure`:

| Activity | sshd lines | `authentication-failure` events | Counted by the pack |
|---|---|---|---|
| 1 attempt, unknown user | 5 | 3 | 1 |
| 1 attempt, existing user | 3 | 2 | 1 |
| 3 attempts, existing user, one connection | 6 | 5 | 3 |

Counting `authentication-failure` events would reach a threshold of 8 after only 3 to 5 attempts.
The pack counts `Failed <method>` lines instead, because sshd writes exactly one per rejected
password. Failed public-key logins (`Failed publickey`) and `Failed none` are not password guessing,
so they are not counted.

#### Grouping

All four monitors group events by agent ID (`wazuh.agent.id`) and source IP (`source.ip`). Activity
on different endpoints, or from different addresses, is never added together. Events without a
source IP are not counted. An example is a Windows console logon, where `IpAddress` is `-`.

The SSH spray monitor counts distinct `user.name` values. Linux accounts belong to one host, and the
host is already part of the group.

**Windows accounts.** A Windows account is a domain (or computer) plus a user name. The pack derives
`domain\user` in lower case from the failed target's fields only:

* the user is `user.target.name`;
* the domain is `user.target.domain` when it is set and is not `-`;
* the domain `.` means the reporting computer, so the pack uses the first label of `host.name`;
* otherwise the domain is unknown and the pack writes `?\user`.

The pack never uses `user.domain`. The stock decoder puts the target's domain in `user.domain` only
when the event has no reporting subject. When a subject is present, `user.domain` holds the
subject's domain. One case cannot be told apart from the other: a subject name with the null SID and
no target domain. A monitor cannot read the raw event to check, because `event.original` is not
indexed.

| Field of the decoded 4625 event | No reporting subject (network logons such as SMB, RDP) | Reporting subject present (for example local logons) |
|---|---|---|
| `user.target.name` | TargetUserName | TargetUserName |
| `user.target.domain` | not set | TargetDomainName |
| `user.domain` | TargetDomainName | SubjectDomainName (the subject's domain) |

**Windows spray counting is conservative.** In each window, every account with a known domain
counts once. An account with an unknown domain, `?\name`, counts only if no account with a known
domain and the same user name appears in the window. The pack cannot tell whether `?\bob` and
`contoso\bob` are the same account, so it assumes they are. As a result, accounts with an unknown
domain that share a user name may be merged, with each other or with a known-domain account. The
count can then be lower than the real number of accounts.

This rule fixes the over-count found on 5.0.0-rc2. One failed target that appeared in both decoded
forms (`contoso\bob` and `?\bob`) was counted twice, so three real accounts scored 6. The rule does
not remove other causes of over-counting. The NetBIOS and DNS names of one domain still count as two
accounts, and a log record collected twice is still counted twice.

| Situation | Result |
|---|---|
| Same user name, different known domains (`CONTOSO\bob`, `FABRIKAM\bob`) | two accounts |
| Different user names, in any domain | always different accounts |
| Different letter case (`CONTOSO\Bob`, `contoso\bob`) | one account |
| `.\admin` and `HOST\admin` on the same computer | one account |
| The same failed target with and without a reporting subject (`contoso\bob`, `?\bob`) | one account |
| Same user name in different domains, without a reporting subject (SMB, RDP) | one account, `?\name` (domain lost) |
| A `.` domain without a reporting subject | `?\name`, not the computer |
| A different account with an unknown domain that shares a user name with a known-domain account | merged into the known-domain account |
| The reporting subject's domain | never used |
| NetBIOS and DNS names of one domain (`CONTOSO`, `contoso.local`) | two accounts |

The rules are defined in `wcp/identity.py`, and the counting script is `PAINLESS_REDUCE_UNKNOWN_REALM`
in `wcp/alerting.py`.

The identity rule changed over time. Revision 25e52cc counted user names only. Revision 105573d
added the domain, falling back to `user.domain` in some cases. On 5.0.0-rc2 that fallback took the
reporting subject's domain (`evidence/2026-11-22-rc2/`). The current rule has been tested on
5.0.0-rc2 only.

The tool can also group across agents, for example by source IP only. No shipped correlation does
this, and it was not tested.

#### Timing and alert lifecycle

| Setting | Brute force and burst | Spray |
|---|---|---|
| Window, measured on event time (`event.start`) | 2 minutes | 10 minutes |
| Monitor interval | 1 minute | 1 minute |
| Allowed lateness | 2 minutes | 2 minutes |
| Lookback read on each run | 5 minutes | 13 minutes |

The **window** decides whether activity is enough for an alert. For brute force, 8 events must lie
less than 120 s apart. The window is never widened. Eight attempts spread over exactly 120 s do not
alert, and neither do 4 + 4 attempts 150 s apart, even though all of them fall within the lookback.

The **lookback** decides which events each run reads. It sets how late an event can become
searchable and still count. It also sets how long an alert stays active: the alert stays active
while a qualifying set of events remains within the lookback.

Observed on 5.0.0-rc1:

* An alert appears at the first run after a qualifying set of events becomes searchable.
* While activity continues, the same alert stays active. Runs do not create new alerts.
* The alert ends at the first run where no qualifying set remains within the lookback. For a short
  burst this is about 5 minutes after the burst. Without alert history, the ended alert is deleted.
* New activity after that raises a new alert.

**Late events.** A qualifying set is counted if each event becomes searchable within the allowed
lateness (2 minutes) of its event time. This holds only when:

1. the monitor runs on schedule. Missed runs are not caught up;
2. the agent, manager and indexer deliver the event in time. All delays count towards the
   2 minutes;
3. the search finishes within `plugins.alerting.input_timeout` (30 s on 5.0.0-rc1), and the group
   has no more than `max_events_per_group` events in the lookback.

Two minutes is a guaranteed minimum, not a cut-off. With the 300 s lookback and a burst that lasts
`s` seconds, a delay of up to about `240 - s` seconds is always counted. Up to about `300 - s`
seconds is counted only when the events become searchable just before a run. Tests with the real
scheduler matched this: delays of 110-133 s were always counted, 264 s depended on timing, and
335 s was never counted. Events older than the lookback when they become searchable are never
counted.

An alert caused only by late events may stay active for a single run. Without alert history it then
disappears about a minute later, so configure a notification or enable alert history.

---

### Known limitations and differences from 4.x

* **Tested versions.** Tested on 5.0.0-rc2 (current version, one lab) and 5.0.0-rc1 (earlier
  versions). Later 5.x releases may change field names, index names or Alerting defaults. Run
  `preflight` and the tests before relying on the pack.
* **Not specific to RDP.** The stock decoder does not map the 4625 `LogonType` to any field. On
  5.0.0-rc2, failed RDP logons with Network Level Authentication were logged as type 3, the same as
  SMB. The Windows monitors therefore detect failed logons in general, not RDP attacks.
* **Windows account counting** is conservative and loses some domain information, as described
  under [Grouping](#grouping). The NetBIOS and DNS names of one domain count as two accounts.
* **Password spraying scope.** The spray monitors detect one source against one endpoint within 10
  minutes. They do not detect spraying from many sources, spraying spread over several endpoints
  (for example several domain controllers), or slow spraying below the threshold per window.
* **Duplicate log records are counted twice.** The pack does not remove duplicate source events. A
  record collected twice (for example by two `<localfile>` entries, or by reading a file again)
  becomes two events with different `wazuh.event.id` values. No stock field identifies one log
  record. The pack does not compare content, because real attempts can produce identical lines.
  The option `event_identity_field` skips repeated values of one field, but no stock 5.x field is
  suitable, so it is off. Avoid collecting the same log twice. Retransmission inside the Wazuh
  pipeline was not tested.
* **Alerts versus counts.** While a group keeps qualifying, Alerting keeps one active alert. With the
  default `notify_on: [NEW]` it notifies once. This affects alerts and notifications, not the count.
* **Behaviour of 5.0.0-rc2 observed in the tests** (with alert history off, the default):
  * If the monitor's user loses read access to the events, scheduled runs raise no error alert.
    The error appears only in a dry run (`python3 -m wcp execute`). New activity is not counted, and
    an active alert stays active. Check the monitors after changing permissions.
  * Disabling and re-enabling a monitor during an active alert creates a second active alert for
    the same group.
  * Runs that fall while a monitor is disabled, or while the indexer restarts, are skipped and never
    caught up. Activity that is within the lookback only during skipped runs is never counted.
  * The Notifications plugin blocks webhooks to loopback, link-local, private (RFC 1918) and TEST-NET
    addresses by default (`opensearch.notifications.core.http.host_deny_list`). An administrator
    must change that list before a webhook to an internal receiver can work.
* **Late events** older than the lookback when they become searchable are not counted, for example
  after a long indexer outage. `@timestamp` is the manager's processing time. The window uses
  `event.start`.
* **Clock and time zone.** SSH event time comes from the syslog timestamp on the endpoint. It has
  1-second resolution and no year or time zone. Only endpoints running in UTC were tested.
* **Scale.** Each run evaluates at most `max_events_per_group` (100000) events per group. Beyond
  that, the oldest events are ignored, which can only lower the count. Tested with up to 5000
  events in one group, and 300 through the full pipeline.
* **Manual edits.** Editing a pack monitor in the dashboard can remove its ownership marker. The
  next `apply` overwrites manual edits when the pack content changes.

#### Differences from 4.x frequency rules

This column describes documented 4.x behaviour. No 4.x system was tested.

| Wazuh 4.x | This pack |
|---|---|
| Evaluated by analysisd as events arrive, on each manager node. | Evaluated by the indexer every minute over indexed events. On the test server, alerts appeared 20-36 s after the last attempt. |
| `timeframe` uses the time the manager received the event. | The window uses the event's own time (`event.start`). Late events are handled explicitly. |
| `frequency` counts matches of a parent rule, often several lines per attempt. | Counts one event per attempt. |
| The result is a rule match with level, groups and MITRE data, and can trigger active response. | The result is an Alerting alert per group. No Wazuh finding, no active response. |
| `same_*` and `different_*` options. | `group-by` on any WCS field. `different_*` becomes a distinct count of one field. |
| `ignore` suppresses new alerts for a number of seconds. | One alert per group while active. Notifications only for new alerts by default. |

---

### Removal and recovery

```bash
python3 -m wcp remove          # lists the pack's monitors; changes nothing
python3 -m wcp remove --yes    # deletes them and their active alerts
python3 -m wcp rollback --yes  # alternatively, returns to the previously applied version
```

The pack creates only Alerting monitors, each marked with
`aggregations.wcp_groups.meta.wcp.pack = wazuh_correlation_pack`. It creates no indices, detectors,
decoders, notification channels or cluster settings, so removing the monitors removes the pack
completely. Without the tool, delete the monitors whose names start with `[wcp]` in
Alerting > Monitors.

---

### Provenance and maintenance

| Item | Details |
|---|---|
| Original source | The bucket-level monitor approach of the Wazuh rule migration guide (wazuh/wazuh repository, section "Alerting on repeated events"), and the frequency-rule monitor generator of the Wazuh ruleset migration tool, wazuh/integrations PR #134 (`rmig/translate/recipes.py`, AGPL-3.0, Copyright Wazuh Inc.). Both are linked under [Sources](#sources). |
| What was reused | The monitor structure (a bucket-level monitor whose `composite` aggregation plays the role of `same_*`, with a `bucket_selector` trigger on a range relative to `{{period_end}}`) and the mapping of `same_*` options to WCS fields. No code was copied. |
| What was changed | Counts one event per attempt instead of findings. Uses an exact sliding window on event time instead of a fixed range widened to 5 minutes. Adds a separate lateness setting and exact distinct counts. Groups by agent ID instead of agent name. Defines detections as Sigma correlation rules. Adds a deployment tool with ownership markers, update, removal and rollback. Adds tests. |
| Samples | Windows 4625 events from sans-blue-team/DeepBlueCLI (GPL-3.0), sanitized; see `samples/windows/README.md`. SSH lines captured on the test endpoints. |
| Adapted by | Olalekan Ajani |
| Tested versions | **Wazuh 5.0.0-rc2**: an all-in-one server on Ubuntu 24.04.5, with wazuh-agent 5.0.0-rc2 on Ubuntu 22.04.5 (OpenSSH 8.9p1) and on Windows Server 2019. The Windows spray monitor was tested at detection revision 6ee2300, and everything else at candidate 5c1da90. Two scenarios that need two Linux endpoints were deferred. **Wazuh 5.0.0-rc1** (earlier versions 25e52cc and 105573d): manager, indexer and dashboard 5.0.0-rc1 with OpenSearch 3.6.0, and wazuh-agent 5.0.0-rc1 on Ubuntu 22.04.5 (OpenSSH 8.9p1). **Client**: Python 3.12.3 with PyYAML 6.0.2 and 6.0.4. **Not tested**: later release candidates and the final 5.0 release. |
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
