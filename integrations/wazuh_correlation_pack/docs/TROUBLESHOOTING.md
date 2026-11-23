# Troubleshooting

Start with `python -m wcp preflight`: it checks connectivity, the Alerting plugin, the field
mappings each correlation needs, and whether matching events exist.

| Symptom | Likely cause | Check / fix |
|---|---|---|
| `preflight`: `no index matches wazuh-events-v5-system-activity-*` | Wazuh 5.0.0-rc1 writes events to a data stream named exactly `wazuh-events-v5-system-activity`; a `-*` suffix pattern matches nothing. | Use the data stream name (the shipped default). `GET _data_stream/wazuh-events-v5-*` lists them. |
| `preflight`: `field event.code is not mapped` (Windows correlations) | No Windows event has been indexed yet; the events template maps fields on first use (`dynamic: strict_allow_templates`). | Expected before the first Windows event. Collect Windows Security events, then re-run `preflight`. |
| `preflight`: `0 matching event(s)` | Source not collected, stock integration disabled, or a decoder/version mismatch. | Look for the raw events in Discover: `wazuh.integration.name: system-auth` (SSH) or `event.code: 4625` (Windows). On Linux agents check the `localfile` configuration (the 5.0.0-rc1 agent collects `journald` by default). |
| Monitor deployed but never alerts | Too few events in one window/group; event time outside the lookback; monitor disabled. | `python -m wcp execute` runs the deployed monitor once (dry run) and prints each group's score and window. Compare with the threshold. |
| `search_phase_execution_exception ... "original" is null` | A scripted_metric parameter was `null` (OpenSearch rejects null params). | Fixed in the pack (empty string sentinels). If you edit the Painless, never pass `null` params. |
| `apply` wants to create monitors that already exist | Monitors lost their ownership marker and are not in this target's manifest. | The marker lives in `inputs[0].search.query.aggregations.wcp_groups.meta.wcp`. Monitors edited in the dashboard's visual editor can lose it. Delete the copies (they are named `[wcp] ...`) or restore the manifest, then re-run `plan`. |
| Alerts stay ACTIVE minutes after the attack stopped | Expected: an alert completes when no qualifying set remains in the lookback (`window + allowed_lateness + interval`, 5 min for brute force; observed 276-321 s after a burst). | Lower `allowed_lateness` if your pipeline delay allows it. |
| Attack during an indexer outage alerted late or not at all | Events are buffered by the manager and indexed after recovery; if the delay exceeds the lookback they are not counted. | Increase `allowed_lateness` (costs a longer resolution delay). |
| Count higher than the number of attempts | The same log is collected twice (e.g. `journald` and `/var/log/auth.log` both configured), or a file was re-read. | The pack does not collapse identical content; remove the duplicate `localfile`. |
| Windows burst/spray never alerts for console/RDP-without-IP logons | 4625 events with `IpAddress` = `-` have no `source.ip`; correlations grouped by `source.ip` skip them. | By design (see README limitations). |
| Indexer killed / unavailable on small lab VMs | Out of memory (the indexer heap is fixed at ~1 GB plus off-heap). | Keep test containers memory-capped, add swap, or use a larger VM. |
| Alerts API / Alerting > Alerts shows nothing for a group that alerted earlier | On 5.0.0-rc1 `plugins.alerting.alert_history_enabled` defaults to `false`: a COMPLETED alert is deleted (observed; `alertState=COMPLETED` and `ALL` return nothing). | Expected after resolution. Enable alert history (cluster setting, operator decision) to keep resolved alerts; with history enabled they are moved to a history index (OpenSearch behaviour, not tested here). |

## Inspecting a monitor

```bash
python -m wcp status                 # deployed monitors, active alerts and their groups
python -m wcp execute --only wcp_ssh_bruteforce   # dry-run the deployed monitor now
python -m wcp render --out /tmp/m    # the exact monitor bodies the pack would deploy
```
