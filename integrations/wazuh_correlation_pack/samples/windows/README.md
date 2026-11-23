# Windows samples

## `4625_smb_bruteforce.sanitized.xml.log`

20 Security events 4625 ("An account failed to log on"), one event per line:
`EvtRender(EvtRenderEventXml)` output, single-quoted attributes, no `RenderingInfo`, CR/LF
removed. According to the Wazuh 5.0 agent source (`src/logcollector/src/read_win_event_channel.c`)
this is the form the Windows agent sends; that was **not verified with a running Windows agent**.
It is the form the stock decoder `decoder/windows-event/0` reads from `event.original`.

* **Origin**: real capture `evtx/smb-password-guessing-security.evtx` from
  [sans-blue-team/DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) (GPL-3.0),
  an SMB password-guessing attack recorded on 2016-09-19 (3,561 events 4625, LogonType 3,
  NTLM, one source IP, 3,560 against `Administrator`). The first 20 events are kept.
* **Conversion**: `wevtutil qe <file> /lf:true /f:xml` (the same Windows rendering call the
  agent uses), then one event per line.
* **Sanitization**: source IP `192.168.198.149` -> `203.0.113.149` (TEST-NET-3), computer name
  -> `WCP-WIN-SAMPLE`. Nothing else was changed.

## Derived test events

`tests/lab/lab.py:win_4625_line` produces test events from the first sample event, replacing
only `TimeCreated`, `EventRecordID`, `Computer`, `TargetUserName`, `IpAddress` and `IpPort`.
The derived events are used for the burst and spraying scenarios (the public capture has only
two distinct user names, so a spraying sample is necessarily derived).

**Limits of this validation.** These events are replayed through a Linux test agent's
logcollector (`/var/log/wcp-replay/replay.log`). This proves that the stock Wazuh 5.0.0-rc1 engine
decodes them and that the monitors count them; it does **not** prove collection from a real
Windows endpoint's EventChannel. No Windows endpoint was available for testing.
