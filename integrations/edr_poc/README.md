# EDR PoC-Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Rules and Decoders](#rules-and-decoders)
    * [Windows Active Response](#windows-active-response)
    * [Linux Active Response and YARA](#linux-active-response-and-yara)
    * [Ransomware Simulation](#ransomware-simulation)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)
* [Provenance and Maintenance](#provenance-and-maintenance)

---

## Introduction

This directory contains the rules, decoders, active response scripts and lab files for five endpoint detection and response use cases with Wazuh:

| Use case | Rules file | Rule IDs | Active response |
|---|---|---|---|
| Shared | `edr_00_common.xml` | 109001-109002 | Alerts on the result of `kill-process.exe` |
| 1. Credential dumping | `edr_01_credential_dumping.xml` | 101001-101003 | `kill-process.exe` |
| 2. Ransomware behavior | `edr_02_ransomware.xml` | 102001-102005, 102010-102011 | `kill-process.exe` |
| 3. Malware detection | `local_rules_uc3_malware.xml` | 100092-100093, 100200-100203, 100300-100301, 108000-108001 | `remove-threat.exe`, `remove-threat.sh`, `yara.sh` |
| 4. Persistence | `edr_05_persistence.xml` | 105001-105006, 105101-105105 | None |
| 5. Brute force and lateral movement | `edr_06_bruteforce_lateral.xml` | 106010-106050 | Built-in `firewall-drop` and `netsh` |

The file names of use cases 4 and 5 follow their rule ID ranges (105xxx and 106xxx). The files are intended for an isolated lab.

## Prerequisites

* Wazuh manager and agents 4.14.x.
* Windows agent with Sysmon, the `Microsoft-Windows-Sysmon/Operational` channel collected by the agent, and the audit policies for logon and account management events.
* Linux agent with `jq` and `yara`.
* A VirusTotal API key for use case 3.

## Installation and Configuration

### Rules and Decoders

Copy the `edr_*.xml` files in `ruleset/rules/` to `/var/ossec/etc/rules/` on the manager. Append the content of `local_rules_uc3_malware.xml` to `/var/ossec/etc/rules/local_rules.xml` and the content of `ruleset/decoders/local_decoder_uc3_yara.xml` to `/var/ossec/etc/decoders/local_decoder.xml`.

```
sudo chown wazuh:wazuh /var/ossec/etc/rules/edr_*.xml
sudo chmod 660 /var/ossec/etc/rules/edr_*.xml
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

`edr_06_bruteforce_lateral.xml` treats `192.168.122.1` as the only approved RDP source. Replace it with the approved sources of your environment. Rule IDs can overlap with other custom rules; if they do, change them in the rules and in the `rules_id` of the active response blocks.

The manager `ossec.conf` must define these commands and active responses:

| Command | Executable | `extra_args` | Triggered by rules |
|---|---|---|---|
| `kill-source` | `kill-process.exe` | `sourceProcessId` | 92900, 101001 |
| `kill-parent` | `kill-process.exe` | `parentProcessId` | 102001-102005 |
| `remove-threat-win` | `remove-threat.exe` | - | 87105 |
| `remove-threat` | `remove-threat.sh` | - | 87105 |
| `yara_linux` | `yara.sh` | `-yara_path /usr/bin -yara_rules /opt/yara/rules/lab.yar` | 100300, 100301 |

The VirusTotal integration uses rules 100200-100203. All active responses use `<location>local</location>`.

### Windows Active Response

`kill-process.exe` and `remove-threat.exe` are built from `kill-process.py` and `remove-threat.py` with PyInstaller (`-F`) and Python 3.15. They are not code-signed. Download them to the agent in PowerShell as Administrator, check their SHA-256 hashes and restart the agent:

```
$base = 'https://raw.githubusercontent.com/wazuh/integrations/main/integrations/edr_poc'
$bin = 'C:\Program Files (x86)\ossec-agent\active-response\bin'
foreach ($f in 'kill-process.exe', 'remove-threat.exe') {
    Invoke-WebRequest "$base/active-response/windows/$f" -OutFile "$bin\$f"
    Get-FileHash "$bin\$f" -Algorithm SHA256
}
Restart-Service -Name wazuh
```

| File | SHA-256 |
|---|---|
| `kill-process.exe` | `8da3b4216e9e3ba2de4e186b32d112c08655f2f68fa55779bf2ebae491b848ab` |
| `remove-threat.exe` | `f87dadb97b81be12e141bce9d61400bfaa14e8372ee7695fc99bec8719e94b02` |

To build them from the sources instead, install Python 3 and run the following in the folder that contains the `.py` files. The hashes of your build will differ from the ones above.

```
pip install pyinstaller
pyinstaller -F kill-process.py
pyinstaller -F remove-threat.py
Copy-Item .\dist\*.exe 'C:\Program Files (x86)\ossec-agent\active-response\bin\' -Force
```

`kill-process.exe` terminates the process whose PID is in the Sysmon event field given in `extra_args`, and its child processes. It does not terminate the processes listed in `PROTECTED`. `remove-threat.exe` deletes the file reported in `data.virustotal.source.file`.

### Linux Active Response and YARA

```
BASE=https://raw.githubusercontent.com/wazuh/integrations/main/integrations/edr_poc
sudo mkdir -p /opt/yara/rules /opt/yara/malware
sudo curl -fsSL -o /opt/yara/rules/lab.yar $BASE/yara/lab.yar
for f in remove-threat.sh yara.sh; do sudo curl -fsSL -o /var/ossec/active-response/bin/$f $BASE/active-response/linux/$f; done
sudo chown root:wazuh /var/ossec/active-response/bin/remove-threat.sh /var/ossec/active-response/bin/yara.sh
sudo chmod 750 /var/ossec/active-response/bin/remove-threat.sh /var/ossec/active-response/bin/yara.sh
```

`lab.yar` contains two rules: the EICAR test file and scripts that pipe `curl` output to a shell. `yara.sh` scans the file reported by FIM and logs each match, and `remove-threat.sh` deletes the file reported by VirusTotal. FIM must monitor `/root` and `/opt/yara/malware` in real time.

### Ransomware Simulation

`simulation/ransom-sim.ps1` reproduces the behavior detected in use case 2. It deletes the volume shadow copies, disables boot recovery, waits 15 seconds, and then overwrites and renames the files in `C:\Users\Public\Documents\00_Finance_Backup`. With `-SkipInhibit`, it only changes the files. Run it only on a lab system, from `C:\Tools\`:

```
Invoke-WebRequest https://raw.githubusercontent.com/wazuh/integrations/main/integrations/edr_poc/simulation/ransom-sim.ps1 -OutFile C:\Tools\ransom-sim.ps1
powershell.exe -ExecutionPolicy Bypass -File C:\Tools\ransom-sim.ps1
```

The decoy folder must exist and be monitored by FIM in real time.

## Integration Steps

1. Sysmon, the Windows Security log, `auth.log` and FIM generate the events on the agents.
2. The custom rules match them, and the rules listed in the commands table trigger the active responses.
3. The scripts log their result in `active-responses.log` on the agent. Rules 109001-109002 report the result of `kill-process.exe`, rules 100092-100093 the result of `remove-threat`, and rule 108001 the YARA matches.

## Integration Testing

After a change to the active response configuration, wait about one minute before testing, so that the agents load the new configuration.

| Use case | Action | Expected rules |
|---|---|---|
| 1 | `Get-Process lsass \| Format-List *` in a separate PowerShell window | 101001, 109001 |
| 2 | `powershell.exe -ExecutionPolicy Bypass -File C:\Tools\ransom-sim.ps1` | 102001, 102004, 109001 |
| 2 | Same script with `-SkipInhibit` | 102010, 102011 |
| 3 | Download the EICAR test file to `C:\Users\Administrator\Downloads` or `/root` | 87105, 100092 |
| 3 | Download the EICAR test file to `/opt/yara/malware` | 108001 |

The active response result is also logged on the agent:

```
Get-Content 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log' -Tail 5
sudo tail -n 5 /var/ossec/logs/active-responses.log
```

## Sources

* [Custom active response scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html)
* [PoC: Detecting and removing malware using VirusTotal integration](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html)
* [PoC: Detecting malware using YARA integration](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-malware-yara-integration.html)

## Provenance and Maintenance

- **Tested versions**: Wazuh 4.14.9 manager and agents; Windows Server 2022 and Ubuntu Server 26.04 LTS agents.
- **Support boundary**: Provided as is, as a lab reference.
