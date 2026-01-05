# Capture Browser History events

## Description
This project enables the collection of browser history events from Google Chrome and Microsoft Edge on Windows endpoints and forwards them to Wazuh for monitoring and alerting.

Both Chrome and Edge are Chromium-based browsers and store browsing history in an SQLite database named History within the user’s profile directory. The provided PowerShell scripts safely extract this data—even while the browser is running—and export it in NDJSON (newline-delimited JSON) format for ingestion by Wazuh.

##### Browser History Database Locations

Chrome: ```%LOCALAPPDATA%\Google\Chrome\User Data\Default\History```

Edge : ```%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History```

To extract browser history data, the following components are required:

1. PowerShell – for scripting and automation
2. SQLite – to query the browser’s History database. You can download the SQLite package from here: Download SQLite from: https://sqlite.org/download.html

## Implementation

1. First, create a folder ```C:\wazuhlogs```, and copy the attached PowerShell scripts (```chrome_once.ps1 and edge_once.ps1```) there. This script will periodically copy each browser’s History DB (so it works while the browser is open), read new visits, convert timestamps to readable times, and append them to a JSON log.

2. You need to update the PowerShell configuration script as required, Change the variables:
```
$BaseDir : Where you want to save the output file (Chrome config), $OutDir (edge config)
$SQLite :  Path of sqlite3

# SAMPLE CONFIGURATION
$BaseDir = "C:\WazuhLogs\Exporting-Chrome-Browser-History-to-Wazuh-Windows--main"
$SQLite  = "C:\sqlite\sqlite3.exe"
$TmpDir  = Join-Path $env:TEMP "chrome_hist_export"
$StateDir = "C:\Users\Public\state\chrome"
$MaxRows  = 200000
$ProfileRegex = '^(Default|Profile \d+)$'
$RetentionDays = 1  # Delete logs older than 1 day
```
3. Now add the ```<wodle name="command">``` to trigger the script automatically with ```<interval>```.The script will create  multiple ndjson files in $BASEDIR / $OUTDIR directory. we need to update the ```C:\Program Files (x86)\ossec-agent\ossec.conf``` file to read the file .ndjson files, to monitor local files.

```

<localfile>
    <location>C:\wazuhlogs\Exporting-Edge-Browser-History-to-Wazuh-Windows\*.ndjson</location>
    <!-- Here location is same as $basedir or $outdir -->
    <log_format>json</log_format>
</localfile>

  <localfile>
    <location>C:\wazuhlogs\Exporting-Chrome-Browser-History-to-Wazuh-Windows--main\*.ndjson</location>
    <!-- Here location is same as $basedir or $outdir -->
    <log_format>json</log_format>
</localfile>

<wodle name="command">
    <disabled>no</disabled>
    <interval>60</interval> <!-- every 1 minutes -->
    <command>powershell.exe -ExecutionPolicy Bypass -File C:\wazuhlogs\chrome_once.ps1 -AllUsers</command>
    <run_on_start>yes</run_on_start>
    <ignore_output>no</ignore_output>
    <timeout>60</timeout>
</wodle>

<wodle name="command">
    <disabled>no</disabled>
    <interval>60</interval> <!-- every 1 minutes -->
    <command>powershell.exe -ExecutionPolicy Bypass -File C:\wazuhlogs\edge_once.ps1 -AllUsers</command>
    <run_on_start>yes</run_on_start>
    <ignore_output>no</ignore_output>
    <timeout>60</timeout>
</wodle>
```

4. Add the below rule to ```/var/ossec/etc/rules/local_rules.xml``` file on Wazuh maanger or create the new file here. The description you can change accordingly. We can create child rules based on the clients requirement.

```
<!-- Modify it at your will. -->
<group name="chrome_history">
  <rule id="100011" level="9">
    <decoded_as>json</decoded_as>
    <field name="title">\S+</field>
    <description>Browser History $(url)</description>
  </rule>
</group>
```
5. Now restart your wazuh manager and agent to apply changes.

## Sample output

#### History alerts from Chrome:
<img width="1919" height="835" alt="image" src="https://github.com/user-attachments/assets/ebca8f34-651d-4150-a140-5a2fd3d00106" />

#### History alerts from Edge:
<img width="1919" height="800" alt="image" src="https://github.com/user-attachments/assets/50558be4-622d-465a-9840-c28237ba6512" />

## References
https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html#wodle-name-command
https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/monitoring-log-files.html
https://medium.com/@shehryartalat41/exporting-chrome-browser-history-to-wazuh-windows-a-fast-incremental-ndjson-pipeline-785817ef85df

