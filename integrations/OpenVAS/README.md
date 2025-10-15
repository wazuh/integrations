Wazuh - OpenVAS Integration
Introduction
OpenVAS (part of the Greenbone Vulnerability Management suite) is an open-source vulnerability scanner that identifies security risks across systems and applications. Wazuh, on the other hand, is a Security Information and Event Management (SIEM) and XDR platform that centralises log collection, threat detection, and alerting.
Integrating OpenVAS with Wazuh allows:
Centralised vulnerability results inside the Wazuh dashboard
Continuous monitoring of assets against vulnerabilities
Correlation of OpenVAS alerts with endpoint and network events
For reliable integration, OpenVAS was deployed natively on Kali Linux instead of Docker, because:
Native installation ensures full access to PostgreSQL tables (results, nvts)
Easier control over file system paths and scripts
Better alignment with Wazuh wodles (command execution)

Deploying OpenVAS (Greenbone) on Kali Linux
 Update system
sudo apt update

Install OpenVAS 
sudo apt install openvas


sudo apt install gvm

Setup OpenVAS
sudo gvm-setup


Verify services

sudo gvm-check-setup


sudo systemctl status gvmd


sudo systemctl status gsad


Change the admin password

sudo gvmd --user=admin --new-password=Str0ng-password


Start the GVM

sudo gvm-start


Log in to Greenbone Security Assistant (Web UI)

Default URL: https://127.0.0.1:9392

Accessing OpenVAS Dashboard from External Systems

By default, the Greenbone Security Assistant Daemon (GSAD) only listens on 127.0.0.1 (localhost), which restricts access to the Kali machine itself.
To make the dashboard accessible from other systems on the network, follow these steps:
Edit GSAD service file
sudo nano /usr/lib/systemd/system/gsad.service




Modify the listen address

Reload systemd daemon
sudo systemctl daemon-reexec

Restart GSAD service
sudo systemctl restart gsad

Access externally
 From a remote system’s browser:
https://<kali-ip>:9392
Security note: For production, restrict access using a firewall or reverse proxy, rather than leaving GSAD open on all interfaces.
Data Extraction from OpenVAS Database
To extract vulnerability results, we use the internal PostgreSQL database where scan results are stored. The two main tables used are:
results → Stores scan findings (per host, per port).


nvts → Stores metadata about each Network Vulnerability Test (CVE, CVSS, OID, family).


The goal is to combine data from both tables into a single JSON output that Wazuh can ingest.
Bash Script: nano /var/ossec/bin/openvas_extract.sh
Create openvas directory under /opt
#!/bin/bash

# ===============================
# OpenVAS Combined JSON Export (Results + NVTS + Report Creation Time)
# ===============================

DB_NAME="gvmd"
DB_USER="_gvm"
OUTPUT_DIR="/opt/openvas"
SOCKET_DIR="/var/run/postgresql"
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/openvas_combined.json"

echo "Exporting combined results of nvts, results, and reports (creation time) to $OUTPUT_FILE ..."

# Start JSON array
echo "[" > "$OUTPUT_FILE"

# Stream combined JSON row by row
sudo -u _gvm psql -d "$DB_NAME" -h "$SOCKET_DIR" -t -A -F "" -c "
SELECT row_to_json(combined)
FROM (
    SELECT
        r.id AS result_id,
        r.report AS report_id,
        r.host,
        r.port,
        r.severity,
        r.description AS result_description,
        n.name AS nvt_name,
        n.oid AS nvt_oid,
        n.family AS nvt_family,
        n.cvss_base AS nvt_cvss_base,
        n.cve AS nvt_cve,
        rep.creation_time AS report_creation_epoch,
        to_timestamp(rep.creation_time) AS report_creation_time
    FROM results r
    LEFT JOIN nvts n ON r.nvt = n.oid
    LEFT JOIN reports rep ON r.report = rep.id
    ORDER BY r.report, r.host
) combined;" | awk 'NR>0 {print (NR==1?"":"") $0}' >> "$OUTPUT_FILE"

# End JSON array
echo "]" >> "$OUTPUT_FILE"

echo "Export completed. Combined JSON saved at $OUTPUT_FILE"


Script Explanation:
Database variables – Defines DB name (gvmd), user (_gvm), and socket directory.
Output directory & file – JSON file will be saved at /opt/openvas/openvas_combined.json.
Start JSON structure – Writes [ to begin a JSON array.
SQL Query –
Selects relevant fields from results (findings) and joins them with nvts (metadata).
Converts each row into JSON format using row_to_json.
awk formatting – Ensures rows are comma-separated inside JSON array.
Close JSON array – Writes ] at the end.
Output confirmation – Prints export location.
5. Automating with Wazuh (Wodle Configuration)
To ensure new OpenVAS results are ingested into Wazuh automatically, we use the command wodle in /var/ossec/etc/ossec.conf.
Example Configuration:
<wodle name="command">
  <disabled>no</disabled>
  <tag>openvas_export</tag>
  <command>/var/ossec/bin/openvas_extract.sh</command>
  <interval>1m</interval>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
  <ignore_output>no</ignore_output>
</wodle>



and set the configuration for the JSON file path /opt/openvas/openvas_combined.json 
<localfile>
    <log_format>json</log_format>
    <location>/opt/openvas/openvas_combined.json</location>
</localfile>

Restart the Wazuh-agent service
systemctl restart wazuh-agent

6. Now, create Rules for the CVE and Open Ports
Log in to Wazuh Manager and create a rule file:
nano /var/ossec/etc/rules/openvas_rules.xml

Add the following configurations:
<group name="openvas">
  <rule id="100767" level="5">
    <decoded_as>json</decoded_as>
    <field name="target_host">\.*</field>
    <field name="open_ports">\.*</field>
    <description>open port found $(open_ports)</description>
    <options>no_full_log</options>
  </rule>
<rule id="100766" level="5">
    <decoded_as>json</decoded_as>
    <field name="OVS_CVE">\.*</field>
    <description>CVE found $(OVS_CVE) with base score $(base_score)</description>
    <options>no_full_log</options>
  </rule>
</group>


7. Start the scan from the OpenVAS dashboard:
Log in to OpenVAS, go to Scans in the left pane, click on Tasks, then select the Wizard wand icon and choose Task Wizard.

Now, put the IP address for the Scan and click on the Start Scan button

All data is stored in the PostgreSQL database, and every alert is triggered instantly on the Wazuh Dashboard as soon as it is detected.




OpenVAS Dashboard:

Dashboard Configuration
