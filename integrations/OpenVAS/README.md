# <h1>Wazuh - OpenVAS Integration</h1>

## Table of Contents

- <a href="#intro">Introduction</a>


## <h2 id="intro" >Introduction</h2>

OpenVAS (part of the Greenbone Vulnerability Management suite) is an open-source vulnerability scanner that identifies security risks across systems and applications. Wazuh, on the other hand, is a Security Information and Event Management (SIEM) and XDR platform that centralises log collection, threat detection, and alerting.

## <h3>Integrating OpenVAS with Wazuh allows</h3>

- Centralised vulnerability results inside the Wazuh dashboard
- Continuous monitoring of assets against vulnerabilities
- Correlation of OpenVAS alerts with endpoint and network events

## <h3>For reliable integration, OpenVAS was deployed natively on Kali Linux instead of Docker, because</h3>

- Native installation ensures full access to PostgreSQL tables (results, nvts)
- Easier control over file system paths and scripts
- Better alignment with Wazuh wodles (command execution)

## <h2 id="deployovas" >Deploying OpenVAS (Greenbone) on Kali Linux</h2>

**Update system**

`sudo apt update`

**Install OpenVAS**

`sudo apt install openvas`
`sudo apt install gvm`

**Setup OpenVAS**

`sudo gvm-setup`

**Verify services**

`sudo gvm-check-setup`

`sudo systemctl status gvmd`

`sudo systemctl status gsad`

**Change the `admin` password**

`sudo gvmd --user=admin --new-password=Str0ng-password`

**Start the GVM**

`sudo gvm-start`

**Log in to Greenbone Security Assistant (Web UI)**

Default URL: https://127.0.0.1:9392

## <h2 id="ovasdashbaord" >Accessing OpenVAS Dashboard from External Systems</h2>

By default, the Greenbone Security Assistant Daemon (GSAD) only listens on `127.0.0.1` (`ocalhost`), which restricts access to the Kali machine itself.
To make the dashboard accessible from other systems on the network, follow these steps:

**Edit GSAD service file**

`sudo nano /usr/lib/systemd/system/gsad.service`

**Modify the listen address**

<img width="400" height="600" src="https://github.com/wazuh/integrations/blob/Harry4share-auth0-integration/integrations/OpenVAS/Screenshots/modlistenaddr.jpg" />

<h3>Reload systemd daemon</h3>

`sudo systemctl daemon-reexec`

<h3>Restart GSAD service</h3>

`sudo systemctl restart gsad`

<h3>Access externally</h3>

From a remote system’s browser:
https://kali-ip:9392

**Security note:** For production, restrict access using a firewall or reverse proxy, rather than leaving GSAD open on all interfaces.

## <h2 id="dataextract" >Data Extraction from OpenVAS Database</h2>

To extract vulnerability results, we use the internal PostgreSQL database where scan results are stored. The two main tables used are:

- `results` → Stores scan findings (per host, per port).


- `nvts` → Stores metadata about each Network Vulnerability Test (CVE, CVSS, OID, family).


The goal is to combine data from both tables into a single JSON output that Wazuh can ingest.

On the Wazuh-agent(OpenVAS server) create [Bash Script](openvas_extract.sh) `nano /var/ossec/bin/openvas_extract.sh`

Create `openvas` directory under `/opt` and give full permission `/opt/openvas`

`sudo chmod +R 777 /opt/openvas`

<h3>Script Explanation:</h3>

- **Database variables** – Defines DB name (`gvmd`), user (`_gvm`), and socket directory.
- **Output directory & file** – `JSON` file will be saved at `/opt/openvas/openvas_combined.json`.
- **Start JSON structure** – Writes `[` to begin a JSON array.
- **SQL Query** –
      - Selects relevant fields from `results` (findings) and joins them with `nvts` (metadata).
      - Converts each row into JSON format using `row_to_json`.
- **`awk` formatting** – Ensures rows are comma-separated inside JSON array.
- **Close JSON array** – Writes `]` at the end.
- **Output confirmation** – Prints export location.

## <h2 id="wodleconf" >Automating with Wazuh (Wodle Configuration)</h2>

To ensure new OpenVAS results are ingested into Wazuh automatically, we use the command wodle in `/var/ossec/etc/ossec.conf`.
Example Configuration:
```
<wodle name="command">
  <disabled>no</disabled>
  <tag>openvas_export</tag>
  <command>/var/ossec/bin/openvas_extract.sh</command>
  <interval>1m</interval>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
  <ignore_output>no</ignore_output>
</wodle>
```


and set the configuration for the JSON file path `/opt/openvas/openvas_combined.json`
```
<localfile>
    <log_format>json</log_format>
    <location>/opt/openvas/openvas_combined.json</location>
</localfile>
```

<h3>Restart the Wazuh-agent service</h3>

`systemctl restart wazuh-agent`

## <h2 id="rulecreation" >Now, create Rules for the CVE and Open Ports</h2>

Log in to Wazuh Manager and create a [rule file](openvas_rules.xml):
`nano /var/ossec/etc/rules/openvas_rules.xml`

## <h2 id="startscan" >Start the scan from the OpenVAS dashboard:</h2>

Log in to OpenVAS, go to Scans in the left pane, click on Tasks, then select the Wizard wand icon and choose Task Wizard.

<img width="400" height="300" src="https://github.com/wazuh/integrations/blob/Harry4share-auth0-integration/integrations/OpenVAS/Screenshots/startscan.jpg" />

Now, put the IP address for the Scan and click on the Start Scan button

<img width="400" height="600" src="https://github.com/wazuh/integrations/blob/Harry4share-auth0-integration/integrations/OpenVAS/Screenshots/taskwizard.jpg" />

All data is stored in the PostgreSQL database, and every alert is triggered instantly on the Wazuh Dashboard as soon as it is detected.

<img width="800" height="1000" src="https://github.com/wazuh/integrations/blob/Harry4share-auth0-integration/integrations/OpenVAS/Screenshots/dashboardVisualization.jpg" />

<img width="800" height="1000" src="https://github.com/wazuh/integrations/blob/Harry4share-auth0-integration/integrations/OpenVAS/Screenshots/dashboardVisualization2.jpg" />

[OpenVAS Dashboard](export.ndjson)

<img width="1000" height="1000" src="https://github.com/wazuh/integrations/blob/Harry4share-auth0-integration/integrations/OpenVAS/Screenshots/openvasdashboard.jpg" />

