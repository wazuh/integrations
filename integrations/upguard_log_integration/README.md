# Monitoring the Attacks  & Different risks with Wazuh And Upguard

## Table of Contents
- <a href="#intro">Introduction</a>
- <a href="#prerequisites">Prerequisites</a>
- <a href="#upguard">Upguard Configuration</a>   
- <a href="#server">Server/Agent Configuration  & Installation</a>
  - <a href="#installation">Installation</a>
  - <a href="#conf">Configuration</a>
- <a href="#ruleset">Custom Ruleset Configuration</a>
  - <a href="#decoders">Testing Decoders</a>
  - <a href="#rules">Testing Rules</a>
- <a href="#dashboard">Dashboard Configuration</a>
- <a href="#source">Sources</a>



## <h2 id="intro" >Introduction</h2>

This integration offers a comprehensive guide and the required steps to perform to integrate the Upguard with Wazuh. By leveraging this integration, we can collect the logs from the multiple risks details with included of the `vendor`, `category`  & the `sources`. This integration enables monitoring of the Upguard security events across the environment.

## <h2 id="prerequisites" >Prerequisites</h2>

Before starting the integration, ensure you have the following:

* Already have the account in the Upguard (refer this link to login: https://app.upguard.com/)
* A fully functional Wazuh environment, including the Server, Indexer, and Dashboard components.

## <h2 id="upguard">Upguard Configuration</h2>

To monitoring the Upguard security logs, we have to need the `API Key` with provided the specific permissions.So, to create a api-key.
1. Go to dashboard via https://cyber-risk.upguard.com/?utm_medium=website&utm-source=website-navbar

2. Click on `Setting icon` &#8594; click on `API-Key` &#8594; click on `Create A API Key`. Then allow the gateways to fetch the logs.
   <img width="1898" height="786" alt="475335196-30fb1779-9c12-4930-9b75-80a0b02d50b4" src="https://github.com/user-attachments/assets/e4a6cba7-f25b-4da1-8998-7d8f2262636b" />
   <img width="1892" height="654" alt="475335250-8f8c9d8e-ce02-4088-a959-843c45fb3e0b" src="https://github.com/user-attachments/assets/8863763c-d2ab-4834-8105-0d263d2b852d" />
   <img width="716" height="834" alt="475335304-97686c21-9ace-435b-96a1-1df060f51457" src="https://github.com/user-attachments/assets/79ab03e0-0c9c-4f7a-8023-bff2e2f695d9" />

3. Then click to `create API key` and copy it to the clipboard.
   <img width="1555" height="605" alt="475335340-a50fd19b-159b-4589-b176-5945a4ee0f78" src="https://github.com/user-attachments/assets/9437e08d-a080-4ace-8574-344c1718196d" />



## <h2 id="server">Server/Agent Configuration  & Installation</h2>

### <h3 id="installation">Installation</h3>

For the integration, we have to configure the script and to run this script effectively, we have to require the `python`.

1. Install `python` and its dependencies.
```
   apt install python3 -y
   apt install python3-pip -y
```
2. Download the script file from above `script` &#8594; `upguard_logs.py`, and update the **Upgurad_API_KEY** variable.
3. Script file to fetch the logs:
```
 python3 upguard_logs.py
```

### <h3 id="conf">Configuration</h3>

1. Move this script file to `/var/ossec/integrations` folder.
```
mv upguard_logs.py /var/ossec/integrations/
```

2. Assign the appropriate permissions  & ownerships
```
chown root:wazuh /var/ossec/integrations/upguard_logs.py
chmod 750 /var/ossec/integrations/upguard_logs.py
```

3. Create the log monitoring file and set the appropriate ownership and permissions
```
touch /var/ossec/logs/upguard_logs.log
chown wazuh:wazuh /var/ossec/logs/upguard_logs.log
chmod 644 /var/ossec/logs/upguard_logs.log
```

4. Update the `/var/ossec/etc/ossec.conf` configuration to schedule the script to run daily.
```
<wodle name="command">
  <disabled>no</disabled>
  <command>/usr/bin/python3 /var/ossec/integrations/upguard_logs.py</command>
  <interval>1d</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
</wodle>
```

5. Update the `/var/ossec/etc/ossec.conf` configuration to enable monitoring of the UpGuard log files.
```
<localfile>
   <log_format>syslog</log_format>
   <location>/var/ossec/logs/upguard_logs.log</location>
</localfile>
```

6. After saving the changes restart the wazuh-server services:
```
systemctl restart wazuh-manager
```
Verify that the server is reading the Upguard log file by checking `cat /var/ossec/logs/ossec.log | grep -iE upguard`  & check the logs at `tail -f /var/ossec/logs/upguard_logs.log`

## <h2 id="ruleset">Custom Ruleset Configuration</h2>

### <h3 id="decoders">Testing Decoders</h3>

By default logs are decoded by the default decoder `JSON`, so we don't need to create the decoders for them.

### <h3 id="rules">Testing Rules</h3>

The following rule groups process the category, risk_ids and source details to know more about the logs.

1. Download the rules from the provided file `rules → upguard_rules.xml` and update your custom rules file as shown below:
```
vi /var/ossec/etc/rules/upguard_rules.xml
```

**NOTE**:
- Use rule ID numbers between 100000 and 120000 for custom rules.
- Ensure there are no duplicate rule IDs configured in any custom or default rule files.

2. Use the sample logs below to test the custom rules:
```
{"timestamp": "2025-08-05T04:42:52.428235Z", "integration": "upguard", "risk_id": "exposed_service:MySQL", "severity": "critical", "vendor": null, "finding": "'MySQL' port open", "category": "network_sec", "source": {"id": "exposed_service:MySQL", "finding": "'MySQL' port open", "risk": "An internet-facing database of any type is under a constant barrage of attacks. Most installations of MySQL will use the default port of 3306. This makes it easy to identify servers running this type of database and to try known exploits against them. Even when the port number is changed, the service can still be identified, so changing the port number is not sufficient protection. A compromised database is usually a very high risk event, due to the sensitive nature of most corporate database content.", "description": "MySQL is an open source relational database. It is part of the LAMP software stack, often used on Linux as an alternative to Microsoft\u2019s SQL Server. MySQL uses port 3306 by default.", "remediation": "All types of databases should be restricted to internal networks, VPNs or other solutions that stop internet-wide visibility. This prevents internet scans and other wide sweeping technologies from seeing the database server at all. If the MySQL service is no longer being used, the port should be closed to the internet. If the server must be internet-facing, rigorous care should be taken to maintain patches and updates on the database and server to protect against known vulnerabilities.", "severity": "critical", "category": "network_sec", "firstDetected": "2025-05-25T16:34:41.991015Z", "hostnames": [], "hostnameCount": 0, "risk_waivers": [{"all_hostnames": true, "hostnames": ["api.samudhramarine.com", "bigpitcher.co.in", "bigwavesinternational.com", "dashboard.samudhramarine.com", "globalconnectsolution.net", "globalunitedmedia.in", "hospitality.anchorpoint.in", "myswastha.org", "samudhramarine.com", "theedgehotels.in"], "created_by": "securityops@synergyship.com", "active_at": "2025-06-05T10:57:22.180152Z", "justification": "SQL Port closed"}, {"all_hostnames": false, "hostnames": ["bigwavesinternational.com"], "created_by": "securityops@synergyship.com", "active_at": "2025-04-22T05:38:41.060944Z", "justification": "SQL Port closed"}], "riskType": "exposed_service", "riskSubtype": "MySQL"}}

{"timestamp": "2025-08-05T04:42:52.428329Z", "integration": "upguard", "risk_id": "exposed_service:PostgresSQL", "severity": "critical", "vendor": null, "finding": "'PostgreSQL' port open", "category": "network_sec", "source": {"id": "exposed_service:PostgresSQL", "finding": "'PostgreSQL' port open", "risk": "An internet-facing database of any type is under a constant barrage of attacks. Most installations of Postgres will use the default port of 5432. This makes it easy to identify servers running this type of database and to try known exploits against them. Even when the port number is changed, the service can still be identified, so changing the port number is not sufficient protection. A compromised database is usually a very high risk event, due to the sensitive nature of most corporate database content.", "description": "Postgres (or PostgreSQL) is an open source relational database that runs on many platforms. As the name suggests, Postgres is SQL compatible, with most of the features expected of a SQL database. By default, Postgres runs on port 5432.", "remediation": "All types of databases should be restricted to internal networks, VPNs or other solutions that stop internet-wide visibility. This prevents internet scans and other wide sweeping technologies from seeing the database server at all. If the Postgres service is no longer being used, the port should be closed to the internet. If the server must be internet-facing, rigorous care should be taken to maintain patches and updates on the database and server to protect against known vulnerabilities.", "severity": "critical", "category": "network_sec", "firstDetected": "2025-06-15T11:55:32.533772Z", "hostnames": ["turbomot.com"], "hostnameCount": 1, "riskType": "exposed_service", "riskSubtype": "PostgresSQL"}}
```

3.  After the changes, test the configuration via:
```
/var/ossec/bin/wazuh-logtest
```
   <img width="711" height="832" alt="Screenshot_96" src="https://github.com/user-attachments/assets/3f37f78d-6c49-4843-955c-7ad064d98caa" />


4. After successfully testing the changes, restart the Wazuh Manager using the command below:
```
systemctl restart wazuh-manager
```

## <h2 id="dashboard">Dashboard Configuration</h2>
Using the collected Upguard logs, we have created the custom wazuh-dashboard that replicates the visibility of the logs provided by the Upguard.

Below is a sample dashboard configuration that visualizes Upguard logs findings, Categories, risk_ids, hostnames, severity and more details.
Can download from the above provided folder `Dashboard -> upguard_dashboard.ndjson`.Once downloaded, you can import it into the Wazuh Dashboard by navigating to **Wazuh Dashboard → Menu → Stack Management → Saved Objects**.

<img width="1919" height="908" alt="dashboard" src="https://github.com/user-attachments/assets/df061a83-f321-4919-8128-b61d880276cc" />


## <h2 id="source">Sources</h2>
- [Upguard Logs API Documentation](https://cyber-risk.upguard.com/api/docs#tag/risks/operation/risk)
- [Custom Visualization/dashboard](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/creating-custom-dashboards.html)
- [Custom Rules In Wazuh](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [Wodle Command Configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html#example-of-configuration)
- [Localfile Configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html#configuration-examples)


