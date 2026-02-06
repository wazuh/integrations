# Find and monitor the vulnerable dependencies rely on repository with Dependabot on Wazuh

## Table of Contents
- <a href="#intro">Introduction</a>
- <a href="#prerequisites">Prerequisites</a>
- <a href="#dependabot">Dependabot Configuration</a>   
- <a href="#server">Server/Agent Configuration  & Installation</a>
  - <a href="#installation">Installation</a>
  - <a href="#conf">Configuration</a>
- <a href="#ruleset">Custom Ruleset Configuration</a>
  - <a href="#decoders">Testing Decoders</a>
  - <a href="#rules">Testing Rules</a>
- <a href="#dashboard">Dashboard Configuration</a>
- <a href="#source">Sources</a>



## <h2 id="intro" >Introduction</h2>

This integration offers a comprehensive guide and the required steps to perform to integrate the dependabot with Wazuh. By leveraging this integration, we can collect the logs of the repository, where dependabot included the `vulnerability`, `severity`  & the `CVE_details`,etc. This integration enables monitoring of the GitHub repository to use a secure version of the dependency.

## <h2 id="prerequisites" >Prerequisites</h2>

Before starting the integration, ensure you have the following:

* GitHub repository for find dependabot vulnerabilities (reference document:https://docs.github.com/en/code-security/getting-started/dependabot-quickstart-guide#enabling-dependabot-for-your-repository)
* A fully functional Wazuh environment, including the Server, Indexer, and Dashboard components.

## <h2 id="dependabot">Dependabot Configuration</h2>

To monitoring the dependabot security logs, we have to need to enable the dependbot setting for the repository, and needed the `token` with allowed the specific permissions.
1. Enable the dependabot logs for the repository via following steps outlined here: https://docs.github.com/en/code-security/getting-started/dependabot-quickstart-guide#viewing-dependabot-alerts-for-your-repository

2. Need to generate the token with full permissions by referencing this document: https://github.com/settings/tokens 

## <h2 id="server">Server/Agent Configuration  & Installation</h2>

### <h3 id="installation">Installation</h3>

1. Download the script file from above folder `script -> dependa.sh`, and update the **ORG**, **REPO** & **TOKEN** variable.

2. Script file to fetch the logs:
```
 sh -x dependa.sh
```

### <h3 id="conf">Configuration</h3>

1. Move this script file to `/var/ossec/integrations` folder.
```
mv dependa.sh /var/ossec/integrations/
```

2. Assign the appropriate permissions  & ownerships
```
chown root:wazuh /var/ossec/integrations/dependa.sh
chmod 750 /var/ossec/integrations/dependa.sh
chmod +x /var/ossec/integrations/dependa.sh
```

3. Create the log monitoring directory and set the appropriate ownership and permissions
```
mkdir /var/log/dependabot
chown wazuh:wazuh /var/log/dependabot /var/log/dependabot/*
chmod 644 /var/log/dependabot/*
```

4. Update the `/var/ossec/etc/ossec.conf` configuration to schedule the script to run daily.
```
<wodle name="command">
  <disabled>no</disabled>
  <command>/bin/bash /var/ossec/integrations/dependa.sh</command>
  <interval>1d</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
</wodle>
```

5. Update the `/var/ossec/etc/ossec.conf` configuration to enable monitoring of the dependabot log files.
```
<localfile>
   <log_format>syslog</log_format>
   <location>/var/log/dependabot/*.json</location>
</localfile>
```

6. After saving the changes restart the wazuh-server services:
```
systemctl restart wazuh-manager
```
Verify that the server is reading the dependabot log file by checking `cat /var/ossec/logs/ossec.log | grep -iE dependabot`  & check the logs at `/var/log/dependabot` directory

## <h2 id="ruleset">Custom Ruleset Configuration</h2>

### <h3 id="decoders">Testing Decoders</h3>

By default logs are decoded by the default decoder `JSON`, so we don't need to create the decoders for them.

### <h3 id="rules">Testing Rules</h3>

The following rule groups process the different-2 severities of the vulnerable dependabot logs

1. Download the rules from the provided file `rules → dependabot_rules.xml` and update your custom rules file as shown below:
```
vi /var/ossec/etc/rules/dependabot_rules.xml
```

**NOTE**:
- Use rule ID numbers between 100000 and 120000 for custom rules.
- Ensure there are no duplicate rule IDs configured in any custom or default rule files.

2. Use the sample logs below to test the custom rules:

```
{"fetched_at":"2025-12-16T05:12:49Z","number":526,"state":"open","dependency":{"package":{"ecosystem":"npm","name":"js-yaml"},"manifest_path":"documentation/bff-documentation/package-lock.json","scope":"runtime","relationship":"transitive"},"security_advisory":{"ghsa_id":"GHSA-mh29-5h37-fv8m","cve_id":"CVE-2025-64718","summary":"js-yaml has prototype pollution in merge (<<)","description":"### Impact\n\nIn js-yaml 4.1.0, 4.0.0, and 3.14.1 and below, it's possible for an attacker to modify the prototype of the result of a parsed yaml document via prototype pollution (`__proto__`). All users who parse untrusted yaml documents may be impacted.\n\n### Patches\n\nProblem is patched in js-yaml 4.1.1 and 3.14.2.\n\n### Workarounds\n\nYou can protect against this kind of attack on the server by using `node --disable-proto=delete` or `deno` (in Deno, pollution protection is on by default).\n\n### References\n\nhttps://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html","severity":"medium","identifiers":[{"value":"GHSA-mh29-5h37-fv8m","type":"GHSA"},{"value":"CVE-2025-64718","type":"CVE"}],"references":[{"url":"https://github.com/nodeca/js-yaml/security/advisories/GHSA-mh29-5h37-fv8m"},{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-64718"},{"url":"https://github.com/nodeca/js-yaml/commit/383665ff4248ec2192d1274e934462bb30426879"},{"url":"https://github.com/nodeca/js-yaml/commit/5278870a17454fe8621dbd8c445c412529525266"},{"url":"https://github.com/advisories/GHSA-mh29-5h37-fv8m"}],"published_at":"2025-11-14T14:29:48Z","updated_at":"2025-11-17T15:20:44Z","withdrawn_at":null,"vulnerabilities":[{"package":{"ecosystem":"npm","name":"js-yaml"},"severity":"medium","vulnerable_version_range":">= 4.0.0, < 4.1.1","first_patched_version":{"identifier":"4.1.1"}},{"package":{"ecosystem":"npm","name":"js-yaml"},"severity":"medium","vulnerable_version_range":"< 3.14.2","first_patched_version":{"identifier":"3.14.2"}}],"cvss_severities":{"cvss_v3":{"vector_string":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N","score":5.3},"cvss_v4":{"vector_string":null,"score":0.0}},"epss":{"percentage":0.00019,"percentile":0.04063},"cvss":{"vector_string":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N","score":5.3},"cwes":[{"cwe_id":"CWE-1321","name":"Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')"}]},"security_vulnerability":{"package":{"ecosystem":"npm","name":"js-yaml"},"severity":"medium","vulnerable_version_range":"< 3.14.2","first_patched_version":{"identifier":"3.14.2"}},"url":"https://api.github.com/repos/gaincredit/common_backend_ui/dependabot/alerts/526","html_url":"https://github.com/gaincredit/common_backend_ui/security/dependabot/526","created_at":"2025-11-18T03:02:46Z","updated_at":"2025-11-18T03:02:46Z","dismissed_at":null,"dismissed_by":null,"dismissed_reason":null,"dismissed_comment":null,"fixed_at":null,"auto_dismissed_at":null}

{"fetched_at":"2025-12-16T05:12:49Z","number":513,"state":"open","dependency":{"package":{"ecosystem":"npm","name":"min-document"},"manifest_path":"style_guide/form-components/package-lock.json","scope":"development","relationship":"transitive"},"security_advisory":{"ghsa_id":"GHSA-rx8g-88g5-qh64","cve_id":"CVE-2025-57352","summary":"min-document vulnerable to prototype pollution","description":"A vulnerability exists in the 'min-document' package prior to version 2.19.1, stemming from improper handling of namespace operations in the removeAttributeNS method. By processing malicious input involving the __proto__ property, an attacker can manipulate the prototype chain of JavaScript objects, leading to denial of service or arbitrary code execution. This issue arises from insufficient validation of attribute namespace removal operations, allowing unintended modification of critical object prototypes. The vulnerability is addressed in version 2.19.1.","severity":"low","identifiers":[{"value":"GHSA-rx8g-88g5-qh64","type":"GHSA"},{"value":"CVE-2025-57352","type":"CVE"}],"references":[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-57352"},{"url":"https://github.com/Raynos/min-document/issues/54"},{"url":"https://github.com/VulnSageAgent/PoCs/tree/main/JavaScript/prototype-pollution/CVE-2025-57352"},{"url":"https://github.com/Raynos/min-document/pull/55"},{"url":"https://github.com/Raynos/min-document/commit/fe32e8da464cef622528725f647029a8fd7d95a6"},{"url":"https://github.com/advisories/GHSA-rx8g-88g5-qh64"}],"published_at":"2025-09-24T18:30:31Z","updated_at":"2025-11-06T18:20:26Z","withdrawn_at":null,"vulnerabilities":[{"package":{"ecosystem":"npm","name":"min-document"},"severity":"low","vulnerable_version_range":"<= 2.19.0","first_patched_version":{"identifier":"2.19.1"}}],"cvss_severities":{"cvss_v3":{"vector_string":null,"score":0.0},"cvss_v4":{"vector_string":"CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:P","score":2.9}},"epss":{"percentage":0.00068,"percentile":0.21001},"cvss":{"vector_string":null,"score":0.0},"cwes":[{"cwe_id":"CWE-1321","name":"Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')"}]},"security_vulnerability":{"package":{"ecosystem":"npm","name":"min-document"},"severity":"low","vulnerable_version_range":"<= 2.19.0","first_patched_version":{"identifier":"2.19.1"}},"url":"https://api.github.com/repos/gaincredit/common_backend_ui/dependabot/alerts/513","html_url":"https://github.com/gaincredit/common_backend_ui/security/dependabot/513","created_at":"2025-09-29T14:22:45Z","updated_at":"2025-09-29T14:22:45Z","dismissed_at":null,"dismissed_by":null,"dismissed_reason":null,"dismissed_comment":null,"fixed_at":null,"auto_dismissed_at":null}
```

3.  After the changes, test the configuration via in-built tool:
```
/var/ossec/bin/wazuh-logtest
```
   <img width="711" height="832" alt="Screenshot_96" src="https://github.com/user-attachments/assets/4234b89b-eb41-4b55-acd5-88a3c32f789a" />


4. After successfully testing the changes, restart the Wazuh Manager using the command below:
```
systemctl restart wazuh-manager
```

## <h2 id="dashboard">Dashboard Configuration</h2>
Using the collected Dependabot logs, we have created the custom Dashboard that replicates the visibility of the logs provided by the Dependabot.

Below is a sample dashboard configuration that visualizes dependabot logs severity, runtimes, log counts, cve_ids and more details.
Can download from the above provided folder `dashboard -> github_dependabot_dashboard.ndjson`.Once downloaded, you can import it into the Wazuh Dashboard by navigating to **Dashboard Management → Saved Objects → Click to import**.

<img width="1919" height="908" alt="dashboard" src="https://github.com/user-attachments/assets/a6cc4fb3-63ba-425e-9e99-524e9dc776a1" />


## <h2 id="source">Sources</h2>
- [dependabot Documentation](https://docs.github.com/en/code-security/getting-started/dependabot-quickstart-guide#viewing-dependabot-alerts-for-your-repository)
- [Custom Visualization/dashboard](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/creating-custom-dashboards.html)
- [Custom Rules In Wazuh](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [Wodle Command Configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html#example-of-configuration)
- [Localfile Configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html#configuration-examples)




