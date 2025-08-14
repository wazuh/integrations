## Barracuda WAF – Decoder and Rule Implementation

## Table of Contents
- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Custom Decoder Configuration in Wazuh Manager Server](#custom-decoder-configuration-in-wazuh-manager-server)
- [Custom Ruleset Configuration in Wazuh Manager Server](#custom-ruleset-configuration-in-wazuh-manager-server)
  - [Testing Decoders and Rules](#testing-decoders-and-rules)
- [Dashboard Configuration](#dashboard-configuration)
- [Sources](#sources)

## Introduction
The `barracuda.waf` dataset captures events forwarded from a configured syslog server. It includes all Barracuda Web Application Firewall (WAF) specific syslog fields, which are organized under the `barracuda.waf` field group.

## Prerequisites
Before starting the integration, ensure you have the following:

- A fully functional Wazuh environment, including the wazuh Server, Indexer, and Dashboard components.

## Custom Decoder Configuration in Wazuh Manager Server

The `Barracuda WAF` sends logs in a syslog format that needs to be parsed into structured fields by Wazuh for analysis and rule matching. We create a custom decoder to extract these fields.

Create a Custom Decoder File:

Create a new custom decoder file under `/var/ossec/etc/decoders/` for `Barracuda WAF`,  add the decoder configuration, and click [here](https://github.com/wazuh/operations/blob/main/content/ruleset/barracuda-waf/decoders/barracuda-waf_decoders.xml) to view the decoder file.

```bash
nano /var/ossec/etc/decoders/barracuda-waf_decoders.xml
```

Set the correct permissions:

```bash
chown wazuh:wazuh /var/ossec/etc/rules/barracuda-waf_decoders.xml
chmod 660 /var/ossec/etc/rules/barracuda-waf_decoders.xml
```

## Custom Ruleset Configuration in Wazuh Manager Server

Once the logs are decoded, custom rules define how Wazuh should react to different types of WAF events. 

Create a Custom Rules File

Create a new custom rule file under `/var/ossec/etc/rules/` for `Barracuda WAF`,  add the rule configuration, and click [here](https://github.com/wazuh/operations/blob/main/content/ruleset/barracuda-waf/rules/barracuda-waf_rules.xml) to view the sample rule.


```bash
nano /var/ossec/etc/rules/barracuda-waf_rules.xml
```

**Note:**

- Use rule ID numbers between `100000` and `120000` for custom rules.
- Ensure there are no duplicate rule IDs configured in any `custom` or `default` rule files.


Set the correct permissions:

```bash
chown wazuh:wazuh /var/ossec/etc/rules/barracuda-waf_rules.xml
chmod 660 /var/ossec/etc/rules/barracuda-waf_rules.xml
```

Restart the Wazuh server service:

After saving the rules, restart the Wazuh server to apply changes:

```bash
sudo systemctl restart wazuh-manager
```

### Testing Decoders and Rules

The `/var/ossec/bin/wazuh-logtest` tool allows you to test and verify decoders and rules against sample log entries directly on the Wazuh server.

To validate the `Barracuda WAF` rules and decoders, execute wazuh-logtest on the Wazuh server and provide a sample log entry for testing.

```bash
/var/ossec/bin/wazuh-logtest
```


Sample log:

<pre> &lt;129&gt;2023-03-01 14:54:44.502 +0100  barracuda WF ALER NO_PARAM_PROFILE_MATCH 193.1.1.1 61507 10.1.1.1 443 Hackazon:adaptive_url_42099b4af021e53fd8fd URL_PROFILE LOG NONE [Parameter\\=\"0x\\\\[\\\\]\" value\\=\"androxgh0st\"] POST / TLSv1.2 \"-\" \"Mozilla/5.0 (Linux; U; Android 4.4.2; en-US; HM NOTE 1W Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 UCBrowser/11.0.5.850 U3/0.8.0 Mobile Safari/534.30\" 20.1.1.1 61507 \"-\" \"-\" 1869d743696-dfcf8d96" </pre>

After creating the custom decoder, an example event for barracuda WAF appears in JSON format as follows:

<details>
<summary>Click to see the JSON format and output</summary>

```json
{
  "_index": "wazuh-alerts-4.x-2025.06.19",
  "_id": "m953hpcBIOKkycBoG-9v",
  "_version": 1,
  "_score": null,
  "_source": {
    "input": {
      "type": "log"
    },
    "agent": {
      "name": "wmanagerH0",
      "id": "000"
    },
    "manager": {
      "name": "wmanagerH0"
    },
    "data": {
      "barracuda": {
        "waf": {
          "attack_description": "NO_PARAM_PROFILE_MATCH",
          "action_taken": "LOG",
          "request_method": "POST",
          "custom_header": {
            "user_agent": "\\\"Mozilla/5.0 (Linux; U; Android 4.4.2; en-US; HM NOTE 1W Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 UCBrowser/11.0.5.850 U3/0.8.0 Mobile Safari/534.30\\\""
          },
          "sessionid": "1869d743696-dfcf8d96",
          "severity_level": "ALER",
          "followup_action": "NONE",
          "unit_name": "barracuda",
          "proxy": {
            "port": "61507",
            "ip": "193.1.1.1"
          },
          "client_port": "61507",
          "log_type": "WF",
          "protocol": "TLSv1.2",
          "rule_type": "URL_PROFILE",
          "attack_details": "[Parameter\\\\=\\\"0x\\\\\\\\[\\\\\\\\]\\\" value\\\\=\\\"androxgh0st\\\"]",
          "server_ip": "10.1.1.1",
          "ruleName": "Hackazon:adaptive_url_42099b4af021e53fd8fd",
          "server_port": "443",
          "client_ip": "20.1.1.1"
        }
      }
    },
    "rule": {
      "firedtimes": 1,
      "mail": false,
      "level": 3,
      "description": "Barracuda waf messages grouped.",
      "groups": [
        "barracuda-waf"
      ],
      "id": "110000"
    },
    "location": "/var/log/test.log",
    "decoder": {
      "name": "barracuda-waf"
    },
    "id": "1750307623.791368",
    "full_log": "<129>2023-03-01 14:54:44.502 +0100  barracuda WF ALER NO_PARAM_PROFILE_MATCH 193.1.1.1 61507 10.1.1.1 443 Hackazon:adaptive_url_42099b4af021e53fd8fd URL_PROFILE LOG NONE [Parameter\\\\=\\\"0x\\\\\\\\[\\\\\\\\]\\\" value\\\\=\\\"androxgh0st\\\"] POST / TLSv1.2 \\\"-\\\" \\\"Mozilla/5.0 (Linux; U; Android 4.4.2; en-US; HM NOTE 1W Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 UCBrowser/11.1.1.850 U3/0.8.0 Mobile Safari/534.30\\\" 20.1.1.1 61507 \\\"-\\\" \\\"-\\\" 1869d743696-dfcf8d96\"",
    "timestamp": "2025-06-19T04:33:43.069+0000"
  },
  "fields": {
    "timestamp": [
      "2025-06-19T04:33:43.069Z"
    ]
  },
  "highlight": {
    "decoder.name": [
      "@opensearch-dashboards-highlighted-field@barracuda-waf@/opensearch-dashboards-highlighted-field@"
    ]
  },
  "sort": [
    1750307623069
  ]
}
```


Sample JSON output:
<img width="956" height="944" alt="111p" src="https://github.com/user-attachments/assets/25866812-25c4-46e9-a088-7ecbe2b932c5" />


Sample result:
<img width="1418" height="934" alt="111p2" src="https://github.com/user-attachments/assets/f36b53c4-ec6e-4473-a217-6f67235a9a08" />


</details>

<details>
<summary>Click to see the fields and descriptions</summary>



| Field                                 | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Type              |
|--------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------|
| `@timestamp`                         | Event timestamp.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | date              |
| `barracuda.waf.action_taken`         | The appropriate action applied on the traffic. DENY - denotes that the traffic is denied. LOG - denotes monitoring of the traffic with the assigned rule. WARNING - warns about the traffic.                                                                                                                                                                                                                                                                                                          | keyword           |
| `barracuda.waf.additional_data`      | Provides more information on the parameter changed.                                                                                                                                                                                                                                                                                                                                                                                                                                                   | keyword           |
| `barracuda.waf.attack_description`   | The name of the attack triggered by the request.                                                                                                                                                                                                                                                                                                                                                                                                                                                      | keyword           |
| `barracuda.waf.attack_details`       | The details of the attack triggered by the request.                                                                                                                                                                                                                                                                                                                                                                                                                                                   | keyword           |
| `barracuda.waf.authenticated_user`   | The username of the currently authenticated client requesting the web page. This is available only when the request is for a service that is using the AAA (Access Control) module.                                                                                                                                                                                                                                                                                                                  | keyword           |
| `barracuda.waf.cache_hit`            | Specifies whether the response is served out of the Barracuda Web Application Firewall cache or from the backend server. Values: 0 - if fetched from server. 1 - if fetched from cache.                                                                                                                                                                                                                                                                                                              | keyword              |
| `barracuda.waf.client_type`          | Indicates that GUI is used as client to access the Barracuda Web Application Firewall.                                                                                                                                                                                                                                                                                                                                                                                                               | keyword           |
| `barracuda.waf.command_name`         | The name of the command that was executed on the Barracuda Web Application Firewall.                                                                                                                                                                                                                                                                                                                                                                                                                 | keyword           |
| `barracuda.waf.custom_header.accept_encoding` | The header Accept-Encoding in the Access Logs.                                                                                                                                                                                                                                                                                                                                                                                                                | keyword           |
| `barracuda.waf.custom_header.cache_control`  | The header Cache-Control in the Access Logs.                                                                                                                                                                                                                                                                                                                                                                                                                   | keyword           |
| `barracuda.waf.custom_header.connection`     | The header Connection in the Access Logs.                                                                                                                                                                                                                                                                                                                                                                                                                      | keyword           |
| `barracuda.waf.custom_header.content_type`   | The header Content-Type in the Access Logs.                                                                                                                                                                                                                                                                                                                                                                                                                    | keyword           |
| `barracuda.waf.custom_header.host`          | The header Host in the Access Logs.                                                                                                                                                                                                                                                                                                                                                                                                                            | keyword           |
| `barracuda.waf.custom_header.user_agent`    | The header User-Agent in the Access Logs.                                                                                                                                                                                                                                                                                                                                                                                                                      | keyword           |
| `barracuda.waf.followup_action`     | The follow-up action as specified by the action policy. It can be either None or Locked in case the lockout is chosen.                                                                                                                                                                                                                                                                                                                                                                               | keyword           |
| `barracuda.waf.log_type`            | Specifies the type of log - Web Firewall Log, Access Log, Audit Log, Network Firewall Log or System Log - WF, TR, AUDIT, NF, SYS.                                                                                                                                                                                                                                                                                                                                                                    | keyword           |
| `barracuda.waf.module.event_id`     | The event ID of the module.                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | keyword              |
| `barracuda.waf.module.event_message`| Denotes the log message for the event that occurred.                                                                                                                                                                                                                                                                                                                                                                                                           | keyword           |
| `barracuda.waf.module.name`         | Denotes the name of the module that generated the logs.                                                                                                                                                                                                                                                                                                                                                                                                         | keyword           |
| `barracuda.waf.new_value`           | The value after modification.                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | keyword           |
| `barracuda.waf.object_type`         | The type of the object that is being modified.                                                                                                                                                                                                                                                                                                                                                                                                                 | keyword           |
| `barracuda.waf.old_value`           | The value before modification.                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | keyword           |
| `barracuda.waf.policy`              | The ACL policy (Allow or Deny) applied to this ACL rule.                                                                                                                                                                                                                                                                                                                                                                                                       | keyword           |
| `barracuda.waf.profile_matched`     | Specifies whether the request matched a defined URL or Parameter Profile. Values: DEFAULT, PROFILED.                                                                                                                                                                                                                                                                                                                                                                                                 | keyword           |
| `barracuda.waf.protected`           | Specifies whether the request went through Barracuda WAF rules and policy checks. Values: PASSIVE, PROTECTED, UNPROTECTED.                                                                                                                                                                                                                                                                                                                                                                           | keyword           |
| `barracuda.waf.protocol`            | The protocol used for the request.                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | keyword           |
| `barracuda.waf.proxy.ip`            | Provides the IP address of the proxy.                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | keyword                |
| `barracuda.waf.proxy.port`          | The port of the proxy server.                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | keyword              |
| `barracuda.waf.request_cookie`      | Specifies whether the request is valid. Values: INVALID, VALID.                                                                                                                                                                                                                                                                                                                                                                                                 | keyword           |
| `barracuda.waf.response_timetaken`  | The total time taken to serve the request from the time it landed on the WAF until the last byte is sent.                                                                                                                                                                                                                                                                                                                                                      | keyword              |
| `barracuda.waf.response_type`       | Specifies whether the response came from backend server or the WAF. Values: INTERNAL, SERVER.                                                                                                                                                                                                                                                                                                                                                                   | keyword           |
| `barracuda.waf.ruleName`            | The path of the URL ACL that matched with the request. "webapp1" is the web application, "deny_ban_dir" is the URL ACL.                                                                                                                                                                                                                                                                                                                                        | keyword           |
| `barracuda.waf.rule_type`           | Type of rule hit by the request: Global, Global URL ACL, URL ACL, URL Policy, URL Profile, Parameter Profile, Header Profile.                                                                                                                                                                                                                                                                                                                                 | keyword           |
| `barracuda.waf.server_time`         | Time taken by backend server to serve the forwarded request.                                                                                                                                                                                                                                                                                                                                                                                                   | keyword              |
| `barracuda.waf.sessionid`           | The value of the session tokens in the request if session tracking is enabled.                                                                                                                                                                                                                                                                                                                                                                                 | keyword           |
| `barracuda.waf.severity_level`      | Defines the seriousness of the attack. (EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFORMATION, DEBUG)                                                                                                                                                                                                                                                                                                                                                | keyword           |
| `barracuda.waf.transaction_id`      | Transaction ID for persistent change. If no change, value is `-1`.                                                                                                                                                                                                                                                                                                                                                                                              | keyword              |
| `barracuda.waf.transaction_type`    | Type of transaction by admin: LOGIN, LOGOUT, CONFIG, COMMAND, etc.                                                                                                                                                                                                                                                                                                                                                                                             | keyword           |
| `barracuda.waf.unit_name`          | Specifies the name of the unit.                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | keyword           |
| `barracuda.waf.user_id`             | The identifier of the user.                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | keyword           |
| `barracuda.waf.wf_matched`          | Specifies whether the request is valid. Values: INVALID, VALID.                                                                                                                                                                                                                                                                                                                                                                                                 | keyword           |
| `data_stream.dataset`               | Data stream dataset.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | keyword  |
| `data_stream.namespace`             | Data stream namespace.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | keyword  |
| `data_stream.type`                  | Data stream type.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | keyword  |
| `input.type`                        | Input type.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | keyword           |
| `log.offset`                        | Log offset.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | keyword              |
| `log.source.address`                | Source address from which the log event was read or sent.                                                                                                                                                                                                                                                                                                                                                                                                       | keyword           |

</details>

## Dashboard Configuration

Sample dashboard output is shown below. Click [here](https://github.com/wazuh/operations/blob/main/content/ruleset/barracuda-waf/dashboard/barracuda-waf.ndjson) to download the `barracuda-waf.ndjson` file for easy import into the Wazuh Dashboard.


<img width="1918" height="939" alt="111p3" src="https://github.com/user-attachments/assets/a45fb0e4-f217-456a-bf8c-fa01346042cd" />


## Sources

<details>
<summary>Click to expand source references</summary>

- [Wazuh custom decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/custom.html)
- [Wazuh custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [Wazuh decoder syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html)
- [Wazuh rule synatx](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [Testing decoders and rules](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)

</details>

