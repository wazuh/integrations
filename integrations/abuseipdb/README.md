# Wazuh - AbuseIPDB IP Reputation Integration

## Table of Contents

- [Introduction](#introduction)
- [Confidence Score Thresholds](#confidence-score-thresholds)
- [Installation and Configuration](#installation-and-configuration)
- [Wazuh Configuration](#wazuh-configuration)
   - [Integrator Config (manager `ossec.conf`)](#integrator-config-manager-ossecconf)
   - [Custom Rules](#custom-rules)
   - [Manual Tests](#manual-tests)
     - [Test 1: Clean IP](#test-1-clean-ip)
     - [Test 2: Malicious IP](#test-2-malicious-ip)
     - [Test 3: Error Handling](#test-3-error-handling)

## Introduction

This integration can be broken down into the following steps:

* Extracts the **source IP** from matching Wazuh alerts using flexible path detection.
* Queries AbuseIPDB's **check endpoint** (`/api/v2/check`) with a configurable lookback period.
* Returns enrichment data including **abuse confidence score**, **total reports**, **ISP**, **usage type**, and **country code**.
* Preserves original alert context (`original_full_log`, `waf.*` fields) for correlation.
* Handles API errors gracefully with proper error codes sent back to Wazuh for generating error alerts.

## Confidence Score Thresholds

AbuseIPDB provides an Abuse Confidence Score (0-100%) that represents the likelihood that an IP is malicious based on community reports. The integration returns this score along with other metadata, and custom rules can be configured to alert at different severity levels.

### Recommended Alert Levels

| Confidence Score | Severity | Description |
|------------------|----------|-------------|
| 0% | Clean | No reports in the database |
| 1-9% | Low | Few reports, likely false positives |
| 10-49% | Medium | Notable activity, worth monitoring |
| 50-74% | High | Significant abuse reports |
| 75-99% | Very High | Strong evidence of malicious activity |
| 100% | Critical | Confirmed malicious - unanimous reports |

Note: These thresholds can be adjusted based on your organization's risk tolerance and use case.

## Installation and Configuration

This integration uses two files: a shell script wrapper called by Wazuh and the Python script that performs the logic.

* Python Script: `/var/ossec/integrations/custom-abuseipdb.py`
* Shell Wrapper: `/var/ossec/integrations/custom-abuseipdb`

**Place & permissions:**

Place the [Python script](custom-abuseipdb.py) in `/var/ossec/integrations/` and create the shell wrapper:

```bash
# Copy the Python script
cp custom-abuseipdb.py /var/ossec/integrations/custom-abuseipdb.py

# Create shell wrapper (copy from existing integration as template)
cp /var/ossec/integrations/shuffle /var/ossec/integrations/custom-abuseipdb

# Set permissions
chmod 750 /var/ossec/integrations/custom-abuseipdb*
chown root:wazuh /var/ossec/integrations/custom-abuseipdb*
```

## Wazuh Configuration

### Integrator Config (manager `ossec.conf`)

Add the following block to `/var/ossec/etc/ossec.conf`. The `<name>` must match the shell script wrapper.

```xml
<integration>
  <name>custom-abuseipdb</name>
  <api_key>YOUR_ABUSEIPDB_API_KEY</api_key>
  <rule_id>100561</rule_id> <!-- adjust to your triggering rule(s) -->
  <alert_format>json</alert_format>
</integration>
```

You can also use `<group>` instead of `<rule_id>` to trigger on rule groups:

```xml
<integration>
  <name>custom-abuseipdb</name>
  <api_key>YOUR_ABUSEIPDB_API_KEY</api_key>
  <group>sshd,authentication_failed</group>
  <alert_format>json</alert_format>
</integration>
```

### Custom Rules

Add the [custom rules](./custom_abuseipdb.xml) to trigger alerts based on AbuseIPDB responses. You can add them to your local rules file at `/var/ossec/etc/rules/local_rules.xml` or create a new file through the Dashboard.

### Manual Tests

#### Test 1: Clean IP

<details>
<summary>Testing with a clean IP address (wazuh.com's IP):</summary>

```bash
[root@wazuh-server ~]# python3 /var/ossec/integrations/custom-abuseipdb.py /var/log/abuseipdb.json $ABUSEIPDB_API sshd debug
# Running AbuseIPDB IP script
# Opening alert file at '/var/log/abuseipdb.json' with '{'timestamp': '2025-07-21T12:41:18.157+0000', 'rule': {'level': 5, 'description': 'sshd: Authentication succeeded from a public IP address 108.157.98.17.', 'id': '100003', 'firedtimes': 2, 'mail': False, 'groups': ['local', 'syslog', 'sshd', 'authentication_failed', 'authentication_success'], 'pci_dss': ['10.2.4', '10.2.5']}, 'agent': {'id': '000', 'name': 'rhel9.localdomain'}, 'manager': {'name': 'rhel9.localdomain'}, 'id': '1753101678.8211', 'full_log': 'Dec 10 01:02:02 host sshd[1234]: Accepted none for root from 108.157.98.17 port 1066 ssh2', 'predecoder': {'program_name': 'sshd', 'timestamp': 'Dec 10 01:02:02', 'hostname': 'host'}, 'decoder': {'parent': 'sshd', 'name': 'sshd'}, 'data': {'srcip': '108.157.98.17', 'srcport': '1066', 'dstuser': 'root'}, 'location': '/var/log/test.log'}'
# Alert output: {'abuseipdb': {'found': 0, 'source': {'alert_id': '1753101678.8211', 'rule': '100003', 'ip': '108.157.98.17'}}, 'integration': 'custom-abuseipdb', 'original_full_log': 'Dec 10 01:02:02 host sshd[1234]: Accepted none for root from 108.157.98.17 port 1066 ssh2'}
# Request result from AbuseIPDB server: 1:abuseipdb:{"abuseipdb": {"found": 0, "source": {"alert_id": "1753101678.8211", "rule": "100003", "ip": "108.157.98.17"}}, "integration": "custom-abuseipdb", "original_full_log": "Dec 10 01:02:02 host sshd[1234]: Accepted none for root from 108.157.98.17 port 1066 ssh2"}
```

**JSON event from archives (Clean IP - Not Found):**

```json
{
  "_index": "wazuh-alerts-4.x-low22-2025.12.11",
  "_id": "9woNDZsBEyaYxyhHiK5M",
  "_version": 1,
  "_score": null,
  "_source": {
    "input": {
      "type": "log"
    },
    "agent": {
      "name": "wazuh-server",
      "id": "000"
    },
    "manager": {
      "name": "wazuh-server"
    },
    "data": {
      "abuseipdb": {
        "found": "0",
        "source": {
          "alert_id": "1753101678.8211",
          "ip": "108.157.98.17",
          "rule": "100003"
        }
      },
      "integration": "custom-abuseipdb",
      "original_full_log": "Dec 10 01:02:02 host sshd[1234]: Accepted none for root from 108.157.98.17 port 1066 ssh2"
    },
    "rule": {
      "firedtimes": 1,
      "mail": false,
      "level": 3,
      "description": "Source IP 108.157.98.17 unknown per AbuseIPDB",
      "groups": [
        "local",
        "abuseipdb",
        "sshd"
      ],
      "id": "199802"
    },
    "event_fingerprint": "f77486d2fcd1b1b6f8e1968145850cf5e0333bdec8476b30c07a79cebb1cbbab",
    "location": "abuseipdb",
    "decoder": {
      "name": "json"
    },
    "id": "1765450544.10736222",
    "full_log": "{\"abuseipdb\": {\"found\": 0, \"source\": {\"alert_id\": \"1753101678.8211\", \"rule\": \"100003\", \"ip\": \"108.157.98.17\"}}, \"integration\": \"custom-abuseipdb\", \"original_full_log\": \"Dec 10 01:02:02 host sshd[1234]: Accepted none for root from 108.157.98.17 port 1066 ssh2\"}",
    "timestamp": "2025-12-11T11:55:44.091+0100"
  },
  "fields": {
    "timestamp": [
      "2025-12-11T10:55:44.091Z"
    ]
  },
  "highlight": {
    "rule.groups": [
      "@opensearch-dashboards-highlighted-field@abuseipdb@/opensearch-dashboards-highlighted-field@"
    ]
  },
  "sort": [
    1765450544091
  ]
}
```

</details>

#### Test 2: Malicious IP

<details>
<summary>Testing with a known malicious IP address</summary>

```bash
[root@wazuh-server ~]# python3 /var/ossec/integrations/custom-abuseipdb.py /var/log/abuseipdb_malicious.json $ABUSEIPDB_API sshd debug
# Running AbuseIPDB IP script
# Opening alert file at '/var/log/abuseipdb_malicious.json' with '{'timestamp': '2025-07-21T12:41:18.157+0000', 'rule': {'level': 5, 'description': 'sshd: Authentication succeeded from a public IP address 64.62.197.132.', 'id': '100003', 'firedtimes': 2, 'mail': False, 'groups': ['local', 'syslog', 'sshd', 'authentication_failed', 'authentication_success'], 'pci_dss': ['10.2.4', '10.2.5']}, 'agent': {'id': '000', 'name': 'rhel9.localdomain'}, 'manager': {'name': 'rhel9.localdomain'}, 'id': '1753101678.8211', 'full_log': 'Dec 10 01:02:02 host sshd[1234]: Accepted none for root from 64.62.197.132 port 1066 ssh2', 'predecoder': {'program_name': 'sshd', 'timestamp': 'Dec 10 01:02:02', 'hostname': 'host'}, 'decoder': {'parent': 'sshd', 'name': 'sshd'}, 'data': {'srcip': '64.62.197.132', 'srcport': '1066', 'dstuser': 'root'}, 'location': '/var/log/test.log'}'
# Alert output: {'abuseipdb': {'found': 1, 'source': {'alert_id': '1753101678.8211', 'rule': '100003', 'ip': '64.62.197.132'}, 'abuse_confidence_score': 100, 'country_code': 'US', 'usage_type': 'Fixed Line ISP', 'isp': 'The Shadowserver Foundation, Inc.', 'domain': 'shadowserver.org', 'total_reports': 2216, 'last_reported_at': '2025-12-11T09:02:57+00:00', 'permalink': 'https://www.abuseipdb.com/check/64.62.197.132'}, 'integration': 'custom-abuseipdb', 'original_full_log': 'Dec 10 01:02:02 host sshd[1234]: Accepted none for root from 64.62.197.132 port 1066 ssh2'}
# Request result from AbuseIPDB server: 1:abuseipdb:{"abuseipdb": {"found": 1, "source": {"alert_id": "1753101678.8211", "rule": "100003", "ip": "64.62.197.132"}, "abuse_confidence_score": 100, "country_code": "US", "usage_type": "Fixed Line ISP", "isp": "The Shadowserver Foundation, Inc.", "domain": "shadowserver.org", "total_reports": 2216, "last_reported_at": "2025-12-11T09:02:57+00:00", "permalink": "https://www.abuseipdb.com/check/64.62.197.132"}, "integration": "custom-abuseipdb", "original_full_log": "Dec 10 01:02:02 host sshd[1234]: Accepted none for root from 64.62.197.132 port 1066 ssh2"}
```

**JSON event from archives (Malicious - 100% Confidence):**

```json
{
  "_index": "wazuh-alerts-4.x-2025.12.11",
  "_id": "_goNDZsBEyaYxyhHo67F",
  "_version": 1,
  "_score": null,
  "_source": {
    "input": {
      "type": "log"
    },
    "agent": {
      "name": "wazuh-server",
      "id": "000"
    },
    "manager": {
      "name": "wazuh-server"
    },
    "data": {
      "abuseipdb": {
        "country_code": "US",
        "last_reported_at": "2025-12-11T09:02:57+00:00",
        "found": "1",
        "total_reports": "2216",
        "usage_type": "Fixed Line ISP",
        "isp": "The Shadowserver Foundation, Inc.",
        "domain": "shadowserver.org",
        "abuse_confidence_score": "100",
        "source": {
          "alert_id": "1753101678.8211",
          "ip": "64.62.197.132",
          "rule": "100003"
        },
        "permalink": "https://www.abuseipdb.com/check/64.62.197.132"
      },
      "integration": "custom-abuseipdb",
      "original_full_log": "Dec 10 01:02:02 host sshd[1234]: Accepted none for root from 64.62.197.132 port 1066 ssh2"
    },
    "rule": {
      "firedtimes": 1,
      "mail": true,
      "level": 13,
      "hipaa": [
        "164.312.b"
      ],
      "pci_dss": [
        "11.4"
      ],
      "tsc": [
        "CC6.1",
        "CC6.8",
        "CC7.2",
        "CC7.3"
      ],
      "description": "Source IP 64.62.197.132 flagged malicious with a 100% confidence score per AbuseIPDB",
      "groups": [
        "local",
        "abuseipdb",
        "sshdabuseipdb_critical"
      ],
      "id": "199806",
      "nist_800_53": [
        "SI.4"
      ],
      "gpg13": [
        "4.12"
      ],
      "gdpr": [
        "IV_35.7.d"
      ]
    },
    "event_fingerprint": "708c03c3ce7e583662ca0a564f6b444850fb552917ea05ceb03e47f062f2cda5",
    "location": "abuseipdb",
    "decoder": {
      "name": "json"
    },
    "id": "1765450551.10736922",
    "full_log": "{\"abuseipdb\": {\"found\": 1, \"source\": {\"alert_id\": \"1753101678.8211\", \"rule\": \"100003\", \"ip\": \"64.62.197.132\"}, \"abuse_confidence_score\": 100, \"country_code\": \"US\", \"usage_type\": \"Fixed Line ISP\", \"isp\": \"The Shadowserver Foundation, Inc.\", \"domain\": \"shadowserver.org\", \"total_reports\": 2216, \"last_reported_at\": \"2025-12-11T09:02:57+00:00\", \"permalink\": \"https://www.abuseipdb.com/check/64.62.197.132\"}, \"integration\": \"custom-abuseipdb\", \"original_full_log\": \"Dec 10 01:02:02 host sshd[1234]: Accepted none for root from 64.62.197.132 port 1066 ssh2\"}",
    "timestamp": "2025-12-11T11:55:51.924+0100"
  },
  "fields": {
    "timestamp": [
      "2025-12-11T10:55:51.924Z"
    ]
  },
  "highlight": {
    "rule.groups": [
      "@opensearch-dashboards-highlighted-field@abuseipdb@/opensearch-dashboards-highlighted-field@"
    ]
  },
  "sort": [
    1765450551924
  ]
}
```

</details>

#### Test 3: Error Handling

<details>
<summary>Testing error handling with an invalid API key:</summary>

```bash
[root@wazuh-server ~]# python3 /var/ossec/integrations/custom-abuseipdb.py /var/log/abuseipdb.json INVALID_KEY sshd debug
# Running AbuseIPDB IP script
# Opening alert file at '/var/log/abuseipdb.json' with '{'timestamp': '2025-07-21T12:41:18.157+0000', 'rule': {'level': 5, 'description': 'sshd: Authentication succeeded from a public IP address 108.157.98.17.', 'id': '100003', 'firedtimes': 2, 'mail': False, 'groups': ['local', 'syslog', 'sshd', 'authentication_failed', 'authentication_success'], 'pci_dss': ['10.2.4', '10.2.5']}, 'agent': {'id': '000', 'name': 'rhel9.localdomain'}, 'manager': {'name': 'rhel9.localdomain'}, 'id': '1753101678.8211', 'full_log': 'Dec 10 01:02:02 host sshd[1234]: Accepted none for root from 108.157.98.17 port 1066 ssh2', 'predecoder': {'program_name': 'sshd', 'timestamp': 'Dec 10 01:02:02', 'hostname': 'host'}, 'decoder': {'parent': 'sshd', 'name': 'sshd'}, 'data': {'srcip': '108.157.98.17', 'srcport': '1066', 'dstuser': 'root'}, 'location': '/var/log/test.log'}'
# Request result from AbuseIPDB server: 1:abuseipdb:{"abuseipdb": {"error": 401, "description": "Error: Unauthorized (check API key)"}, "integration": "custom-abuseipdb", "original_full_log": "Dec 10 01:02:02 host sshd[1234]: Accepted none for root from 108.157.98.17 port 1066 ssh2"}
```

**JSON event from archives (Error - Unauthorized):**

```json
{
  "_index": "wazuh-alerts-4.x-low22-2025.12.11",
  "_id": "9AoNDZsBEyaYxyhHTa6z",
  "_version": 1,
  "_score": null,
  "_source": {
    "input": {
      "type": "log"
    },
    "agent": {
      "name": "wazuh-server",
      "id": "000"
    },
    "manager": {
      "name": "wazuh-server"
    },
    "data": {
      "abuseipdb": {
        "description": "Error: Unauthorized (check API key)",
        "error": "401"
      },
      "integration": "custom-abuseipdb",
      "original_full_log": "Dec 10 01:02:02 host sshd[1234]: Accepted none for root from 108.157.98.17 port 1066 ssh2"
    },
    "rule": {
      "firedtimes": 1,
      "mail": false,
      "level": 5,
      "description": "Error in custom AbuseIPDB integration - Error: Unauthorized (check API key)",
      "groups": [
        "local",
        "abuseipdb",
        "sshdabuseipdb_error"
      ],
      "id": "199807"
    },
    "event_fingerprint": "dfa19330868e36e696993c941eead87ee0725ab1f2f7346dd0788952c4dd435f",
    "location": "abuseipdb",
    "decoder": {
      "name": "json"
    },
    "id": "1765450523.10735551",
    "full_log": "{\"abuseipdb\": {\"error\": 401, \"description\": \"Error: Unauthorized (check API key)\"}, \"integration\": \"custom-abuseipdb\", \"original_full_log\": \"Dec 10 01:02:02 host sshd[1234]: Accepted none for root from 108.157.98.17 port 1066 ssh2\"}",
    "timestamp": "2025-12-11T11:55:23.902+0100"
  },
  "fields": {
    "timestamp": [
      "2025-12-11T10:55:23.902Z"
    ]
  },
  "highlight": {
    "rule.groups": [
      "@opensearch-dashboards-highlighted-field@abuseipdb@/opensearch-dashboards-highlighted-field@"
    ]
  },
  "sort": [
    1765450523902
  ]
}
```

</details>