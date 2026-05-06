# Wazuh Alerts IOC Enrichment Using Opensearch Alerting

---

## Table of Contents
- [Tested Version](#tested-version)
- [Overview](#overview)
  - [Enriched Alert Example](#enriched-alert-example)
  - [Prerequisite](#prerequisite)
- [Step 1: Obtain a MISP API Key](#step-1-obtain-a-misp-api-key)
- [Step 2: Configure Notification Channel](#step-2-configure-notification-channel)
- [Step 3: Create a Monitor](#step-3-create-a-monitor)
- [Step 4: Install Required Packages](#step-4-install-required-packages)
- [Step 5: Add Custom Scripts](#step-5-add-custom-scripts)
- [Step 6: Configure as a Service](#step-6-configure-as-a-service)
- [Testing](#testing)
- [Conclusion](#conclusion)
- [Reference](#reference)

## Tested Version
| Wazuh version | Component | Deployment Type | OS |
|---|---|---|---|
| 4.14.4 | Wazuh Indexer | OVA | Amazon Linux |

## Overview
This guide explains how to integrate Wazuh with MISP Threat Intelligence to automatically enrich alerts with IOCs (Indicators of Compromise) matching against IPs, Hashes, Domains, and URLs directly inside the **same alert**.

In this integration, a Wazuh Monitor runs every minute to check for alerts triggered within the last ten minutes that match specific rule IDs indicating potential security anomalies. These alerts are pushed to a Python Flask enrichment service via a webhook configured in the Wazuh Notification Channel. 

Simultaneously, a scheduled fetcher permanently synchronizes current MISP malicious indicators (Domains, IPs) directly to lightweight SQLite databases locally on the server, mapping offline Geolocation contexts completely natively without external IP rate limits. When a Wazuh alert matches a local IOC inside these `.db` files, the Flask API immediately updates and tags the exact OpenSearch document with context.

### Enriched Alert Example
<img width="1175" height="1847" alt="image" src="https://github.com/user-attachments/assets/48af461a-1b0d-4dee-afc7-911f212cee09" />


### Prerequisite 

- **MISP API Key** (from your MISP Dashboard)  
- **Wazuh Indexer CLI access and Dashboard Admin Access** (To create notification channel and Monitor)  

### Step 1: Obtain a MISP API Key
1. Log in to your MISP instance.  
2. Navigate to your Auth Keys and generate a new key.  
3. Save the key securely and ensure your MISP instance is explicitly reachable from your Wazuh server via URL.

### Step 2: Configure Notification Channel
Run the following command on your Wazuh Indexer server to create a Webhook Notification Channel. This instructs OpenSearch where the integration webhook lives:

```bash
curl -k -u admin:admin -H 'Content-Type: application/json' \
  -X POST 'https://<indexer-IP>:9200/_plugins/_notifications/configs/' \
  -d '{
    "config_id": "IOC-enrich-webhook-3000-enrich",
    "name": "IOC-enrich-webhook-3000-enrich",
    "config": {
      "name": "IOC-enrich-webhook-3000-enrich",
      "description": "Send monitor alerts to IOC enrichment",
      "config_type": "webhook",
      "is_enabled": true,
      "webhook": {
        "url": "http://127.0.0.1:3000/enrich"
      }
    }
  }'
```
*(Replace `admin:admin` with your Wazuh Dashboard administration credentials and adjust `<indexer-IP>` if needed.)*

Copy and save the returned `config_id` exactly as defined (`IOC-enrich-webhook-3000-enrich`) — it is securely linked in the monitor script.

### Step 3: Create a Monitor
Use this API call to instruct OpenSearch to monitor Rule IDs mapping to our configurations and forward them to the webhook:

```bash
curl -k -u admin:admin -X POST "https://<indexer-IP>:9200/_plugins/_alerting/monitors" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "monitor",
    "name": "wazuh-ioc-enrich-monitor",
    "monitor_type": "query_level_monitor",
    "enabled": true,
    "schedule": {
      "period": {
        "interval": 1,
        "unit": "MINUTES"
      }
    },
    "inputs": [
      {
        "search": {
          "indices": ["wazuh-alerts-*"],
          "query": {
            "size": 100,
            "sort": [
              {
                "@timestamp": {
                  "order": "desc"
                }
              }
            ],
            "_source": true,
            "query": {
              "bool": {
                "filter": [
                  {
                    "range": {
                      "@timestamp": {
                        "gte": "{{period_end}}||-10m",
                        "lte": "{{period_end}}",
                        "format": "epoch_millis"
                      }
                    }
                  },
                  {
                    "terms": {
                      "rule.id": ["5760", "554"]
                    }
                  }
                ],
                "must_not": [
                  {
                    "term": {
                      "ioc_check_status": true
                    }
                  }
                ]
              }
            }
          }
        }
      }
    ],
    "triggers": [
      {
        "name": "send-to-ioc-enrich",
        "severity": "1",
        "condition": {
          "script": {
            "source": "ctx.results[0].hits.total.value > 0",
            "lang": "painless"
          }
        },
        "actions": [
          {
            "name": "webhook-ioc-enrich",
            "destination_id": "IOC-enrich-webhook-3000-enrich",
            "message_template": {
              "source": "{\"secret\":\"<YOUR_WEBHOOK_SECRET>\",\"hits\":{{#toJson}}ctx.results.0.hits.hits{{/toJson}}}"
            },
            "throttle_enabled": false
          }
        ]
      }
    ]
  }'
```

> **Important:** You MUST replace `<YOUR_WEBHOOK_SECRET>` in the `message_template` source above with a secure, random string of your choice.

You can update the above command by adding more rule id or can modify the query section to check other alerts also based on your requirement.

### Step 4: Install Required Packages
Install Python and pip packages securely for the webhook:

For Ubuntu/Debian:
```bash
apt update
apt install -y python3 python3-pip
```

For CentOS/RHEL/Amazon Linux:
```bash
yum install -y python3 python3-pip
```

Install Python Dependencies:
```bash
pip3 install flask requests
```

### Step 5: Add Custom Scripts
1. Create and position the Python Scripts:
Copy the provided packaged source scripts into the Wazuh Integrations directory:
```bash
mkdir -p /var/ossec/integrations/ioc
```
Copy and paste the `misp_ioc_fetcher.py` & `misp_enricher.py` into `/var/ossec/integrations/` directory in the same name.

2. Generate the Environment File:
```bash
sudo nano /var/ossec/integrations/.env
```
Populate the environment configuration mapping directly to your MISP instance. **Important:** Ensure `WEBHOOK_SECRET` matches the secret defined in the Monitor payload (Step 3).
```bash
MISP_URL=https://your-misp-server
MISP_AUTH_KEY=<YOUR_REAL_KEY>
WEBHOOK_SECRET=<YOUR_WEBHOOK_SECRET>
MISP_VERIFYCERT=false
IOC_DIR=/var/ossec/integrations/ioc
LAST_DAYS=30
```

3. Set permissions exactly for execution:
```bash
chmod +x /var/ossec/integrations/misp_*.py
chmod 644 /var/ossec/integrations/.env
```
> **Note:** The `.env` file must be readable (644) so the `wazuh` system user can access the webhook secret and API keys when the service starts!

### Step 6: Configure as a Service
We have bundled 3 highly-tuned Linux `systemd` Daemons to handle this automation.
1. `misp-enricher.service`: An always-on Flask webhook listening on port `3000`.
2. `misp-fetcher.service`: A one-shot executor that pulls and maps SQLite records.
3. `misp-fetcher.timer`: A background system scheduler that triggers the fetcher service exactly twice a day.

1. Deploy the unit files:
```bash
cp misp-*.service /etc/systemd/system/
cp misp-*.timer /etc/systemd/system/
sudo systemctl daemon-reload
```

2. Enable and start the Webhook & Automation Timer:
```bash
sudo systemctl enable --now misp-enricher.service
sudo systemctl enable --now misp-fetcher.timer
```

3. Verify service status:
```bash
sudo systemctl status misp-enricher.service
sudo systemctl status misp-fetcher.timer
sudo ss -tlnp | grep 3000
```
> Note: If you want to force an immediate MISP IOC pull, execute: `sudo systemctl start misp-fetcher.service`

## Testing
Once configuration is complete:
- Force the fetcher to load MISP indicators via `sudo systemctl start misp-fetcher.service`.
- Trigger alerts matching any of the configured `rule.id` values (e.g., matching a domain or IP from your MISP feed).
- Wait 1 minute for OpenSearch monitor enrichment.
- Open the Wazuh Dashboard and view the enriched alert!

It should now natively contain `ioc_hits.ips` arrays detailing precise geographic infrastructure parameters from our locally updated GeoIP DB mapped to the MISP threat Intel definitions.

## Conclusion
By integrating Wazuh fully with a natively cached MISP python instance, you can automatically aggressively cross-reference every network log to MISP Threat feeds entirely offline without exhausting MISP API keys or OpenSearch network resources, establishing extremely competent SOC foundations!

## Reference
- [Wazuh Documentation](https://wazuh.com/docs/)
- [Opensearch Alerting](https://docs.opensearch.org/latest/observing-your-data/alerting/index/)
- [Opensearch Notifications](https://docs.opensearch.org/latest/observing-your-data/notifications/index/)
