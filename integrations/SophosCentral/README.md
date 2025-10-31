# Sophos Central → Wazuh Integration

This repository contains a Python script that collects events from the **Sophos Central SIEM API** and sends them to Wazuh using socket queue.

It is designed to be executed periodically using the **Wazuh `command` wodle**, ensuring that new events are continuously ingested.
---

## 📌 Introduction

The main steps for the script are the following:

1. **Authenticates** to Sophos Central using OAuth2 Client Credentials.
2. **Fetches events** in batches using the `cursor` parameter until no more events remain.
3. **Sends each event** to Wazuh’s local socket (`/var/ossec/queue/sockets/queue`) as a clean JSON object, tagged with the location `wazuh_sophos`.

---

## ⚙️ Wodle Configuration

To run this integration automatically every minute, add the following configuration to `/var/ossec/etc/ossec.conf`:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>wazuh_sophos</tag>
  <command>/var/ossec/framework/python/bin/python3 /var/ossec/wodles/custom_wazuh_sophos.py --client-id "CLIENT_ID" --client-secret "CLIENT_SECRET" --tenant-id "TENANT_ID"</command>
  <interval>1m</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>
```

🚀 Usage Example
```
Sophos Central to Wazuh Integration Script with In-Memory Scroll

optional arguments:
  -h, --help            show this help message and exit
  --client-id CLIENT_ID
                        Sophos Central Client ID
  --client-secret CLIENT_SECRET
                        Sophos Central Client Secret
  --tenant-id TENANT_ID
                        Sophos Central Tenant ID
  --api-host API_HOST   Sophos API Host (region-specific)
  --limit LIMIT         Number of events per request (default: 200)
```

Manual execution for testing:
```
/var/ossec/framework/python/bin/python3 \
  /var/ossec/wodles/custom_wazuh_sophos.py \
  --client-id "xxxxxxxxxxxxxxxxxxxx" \
  --client-secret "xxxxxxxxxxxxxxxxxxxx" \
  --tenant-id "xxxxxxxxxxxxxxxxxxxx"
```
📊 Output Format in Wazuh

Each event is forwarded as JSON with this structure:
```json
{
  "wazuh_sophos": {
    "endpoint_id": "XXXXXXXX",
    "endpoint_type": "computer",
    "user_id": "XXXXXXXXX",
    "created_at": "2025-09-16T02:55:03.676Z",
    "source_info": {"ip": "192.168.11.27"},
    "customer_id": "2400dbf5-f151-43cc-a078-6dc4c4409593",
    "severity": "low",
    "type": "Event::Endpoint::Application::Detected",
    "source": "Pilotos Administrativo",
    "location": "PILOTOS-PC2",
    "id": "XXXXX",
    "group": "APPLICATION_CONTROL"
  }
}
```