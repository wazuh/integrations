# Google Chronicle (SecOps) API Integration for Wazuh

This Python script enables integration between **Wazuh** and **Google Chronicle (Google SecOps)** by forwarding Wazuh alerts to a Chronicle feed using a webhook.

---

## Features

- Sends alerts to Google Chronicle via HTTP POST

---
## Implementation

- touch /var/ossec/integration/custom-google-chronicle.py
- vim /var/ossec/integration/custom-google-chronicle.py
- paste the content provided on the custom-google-chronicle.py
- chown root:wazuh /var/ossec/integration/custom-google-chronicle.py
- chmod 750 /var/ossec/integration/custom-google-chronicle.py
- save the file and restart the wazuh manager.
---

## Configuration in `ossec.conf`

To configure this integration in Wazuh, add the following block inside `ossec.conf`:

```xml
<integration>
    <name>google-chronicle</name>
    <hook_url>https://<REGION>-chronicle.googleapis.com/v1alpha/projects/<PROJECT_NUMBER>/locations/<LOCATION>/instances/<CUSTOMER_ID>/feeds/<FEED_ID>:importPushLogs?key=<API_KEY>&secret=<SECRET></hook_url>
    <alert_format>json</alert_format>
    <level>0</level>
</integration>