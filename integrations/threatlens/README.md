# Wazuh to Threatlens Integration

This custom integration script connects **Wazuh** to **Threatlens**, forwarding security alerts in real-time.

It is designed to run natively within the Wazuh environment without requiring external Python libraries (like `requests`), using only the standard library (`urllib`). It also includes specific handling for **WAF bypass** (Cloudflare) and proper **JSON formatting** required by the Threatlens API.

## Features

* **Zero Dependencies**: Uses Python's built-in `urllib` library, so no `pip install` is required on the Wazuh manager.
* **WAF Bypass**: Includes a spoofed User-Agent header to prevent 403 Forbidden errors (Cloudflare Error 1010).
* **JSON Wrapper**: Automatically wraps Wazuh alerts in the `{"alert": { ... }}` format required by Threatlens.
* **Debug Logging**: detailed logging to `/var/ossec/logs/integrations.log`.

## Prerequisites

* Wazuh Manager (v4.x)
* Python 3 (Pre-installed with Wazuh)
* Threatlens API Key and Webhook URL

## Installation

### 1. Deploy the script

Place the script `custom-threatlens` in the Wazuh integrations directory: `/var/ossec/integrations/`.

### 2. Give the necessary permissions

```
sudo chmod 750 /var/ossec/integrations/custom-threatlens
sudo chown root:wazuh /var/ossec/integrations/custom-threatlens
```

### 3. Configure Wazuh Manger's settings.

Go to `/var/ossec/etc/ossec.conf`or through the UI at **Hamburguer Menu ☰** > **Server Management** > **Settings** > **Edit Configuration** and paste a configuration similar to this:

```
<integration>
  <name>custom-threatlens</name>
  <hook_url>YOUR_WEBHOOK_HERE</hook_url>
  <api_key>YOUR_THREATLENS_API_KEY</api_key>
  <level>10</level> 
  <alert_format>json</alert_format>
</integration>
```

### 4. Restart Wazuh

```
systemctl restart wazuh-manager
```

## Troubleshooting

### Check logs

You can check that the integration is working correctly by running the following command:
```
tail -f /var/ossec/logs/integrations.log
```

