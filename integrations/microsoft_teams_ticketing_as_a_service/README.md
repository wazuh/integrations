# Wazuh Alerts Integration with Microsoft Teams Using Ticketing as a Service

This repository provides a guide and custom script to integrate Wazuh alerts with Microsoft Teams using the "Ticketing as a Service" application. This solution enables automated alert delivery to a Teams channel, ticket creation in the ticketing system, and efficient security incident management within Teams, optimizing your security workflows.

## Table of Contents
- [Overview](#overview)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Steps](#steps)
    - [Step 1: Add the Ticketing as a Service App to Microsoft Teams](#step-1-add-the-ticketing-as-a-service-app-to-microsoft-teams)
    - [Step 2: Configure Wazuh Manager](#step-2-configure-wazuh-manager)
    - [Step 3: Get Your API Key](#step-3-get-your-api-key)
    - [Step 4: Add the Custom Script](#step-4-add-the-custom-script)
    - [Step 5: Install the Script](#step-5-install-the-script)
    - [Step 6: Restart Wazuh Manager](#step-6-restart-wazuh-manager)
- [How It Works](#how-it-works)
- [Notes](#notes)

## Overview
This integration leverages the "Ticketing as a Service" app to bridge Wazuh security alerts with Microsoft Teams, enabling real-time notifications and automated ticket creation. Ideal for security teams, this setup enhances incident response by centralizing alerts and case management in a familiar Teams environment. The provided custom script and configuration steps ensure a smooth integration process, customizable to your organization's needs.

## Getting Started

### Prerequisites
- A running Wazuh Manager installation.
- Access to a Microsoft Teams environment with appropriate permissions.
- The "Ticketing as a Service" app available in your Teams instance.

### Steps

#### Step 1: Add the Ticketing as a Service App to Microsoft Teams
Incorporate the "Ticketing as a Service" app into your Teams channel with these steps:

1. Navigate to the desired Teams channel.
2. Click the "+" (plus) icon at the top of the channel.
3. Enter "Ticketing as a Service" in the search bar.
4. Select the app from the results.
5. Name the tab (e.g., "Wazuh Alerts") and click **Save**.

The app is now integrated into your channel, ready for Wazuh alert configuration.

#### Step 2: Configure Wazuh Manager
Modify the Wazuh Manager configuration file (`ossec.conf`) to connect with the ticketing service.

1. Edit the `ossec.conf` file, typically found at `/var/ossec/etc/ossec.conf`.
2. Insert the following `<integration>` block within the `<ossec_config>` section:

```xml
<integration>
  <name>custom-ticketing</name>
  <hook_url>https://ticketing-apim-aus.azure-api.net/ticketing/v1/tickets?key=your_api_key</hook_url>
  <api_key>your_api_key</api_key>
  <level>12</level> <!-- Minimum alert level to trigger the integration -->
  <alert_format>json</alert_format>
</integration>
```
Configuration Details

`<name>`: Set to custom-ticketing to align with the upcoming script.

`<hook_url>`: The ticketing service endpoint. Replace your_api_key with your actual key (see Step 3). Choose the regional URL:

Australia: https://ticketing-apim-aus.azure-api.net/ticketing/v1/tickets?key=your_api_key
Europe: https://ticketing-apim-eu.azure-api.net/ticketing/v1/tickets?key=your_api_key
US (Global): https://teamswork.azure-api.net/ticketing/v1/tickets?key=your_api_key


`<api_key>`: Use the same API key for authentication.
`<level>`: Triggers integration for alerts at this level or higher (e.g., 12). Adjust as needed.
`<alert_format>`: Set to json for script compatibility.

Step 3: Get Your API Key
Retrieve your API key from the "Ticketing as a Service" app:

Open the app in Teams.
Go to Settings > API.
Copy the API key and insert it into the <hook_url> and <api_key> fields in ossec.conf.

Step 4: Add the Custom Script
Wazuh requires a custom script to process and send alerts. The script is available here: Wazuh-Integrations.
Customize the Script

Download the script and modify the generate_msg function to suit your environment. Default version:

```
    def generate_msg(alert):
    timestamp = alert.get('timestamp', datetime.now(timezone.utc).isoformat())
    description = alert.get('rule', {}).get('description', 'No description available')
    return {
        "ticket": {
            "title": f"Wazuh Alert: {description}",
            "description": f"Alert received at {timestamp}. Details: {description}",
            "customFields": {"timestamp": timestamp},
            "requestor": {
                "id": "71785f5f-83a1-4616-a20a-c507a817742a",
                "name": "Hasitha Upekshitha",
                "email": "user@domain.com"
            }
        },
        "user": {
            "id": "71785f5f-83a1-4616-a20a-c507a817742a",
            "name": "Hasitha Upekshitha",
            "email": "user@domain.com"
        }
    }
```

Changes to Make:

Update requestor and user details (id, name, email) with your admin user's information.
To find your admin user’s details:

Create a manual case in the app and assign it to your admin user.
Run this curl command:
`curl -X GET "https://ticketing-apim-aus.azure-api.net/ticketing/v1/tickets?timezone=0&orderBy=status&order=ASC&select=id,ticketId,title,description,status,requestorName&offset=0&limit=20" -H "Ocp-Apim-Subscription-Key: your_api_key"`

Extract the id, name, and email from the response and update the script.

Step 5: Install the Script
Deploy the customized script to the Wazuh integrations directory:

Move the script files (e.g., custom-ticketing and dependencies) to /var/ossec/integrations/.
Set ownership and permissions:
`chown root:wazuh /var/ossec/integrations/custom-ticketing*`
`chmod 750 /var/ossec/integrations/custom-ticketing*`


Step 6: Restart Wazuh Manager
Apply the changes by restarting the Wazuh Manager:
`systemctl restart wazuh-manager`

How It Works

For alerts with a level of 12 or higher:

The alert is routed to the custom-ticketing integration.
The script formats it into a ticket, including a title, description, and your admin user as the requestor, with priority set based on alert severity.
The ticket is displayed in your Teams channel under the "Ticketing as a Service" tab.

Notes

Replace your_api_key and user details with your actual values.
Ensure the script is executable and compatible with your Wazuh version.
For troubleshooting, review /var/ossec/logs/ossec.log for integration errors.
