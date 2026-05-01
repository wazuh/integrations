 # Google Workspace-Wazuh Integration

 ## Table of Contents

 * [Introduction](#introduction)
 * [Prerequisites](#prerequisites)
 * [Installation and Configuration](#installation-and-configuration)
     * [1. Create a GCP Service Account](#1-create-a-gcp-service-account)
     * [2. Create a Google Workspace Service Account](#2-create-a-google-workspace-service-account)
     * [3. Configure the Wazuh Agent](#3-configure-the-wazuh-agent)
     * [4. Multi-Account Configuration](#4-multi-account-configuration)
     * [5. Configure the Wazuh Manager](#5-configure-the-wazuh-manager)
 * [Integration Steps](#integration-steps)
 * [Integration Testing](#integration-testing)

 ---

 ### Introduction

 This integration provides the capability to monitor Google Workspace events using Wazuh. It utilizes a custom Python "wodle" running on the agent to query the Google Admin SDK and Alert Center APIs.

 Multi-Account Support: This integration supports monitoring multiple Google Workspace tenants simultaneously by using specific configuration file naming conventions.

 ---

 ### Prerequisites

 * Wazuh Agent: A Linux agent where the script will run.
 * Python 3: Required on the agent to run the extraction script.
 * Google Cloud Platform (GCP) Project: To create credentials for API access.
 * Google Workspace Admin Access: To grant domain-wide delegation to the service account.

 ---

 ### Installation and Configuration

 #### 1. Create a GCP Service Account

 First, you will create a GCP service account. This service account will use Domain-wide delegation to impersonate a Google Workspace service account to access events and alerts.

 1. Go to the [Google Cloud Console](https://console.cloud.google.com/) and create a new project called Wazuh.
 2. In Enabled API & services, enable:
    * Admin SDK API
    * Alert Center API
 3. In the API & Services menu, select the Credentials screen and create a service account (e.g., name it "Wazuh monitoring").
 4. Important: Note down the Client ID; you will need it later.
 5. Select the "Keys" option from the horizontal menu and add a new JSON key.
 6. Save this JSON file securely. It will be used to configure the agent.

 #### 2. Create a Google Workspace Service Account

 Now, in the Google Workspace admin console, allow the GCP service account Domain-wide delegation.

 1. Enter the Client ID from the previous step and grant it the following scopes:
    * [admin.reports.audit.readonly](https://www.googleapis.com/auth/admin.reports.audit.readonly)
    * [apps.alerts](https://www.googleapis.com/auth/apps.alerts)

 Next, create a Google Workspace user that Wazuh will impersonate. To avoid costs and risks, we will create a user without a license.

 2. Create a new Organizational Unit (OrgUnit) called "Service accounts".
 3. Change the License settings for that OrgUnit so that licenses are not automatically assigned (turn off auto-assignment).
 4. Create a new user in that OrgUnit (e.g., First Name: "SVC Wazuh", Last Name: "Monitoring", Email: svc-wazuh-monitoring@yourdomain.com).
 5. Privileges:
    * In Admin roles and privileges, assign the Reports role.
    * In Alert Center, check View access.
 6. Checks:
    * Verify in Licenses that the user does not have a paying license.
    * Verify in Apps that the user does not have access to unnecessary apps.
    * You can discard the password for this user; the GCP service account will impersonate it via API.
 7. Security: Depending on your policies, you may need to disable 2-step verification or password change requirements for this specific OrgUnit.

 #### 3. Configure the Wazuh Agent

 On the Linux machine where the agent is installed, perform the following steps as root.

 A. Install Dependencies
 The agent has its own internal Python environment. Use it to install the Google library:

 ```bash
 /var/ossec/framework/python/bin/python3 -m pip install google-api-python-client
 ```

 B. Setup the Wodle Directory

 ```bash
 mkdir -p /var/ossec/wodles/gworkspace
 ```

 Move the provided files into this directory:
 * Copy [wodles/gworkspace/gworkspace](wodles/gworkspace/gworkspace) to `/var/ossec/wodles/gworkspace/gworkspace`
 * Copy [wodles/gworkspace/gworkspace.py](wodles/gworkspace/gworkspace.py) to `/var/ossec/wodles/gworkspace/gworkspace.py`

 Ensure they are executable and owned by Wazuh:

 ```bash
 chmod +x /var/ossec/wodles/gworkspace/gworkspace
 chown -R wazuh:wazuh /var/ossec/wodles/gworkspace
 ```

 C. Add Credentials (Single/Default Account)

 1. Key File: Paste the content of your downloaded GCP JSON key into:
    `/var/ossec/wodles/gworkspace/service_account_key.json`

 2. Config File: Create the configuration file. Replace <E-MAIL> with the email of the Google Workspace user you created in Step 2 (e.g., svc-wazuh-monitoring@yourdomain.com).

    ```json
    {
        "service_account": "<E-MAIL OF YOUR GOOGLE WORKSPACE SERVICE ACCOUNT>"
    }
    ```
    Save this as `/var/ossec/wodles/gworkspace/config.json`.

 3. Permissions: Ensure the wazuh user owns these files:
    ```bash
    chown wazuh:wazuh /var/ossec/wodles/gworkspace/*.json
    ```

 D. Local Agent Configuration
 Open the agent's config file `/var/ossec/etc/ossec.conf` and add the wodle block:

 ```xml
 <ossec_config>
   <wodle name="command">
     <disabled>no</disabled>
     <tag>gworkspace</tag>
     <command>/var/ossec/wodles/gworkspace/gworkspace -a all -o 2</command>
     <interval>10m</interval>
     <ignore_output>no</ignore_output>
     <run_on_start>yes</run_on_start>
     <timeout>0</timeout>
   </wodle>
 </ossec_config>
 ```

 Restart the agent:
 ```bash
 systemctl restart wazuh-agent
 ```

 #### 4. Multi-Account Configuration

 The script supports monitoring multiple Google Workspace tenants using a tagging system based on filenames.

 * Default Account: Uses config.json and service_account_key.json. Logs appear with tag default.
 * Additional Accounts: Create files with a suffix _<identifier>.

 Example for a "Marketing" tenant:
 1. Create config file: `/var/ossec/wodles/gworkspace/config_marketing.json` containing the marketing service account email.
 2. Create key file: `/var/ossec/wodles/gworkspace/service_account_key_marketing.json` containing the GCP JSON key for that tenant.
 3. The logs will automatically contain the field data.gworkspace.source_account: marketing.

 Just place these files in the same directory. The script automatically scans for them.

 #### 5. Configure the Wazuh Manager

 Step 1: Add Custom Rules
 1. Go to Server Management > Rules.
 2. Click Manage rules files > + Create new rules file.
 3. Name it gworkspace_rules.xml.
 4. Paste the content from [ruleset/rules/gworkspace_rules.xml](ruleset/rules/gworkspace_rules.xml).
 5. Save and Restart the Manager.

 Step 2: Add Custom Dashboard
 1. Download [dashboards/gworkspace_dashboard.ndjson](dashboards/gworkspace_dashboard.ndjson).
 2. Go to Stack Management > Saved Objects > Import.
 3. Upload the .ndjson file.

 ---

 ### Integration Steps

 1. Agent Execution: The Agent runs the Python script every 10 minutes.
 2. API Query: The script queries Google APIs for all configured accounts.
 3. Output: The script outputs JSON logs to stdout.
 4. Ingestion: The Wazuh Agent captures the output and sends it to the Manager.
 5. Alerting: The Manager decodes the JSON and matches it against gworkspace_rules.xml.

 ---

 ### Integration Testing

 1. Trigger an Event: Log in to the Google Workspace admin console or create a file in Drive using a monitored user account.
 2. Check Logs: Wait for the wodle interval (10m) or restart the agent to force a run. Check the log file generated by the script (if debug is enabled) or the Wazuh archives.
 3. Verify Dashboard: Open the Google Workspace Multi-Account Dashboard to see the visualized events.
