# Salesforces-Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

---

### Introduction

The Salesforce–Wazuh integration enables centralised monitoring, security event analysis, and compliance tracking for Salesforce environments within the Wazuh Security Information and Event Management (SIEM) platform.

This integration utilises the Salesforce REST API with JWT-based authentication (private/public key pair) to securely collect logs and events, including login activities, configuration changes, and user behaviour, from Salesforce Event Monitoring (EventLogFile) or the Setup Audit Trail.

Wazuh periodically connects to Salesforce via a scheduled command wodle, retrieves the latest event data every few minutes, and normalises it into structured JSON. These events are then analysed using Wazuh decoders and rules, enabling the detection of anomalies, policy violations, or unauthorised access attempts..

---


### Prerequisites

Before starting, ensure the following:
* Administrator access to the target Salesforce org (to create a Connected App).
* OpenSSL (or equivalent) to generate an RSA key pair (private.pem and public.crt).
* Wazuh Manager access to edit /var/ossec/etc/ossec.conf and to place the Python script under `/var/ossec/integrations/`.
* Necessary network access or firewall rules.
* Python 3.8+ installed on the Wazuh host.


---

### Installation and Configuration

Tested on: Wazuh v4.13

Perform the following steps once to prepare Salesforce for Wazuh integration:

#### 2. **Install required Python dependencies**

Ensure `pip` is available and install the required packages:

```
python3 -m pip install --upgrade pip
pip install pyjwt cryptography requests
```
#### 2. **Generate an RSA key pair on your Wazuh server**
```
cd /var/ossec/integrations
openssl genpkey -algorithm RSA -out private.key -pkeyopt rsa_keygen_bits:2048
openssl req -x509 -key private.key -out public.crt -days 365
```
Set permissions:

```
chown root:wazuh /var/ossec/integrations/private.key /var/ossec/integrations/public.crt
chmod 600 /var/ossec/integrations/private.key
chmod 644 /var/ossec/integrations/public.crt
```
#### 3. **Create a Connected App in Salesforce**
   
Go to:
`Setup → Apps → External Client Apps → External Client App Manager`

<img width="911" height="249" alt="salesforce_setup_menu" src="https://github.com/user-attachments/assets/11aad318-eafc-465d-963e-02f88c9c6dd0" />

On the External Client App Manager tab, click on the **New External Client App** button

<img width="917" height="187" alt="external_client_app_manager" src="https://github.com/user-attachments/assets/9c14cec7-0478-43c4-a991-ef2c7840916f" />

Fill in the **Basic Information**, complete the required fields, including **External Client APP Name**, **API Name**, **Contact Email**, and **Distribution State**.

<img width="764" height="558" alt="salesforce_basic_information" src="https://github.com/user-attachments/assets/c3a6277b-2e33-4216-b977-9b0b67d406b9" />

On the same page, enable **OAuth** under API(Enable OAuth Settings). When you check Enable OAuth, a Dialogue box will appear on this Box. Fill the `Callback URL` and `OAuth Scopes` and also check some important fields under **Flow Enablement** and **Security**.

Callback URL: [https://login.salesforce.com/services/oauth2/success](url)

OAuth Scopes:
* Full access (full)
* Manage user data via APIs (api)
* Perform requests at any time (refresh_token, Offline_access)
  
In the Flow Enablement section, check **Enable JWT Bearer** Flow and upload the `public.crt from` `/var/ossec/integrations`.

Click on the **Create** Button

<img width="831" height="711" alt="salesforce_oauth_settings" src="https://github.com/user-attachments/assets/e3b146d1-a829-41ce-8a85-1e6c348030af" />

After clicking **Create**, the *Policies* page will appear. On this page. Click on the **Edit** button to modify the changes and change the **App Policies** from `None` to `OAuth` in the drop-down.

<img width="1332" height="405" alt="salesforce_app_policies" src="https://github.com/user-attachments/assets/6ea4db02-19a5-4b7f-bda5-73e096cb9ee2" />

Before clicking on the **Save** button, update the OAuth Policies

Under Plugin Policies:
* **Permitted Users**: All users can self-authorize
* **OAuth Start URL**: https://login.salesforce.com/services/oauth2/authorize 

Under App Authorization:
* **Refresh Token Policy**: Expire refresh token after a specific time
* **IP Relaxation**: Relax IP Restriction (For testing purposes) recommended: Enforce IP restrictions

After clicking **Save**, a **Consumer Key and Secret** Button will appear under the `External Client App Manager → Settings tab → OAuth Settings → App Settings`

Click **Consumer Key and Secret**. You will be prompted to enter a verification code sent to your registered email.

After verification, the `Consumer Key` and `Consumer Secret` will be displayed. Save both securely.


<img width="824" height="577" alt="salesforce_consumer_details" src="https://github.com/user-attachments/assets/3bc0f304-0fc4-4867-8952-0beeb721a146" />

Go back to External Client Apps, click Settings, and enable: `Allow access to external Client App consumer secrets via REST API`

<img width="1426" height="427" alt="salesforce_rest_api_access" src="https://github.com/user-attachments/assets/93720a73-082f-4a54-9c7f-28fa3bedb1b0" />

Finally, a Security Token is required for the integration user. If you already have one, skip this step. Otherwise:

Click your `profile icon` (top right corner) → `Settings`. Go to **Reset My Security Token** under **My Personal Information** and click **Reset Security Token**.

<img width="1283" height="475" alt="salesforce_reset_security_token" src="https://github.com/user-attachments/assets/2d98753e-96dc-48dc-b748-fae75f955a39" />


Salesforce will send the new token to your registered email address


#### 4. **Wazuh Manager Setup**

#### Add the integration script

Go to the `/var/ossec/integrations` directory, where you have generated the Private and Public Key, and now copy the Python script `custom-salesforce.py`.


Before using the script, open it and update the following variables with your Salesforce details:

* `CONSUMER_KEY`: The Consumer Key (Client ID) from your Salesforce Connected App.
* `USERNAME` : Salesforce integration user email.

What the script does
* This Python script securely connects to Salesforce Setup Audit Trail using JWT-based OAuth (no password), fetches new administrative activity logs, and outputs each audit event as a single one-line JSON object for Wazuh ingestion via wodle.
* JWT Authentication
  * Uses your Salesforce Connected App credentials: `CONSUMER_KEY` (client ID), `USERNAME` (integration user), `PRIVATE_KEY_PATH` (RSA key that matches the uploaded Salesforce certificate)
  * Creates and signs a JWT.
  * Exchanges it for a short-lived access token from Salesforce.
* Fetches SetupAuditTrail Logs
  * Builds an SOQL query
  * Uses the last seen timestamp (`last_seen` + `last_id`) stored in a state file to fetch only new logs since the last run.
* Formats the Logs
  * Simplifies each Salesforce record
  * Each record is printed as one line of JSON ({"...": "..."}), not wrapped in an array.
* Outputs for Wazuh
  * Prints each log line to stdout → Wazuh command wodle reads it.
  * Each JSON line becomes one event for Wazuh’s JSON decoder and triggers alerts.
* Maintains State
  * Updates /var/log/salesforce/salesforce_state.json with the latest CreatedDate and Id.
  * Ensures the next run only fetches new events.


Set the script permission:
```
chown root:wazuh custom-salesforce.py
chmod 750 custom-salesforce.py
```


#### Add the Wodle configuration in `/var/ossec/etc/ossec.conf`

```
<wodle name="command">
  <disabled>no</disabled>
  <run_on_start>yes</run_on_start>
  <interval>1m</interval>
  <tag>salesforce-setup-audit</tag>
  <command>/var/ossec/integrations/custom-salesforce.py</command>
  <timeout>0</timeout>
  <ignore_output>no</ignore_output>
</wodle>
```
This block makes Wazuh act like a scheduler + log collector for your Salesforce script:
Every 1 minute, run the Salesforce audit script, capture its JSON output as logs, tag them as salesforce-setup-audit, and analyze them for alerts.

#### Add the decoders and rules
* In Wazuh Dashboard go to Server Management > Decoders > Add new decoders file. Name it `salesforce_decoders.xml`, add the content of `salesforce_decoders.xml` and save.
* In Wazuh Dashboard go to Server Management > Rules > Add new rules file. Name it `salesforce_rules.xml`, add the content of `salesforce_rules.xml` and save.
Restart the Wazuh Manager to apply the changes.


---

### Integration Testing

Once the configuration on the manager is done, the integration will run after 1 minutes and the alerts will appear on the dashboard.

<img width="1283" height="289" alt="wazuh_dashboard_salesforce_alerts" src="https://github.com/user-attachments/assets/0f36cb61-c354-4de5-bd33-40bf5da6e1b2" />

<img width="555" height="626" alt="wazuh_dashboard_salesforce_alert_details" src="https://github.com/user-attachments/assets/f95d86b3-40f8-468b-ad1d-41a1e815dfab" />
