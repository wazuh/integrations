# okta_api-Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Compatibility](#compatibility)
* [Prerequisites](#prerequisites)
* [Configuration](#configuration)
  * [Step 1: Create an Okta API Token](#step-1-create-an-okta-api-token)
  * [Step 2: Deploy the Python Script](#step-2-deploy-the-python-script)
  * [Step 3: Configure a Cronjob](#step-3-configure-a-cronjob)
  * [Step 4: Rules](#step-4-rules)
* [Data Flow Overview](#data-flow-overview)
* [Integration Testing](#integration-testing)
  * [Step-by-step](#step-by-step)
* [Example Event](#example-event)
  
---

### Introduction

This integration provides support for ingesting and alerting on Okta logs using Wazuh. It includes a Python script to fetch logs via API, and a cronjob setup to automate log collection.

This integration was developed and tested in a production use case for centralized security monitoring.

---

### Compatibility

* **Wazuh version:** v4.12
* **Log source:** Okta System Log API
* **Platform:** Wazuh Manager (tested on On-prem)

---

### Prerequisites

* An active Okta organization with admin access
* API Token from Okta
* Wazuh Manager installed and functioning
* Access to `/var/ossec/` and permissions to edit cron and rules files

---

### Configuration

#### Step 1: Create an Okta API Token

1. Log into Okta Admin Console.
2. Navigate to **Security > API > Tokens**.
3. Click **Create Token**, name it, and **copy the token** immediately.
4. Note your Okta domain (e.g., `https://yourcompany.okta.com`).

---

#### Step 2: Deploy the Python Script

Create `/var/ossec/integrations/okta_api.py` and paste the script code in.

Make it executable:

```bash
chmod +x /var/ossec/integrations/okta_api.py
```

---

#### Step 3: Configure a Cronjob

Edit the root crontab:

```bash
crontab -e
```

Add the following line to fetch logs every minute:

```cron
*/1 * * * * /var/ossec/integrations/okta_api.py
```

---

#### Step 4: Rules and Decoders

Because Okta events vary, field names and structure can differ. You should create rules that match your actual events. For now the rules in this workflow are intended to generate an alert for different messeges contained in the field okta.displayMessage.

You can place the Decoders in two ways:

1- Create a decoder file at:

```bash
vim /var/ossec/etc/decoders/okta_decoders.xml
```

2- You can go to Menu > Server management > Decoders > Custom decoders > Add new decoders file > place the decoders. 
SAVE and RESTART

You can place the rules in two ways:

1- Create a rule file at:

```bash
vim /var/ossec/etc/rules/okta_rules.xml
```
Restart Wazuh to apply:

```bash
systemctl restart wazuh-manager
```

2- You can go to Menu > Server management > Rules > Custom rules > Add new rules file > place the rules. 
SAVE and RESTART

---

## Data Flow Overview

1. **Script runs via cron** → contacts Okta API.
2. **Logs fetched** → each event is sent as JSON to Wazuh via the Unix socket.
3. **Wazuh decodes** the JSON payload.
4. **Custom rules match** the event fields.
5. **Alerts appear** in `archives.log`.

---

## Integration Testing

### Step-by-step:

#### 1. Trigger the integration manually:

```bash
python3 /var/ossec/integrations/okta_api.py
```

#### 2. Confirm log arrival:

```bash
tail -f /var/ossec/logs/archives/archives.log | grep okta
```

#### 3. Check for alerts:

```bash
tail -f /var/ossec/logs/archives/archives.log | grep okta
```

#### 4. Wazuh Dashboard:

Navigate to **Discover** or **Threat Hunting**.

Filter by:

```
rule.id:[ID]
```

You should see the alert from your custom rule.

---

## Example Event

```json
{"okta":{"actor":{"id":"okta.11111111-aaaa-bbbb-cccc-222222222222","type":"PublicClientApp","alternateId":"app123abc456","displayName":"Okta Dashboard"},"client":{"userAgent":{"rawUserAgent":"Mozilla/5.0 (Mockintosh; Intel Mock OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36","os":"Mock OS 15.3.0","browser":"CHROME"},"device":"Computer","ipAddress":"10.10.10.10","geographicalContext":{"city":"Mockville","state":"Mock State","country":"Mockland"}},"authenticationContext":{"authenticationStep":0,"rootSessionId":"sess-12345-mock"},"displayMessage":"OIDC id token is granted","eventType":"app.oauth2.token.grant.id_token","outcome":{"result":"SUCCESS"},"published":"2025-08-14T18:32:36.845Z","severity":"INFO","uuid":"uuid-1111-2222-3333-4444"}}
{"okta":{"actor":{"id":"mockAgent123XYZ","type":"AD_AGENT","alternateId":"mockAltID456","displayName":"Active Directory Agent"},"client":{"userAgent":{"rawUserAgent":"Okta AD Agent/9.99.0 (Mock Windows NT 10.0.0000.0; .NET CLR 4.0.30319.42000; 64-bit OS; 64-bit Process)","os":"Windows 10 Mock","browser":"UNKNOWN"},"device":"Computer","ipAddress":"192.168.50.25","geographicalContext":{"city":"Mocktown","state":"Mockshire","country":"Mockland"}},"authenticationContext":{"authenticationStep":0,"rootSessionId":"sess-67890-mock"},"displayMessage":"Perform LDAP read by AD agent","eventType":"system.agent.ad.read_ldap","outcome":{"result":"SUCCESS"},"published":"2025-08-14T18:28:04.761Z","severity":"INFO","uuid":"uuid-2222-3333-4444-5555"}}
{"okta":{"actor":{"id":"mockUserID001","type":"User","alternateId":"user1@mockmail.com","displayName":"Mock User"},"client":{"userAgent":{"rawUserAgent":"Mozilla/5.0 (MockPhone; CPU Mock OS 19_0 like Mock OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1","os":"Mock OS (Phone)","browser":"SAFARI"},"device":"Mobile","ipAddress":"172.16.5.50","geographicalContext":{"city":"Faketon","state":"Testshire","country":"Mockland"}},"authenticationContext":{"authenticationProvider":"FACTOR_PROVIDER","credentialType":"OTP","rootSessionId":"sess-abcde-mock"},"displayMessage":"Authentication of user via MFA","eventType":"user.authentication.auth_via_mfa","outcome":{"result":"FAILURE","reason":"INVALID_CREDENTIALS"},"published":"2025-07-15T18:14:01.653Z","severity":"INFO","uuid":"uuid-3333-4444-5555-6666"}}
{"okta":{"actor":{"id":"mockUserID002","type":"User","alternateId":"user2@mockmail.com","displayName":"Demo User"},"client":{"userAgent":{"rawUserAgent":"Mozilla/5.0 (MockPhone; CPU Mock OS 19_0 like Mock OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1","os":"Mock OS (Phone)","browser":"SAFARI"},"device":"Mobile","ipAddress":"172.16.5.51","geographicalContext":{"city":"Testopolis","state":"Mockshire","country":"Mockland"}},"authenticationContext":{"authenticationStep":0,"rootSessionId":"sess-fghij-mock"},"displayMessage":"Evaluation of sign-on policy","eventType":"policy.evaluate_sign_on","outcome":{"result":"CHALLENGE","reason":"Sign-on policy evaluation resulted in CHALLENGE"},"published":"2025-07-15T15:47:29.473Z","severity":"INFO","uuid":"uuid-4444-5555-6666-7777"}}
{"okta":{"actor":{"id":"unknown","type":"SystemPrincipal","alternateId":"system@mock.okta.com","displayName":"Okta System"},"client":{"userAgent":null,"ipAddress":null},"authenticationContext":{"authenticationStep":0,"rootSessionId":"sess-klmno-mock"},"displayMessage":"Email delivery","eventType":"system.email.delivery","outcome":{"result":"SUCCESS","reason":"delivered"},"published":"2025-07-15T15:48:06.402Z","severity":"INFO","uuid":"uuid-5555-6666-7777-8888","target":[{"id":"user3@mockmail.com","type":"email","displayName":"user3@mockmail.com"}]}}
```

