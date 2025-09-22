# Integration Guide: Gemini AI with Wazuh

## Table of Contents
- [Overview](#overview)
- [Requirements](#requirements)
- [Integrtaion Steps:](#integration-steps)
  - [Obatin API Key](#step-1-obtain-a-gemini-api-key)
  - [Add Custom Script](#step-2-add-custom-integration-script)
  - [Configure Wazuh Manager](#step-3-configure-wazuh-integration)
  - [Custom Rules](#step-4-add-custom-rules)
- [Verification](#verification)

## Tested Version

| Wazuh version | Component |
|---|---|
| 4.12.0 | Wazuh Manager |

## Overview
Integrate **Gemini AI** with **Wazuh** to enrich alerts. The integration leverages the **Gemini API** (`gemini-2.0-flash` model) to generate summaries and explanations for triggered alerts, which are then displayed directly on the **Wazuh Dashboard**.

---

## Requirements
- **Gemini API Key** (from [Google AI Studio](https://aistudio.google.com/))  
- **Wazuh Manager server access** (with integration and rules configuration rights)  
- Model: **`gemini-2.0-flash`**

---

## Integration Steps

### Step 1: Obtain a Gemini API Key
1. Log in to [Google AI Studio](https://aistudio.google.com/).  
2. Generate a new API key for the **Gemini 2.0 Flash** model.  
3. Save the key securely, as it will be required in the integration configuration.  

---

### Step 2: Add Custom Integration Script
1. On the **Wazuh Manager** server, create a new Python script file:
   ```bash
   vi /var/ossec/integrations/custom-gemini.py
   ```
2. Copy and paste the script from the attached custom-gemini.py file.

3. Set permissions and ownership:
   ```bash
   chmod 750 /var/ossec/integrations/custom-gemini.py
   chown root:wazuh /var/ossec/integrations/custom-gemini.py
   ```

---

### Step 3: Configure Wazuh Integration

Add the following <integration> block in /var/ossec/etc/ossec.conf:
```bash
<integration>
  <name>custom-gemini.py</name>
  <hook_url>https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent</hook_url>
  <api_key><your_api_key></api_key>
  <rule_id>554</rule_id>
  <alert_format>json</alert_format>
</integration>
```
- Replace `<your_api_key>` with your Gemini API key.

Update `<rule_id>` to the Wazuh rule ID you want Gemini AI to analyze (e.g., 554 = File added to the system).

Add `<level>` if needed based on alert severity.

📖 You can refer to the [Wazuh external integration documentation](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html) for more details.

---

### Step 4: Add Custom Rules

Edit `/var/ossec/etc/rules/local_rules.xml` and append:
```bash
<group name="local,gemini,">
  <!-- Enriched alert from Gemini -->
  <rule id="100210" level="5">
    <field name="gemini.summary" type="pcre2">.+</field>
    <description>$(data.gemini.source.description) [Gemini] $(gemini.summary)</description>
    <options>no_full_log</options>
  </rule>

  <!-- Optional: catch errors -->
  <rule id="100211" level="3">
    <field name="gemini.error">.+</field>
    <description>[Gemini] API error $(gemini.error): $(gemini.error_description)</description>
    <options>no_full_log</options>
  </rule>
</group>
```

Apply changes by restarting the manager:
```bash
systemctl restart wazuh-manager
```

---

## Verification

- Trigger an alert for the configured rule ID (e.g., 554).
- Wazuh will:
  - Forward the alert details to Gemini AI.
  - Receive a summary/explanation from Gemini.
  - Generate a new enriched alert with Gemini’s output.
- The enriched alert will appear on the Wazuh Dashboard with the [Gemini] prefix under rule ID 100210.

<img width="844" height="1459" alt="Screenshot 2025-09-15 153354" src="https://github.com/user-attachments/assets/e79901af-ea4d-4823-a4e2-d119aec5d4c7" />
