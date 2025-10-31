# Sending Wazuh Custom Dashboard PDF Reports via Email

## Table of Contents
- [Overview](#overview)
- [Configuration Steps](#configuration-steps)
  - [Create Custom Dashboard](#step1-create-custom-dashboard)
  - [Generate Dashboard URL](#step2-generate-the-dashboard-url)
  - [SMTP Configuration](#step3-configure-smtp-server)
  - [Custom Script Configurtaion](#step4-configure-wazuh-dashboard-to-send-reports)
- [Conclusion](#conclusion)
- [Reference](#reference)

## Tested Version

| Wazuh version | Component | Deployment Type | OS |
|---|---|---|---|
| 4.13.1 | Wazuh dashboard | OVA | Amazon Linux | 

## Overview
This guide explains how to configure Wazuh to automatically generate and send custom dashboard reports in PDF format via email. The generated PDF is identical to the one you download manually from the Wazuh Dashboard.

Example – PDF report received via email using custom dashboard created for SSH activity:
<img width="2346" height="1191" alt="image" src="https://github.com/user-attachments/assets/5b6cc9c0-856d-405e-8044-9ee3f696a486" />
<img width="2378" height="834" alt="image" src="https://github.com/user-attachments/assets/1b7fc5d1-59d9-4c75-8a4c-276f9b870af0" />
 


## Configuration Steps

### Example: In this guide, we will configure Wazuh to send a Vulnerability Dashboard PDF report via email.

### Step1: Create Custom dashboard.
- Refer to the [Wazuh documentation](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/creating-custom-dashboards.html) for creating custom dashboards (e.g., Vulnerability dashboard).
- If needed, you can import the provided .ndjson sample file of a Vulnerability dashboard.  

### Step2: Generate the Dashboard URL
- Open your custom dashboard in Wazuh Dashboard.
- Apply the time filter (e.g., Last 24 hours if sending a daily report).
- Click Share → Permalinks → Snapshot, enable Short URL, and copy the generated link.
- Save this link – it will be used by the script to generate the PDF.
  <img width="1706" height="886" alt="image" src="https://github.com/user-attachments/assets/b0afd7dd-5afd-4d1b-8a51-94767c35997b" />
  <img width="1705" height="481" alt="image" src="https://github.com/user-attachments/assets/9645b140-f628-4678-bab7-3e27bf1d1a0b" />



### Step3: Configure SMTP Server
- Follow the [Wazuh SMTP configuration guide](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html#smtp-server-with-authentication).
- If running a distributed deployment, configure SMTP on the Wazuh Dashboard server.
- Complete steps up to Step 6 in the Wazuh documentation.

### Step4: Configure Wazuh Dashboard to Send Reports

1. Install Node.js and npm
   ```bash
   sudo dnf install -y nodejs npm
   node -v && npm -v
   ```
2. Install OpenSearch Reporting CLI
   ```bash
   sudo npm i -g @opensearch-project/reporting-cli
   ```
3. Ensure CLI Path `/usr/local/bin`
   ```bash
   echo 'export PATH=/usr/local/bin:$PATH' | sudo tee -a /root/.bashrc
   source /root/.bashrc
   which opensearch-reporting-cli
   ```
   You should see an output similar to:

   <img width="617" height="84" alt="image" src="https://github.com/user-attachments/assets/719c8789-0d5f-4833-8d45-c10b8ca732aa" />

5. Install Google Chrome (required by CLI)
   ```bash
   sudo rpm --import https://dl.google.com/linux/linux_signing_key.pub
   cat <<'EOF' | sudo tee /etc/yum.repos.d/google-chrome.repo
   [google-chrome]
   name=google-chrome
   baseurl=https://dl.google.com/linux/chrome/rpm/stable/$basearch
   enabled=1
   gpgcheck=1
   gpgkey=https://dl.google.com/linux/linux_signing_key.pub
   EOF

   sudo dnf install -y google-chrome-stable
   export CHROME_PATH=/usr/bin/google-chrome
   $CHROME_PATH --version
   ```
6. Create the Report Script
   ```bash
   sudo tee /usr/local/sbin/wazuh_report.sh >/dev/null <<'EOF'
   #!/usr/bin/env bash
   set -euo pipefail
   
   # ----- Minimal, cron-safe env -----
   export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
   export NODE_TLS_REJECT_UNAUTHORIZED=0

   # Hard-set Chrome path (adjust if you use Chromium)
   export CHROME_PATH="${CHROME_PATH:-/usr/bin/google-chrome}"

   # Find CLI even if cron PATH is tiny
   CLI="$(command -v opensearch-reporting-cli || true)"
   if [[ -z "$CLI" ]]; then
   # Try common npm global bin spots
   for p in /usr/local/bin /usr/bin /root/.npm-global/bin; do
    [[ -x "$p/opensearch-reporting-cli" ]] && CLI="$p/opensearch-reporting-cli" && break
   done
   fi

   LOG_FILE="/var/log/wazuh-reporting.log"
   URL="<your-custom-dashboard-permalink-url>" # Replace it with your custom dashboard permalink that you have copied in the Step2.
   AUTH_TYPE="basic"
   CREDS="admin:<password>" # Replace the <password> with your Wazuh dashboard user admin password.

   # SMTP via localhost
   SMTP_HOST="localhost"
   SMTP_PORT="25"
   FROM="<sender>@gmail.com" # Replace the <sender> with your send mail id that you have configured in the SMTP configurtaion.
   TO="<reciver>@gmail.com" # Replace the <receiver> with your mail id that who want to receive the report.

   FORMAT="pdf"
   SUBJECT="Daily Wazuh Dashboard Report"
   NOTE=$'Hi,\nHere is the latest Wazuh dashboard report generated by OpenSearch Reporting CLI.'

   # ----- Sanity checks -----
   {
   ts="$(date '+%F %T')"
   echo "[$ts] --- Wazuh report start ---"
   echo "PATH=$PATH"
   echo "CHROME_PATH=$CHROME_PATH"
   echo "CLI=$CLI"

   if [[ ! -x "$CHROME_PATH" ]]; then
    echo "ERROR: CHROME_PATH not executable: $CHROME_PATH"
    exit 1
   fi
   if [[ -z "$CLI" || ! -x "$CLI" ]]; then
    echo "ERROR: reporting CLI not found/executable"
    exit 1
   fi

   # ----- Run the report -----
   "$CLI" \
    -u "$URL" \
    -a "$AUTH_TYPE" -c "$CREDS" \
    -e smtp --smtphost "$SMTP_HOST" --smtpport "$SMTP_PORT" --selfsignedcerts true \
    -s "$FROM" -r "$TO" \
    -f "$FORMAT" \
    --subject "$SUBJECT" \
    --note "$NOTE"

   echo "[$ts] Report completed."
   echo "[$ts] --- Wazuh report end ---"
   } >>"$LOG_FILE" 2>&1
   EOF
   sudo chmod +x /usr/local/sbin/wazuh_report.sh
   ```

   Replace:
   - `URL="<your-dashboard-url>"` → Your Step 2 permalink
   - `CREDS="admin:<password>"` → Wazuh dashboard user Admin credentials
   - `FROM="<sender>@gmail.com"` → Sender address
   - `TO="<receiver>@gmail.com"` → Receiver address

7. Test it manually:
   ```bash
   sudo /usr/local/sbin/wazuh_report.sh
   sudo tail -n 80 /var/log/wazuh-reporting.log
   ```
   Expected successful log output:
   <img width="1001" height="213" alt="image" src="https://github.com/user-attachments/assets/0497503a-b4a7-4f3b-85f8-98c9fa7b8c11" />

8. Automate with Cron
   - Install and enable cron:
   ```bash
   sudo dnf install -y cronie
   sudo systemctl enable --now crond
   ```
   - Create a cron job:
   ```bash
   sudo tee /etc/cron.d/wazuh-report >/dev/null <<'EOF'
   SHELL=/bin/bash
   PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
   MAILTO=""
   0 0 * * * root /usr/local/sbin/wazuh_report.sh
   EOF
   ```
   - Verify:
   ```bash
   sudo systemctl status crond
   sudo ls -l /etc/cron.d/wazuh-report
   ```

## Conclusion:
Using the OpenSearch Reporting CLI, you can automatically generate Wazuh custom dashboard reports in PDF format and deliver them via email. This process is ideal for daily reports such as vulnerabilities, compliance status, or security events.

## Reference:
- Wazuh SMTP documentation: https://documentation.wazuh.com/current/user-manual/manager/alert-management.html#smtp-server-with-authentication
- OpenSearch Reporting CLI Documentation: https://docs.opensearch.org/latest/reporting/rep-cli-create/
   



