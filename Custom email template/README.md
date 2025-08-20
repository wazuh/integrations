# Office365 Email alert Integration using custom template

## Overview

This guide outlines the process for configuring Postfix to send Wazuh SOC alert notifications via an Office 365 SMTP relay. It includes steps to install required packages, configure Postfix for secure email delivery, set up a Python script to process Wazuh alerts, and integrate it with the Wazuh manager. The setup ensures that high-severity alerts (level 12 or higher) are sent as email notifications with detailed information, logged for monitoring and debugging.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation and Configuration](#installation-and-configuration)
  - [1. Install Required Packages](#1-install-required-packages)
  - [2. Configure Postfix](#2-configure-postfix)
  - [3. Set Up SMTP Credentials](#3-set-up-smtp-credentials)
  - [4. Restart Postfix](#4-restart-postfix)
  - [5. Test Postfix Configuration](#5-test-postfix-configuration)
  - [6. Add Python Script for Wazuh Alerts](#6-add-python-script-for-wazuh-alerts)
  - [7. Configure Wazuh Manager](#7-configure-wazuh-manager)
  - [8. Restart Wazuh Manager](#8-restart-wazuh-manager)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)

## Prerequisites

- A Linux server with root access.
- An Office 365 account with 2-Step Verification enabled and an App Password generated for the sender email.
- Wazuh manager installed and running.
- Internet access for package installation and SMTP communication.

## Installation and Configuration

### 1. Install Required Packages

Update the package list and install Postfix and related packages. Select **No configuration** if prompted about the mail server configuration type.

```bash
apt-get update && apt-get install postfix mailutils libsasl2-2 ca-certificates libsasl2-modules
```

### 2. Configure Postfix

Append the following configuration to `/etc/postfix/main.cf`. Create the file if it does not exist.

```bash
inet_protocols = ipv4
relayhost = [smtp.office365.com]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtp_use_tls = yes
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination
```

### 3. Set Up SMTP Credentials

Create or edit `/etc/postfix/sasl_passwd` with the sender's Office 365 credentials. Replace `<USERNAME>` and `<PASSWORD>` with the sender’s email address and App Password, respectively. The App Password must be generated from an account with 2-Step Verification enabled.

```bash
[smtp.office365.com]:587 noreply@test.xyz:csdhaskjhk878
```

Generate the Postfix database file:

```bash
postmap /etc/postfix/sasl_passwd
```

Secure the password files to ensure only the root user has access:

```bash
chown root:root /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
chmod 0600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
```

### 4. Restart Postfix

Restart the Postfix service to apply the configuration:

```bash
systemctl restart postfix
```

### 5. Test Postfix Configuration

Send a test email to verify the Postfix setup. Replace `<CONFIGURED_EMAIL>` with the sender’s email (e.g., `noreply@test.xyz`) and `<RECEIVER_EMAIL>` with the recipient’s email (e.g., `socsupport@test.xyz`).

```bash
echo "Test mail from postfix" | mail -s "Test Postfix" -r "<CONFIGURED_EMAIL>" <RECEIVER_EMAIL>
```

### 6. Add Python Script for Wazuh Alerts

Place the Python script (`custom-email.py`) in `/var/ossec/integrations/`. This script processes Wazuh alerts and sends email notifications via the local Postfix server.

Set the appropriate ownership and permissions for the script:

```bash
chown root:wazuh /var/ossec/integrations/custom-email.py
chmod 750 /var/ossec/integrations/custom-email.py
```

### 7. Configure Wazuh Manager

Add the following integration block to the Wazuh manager’s configuration file (e.g., `/var/ossec/etc/ossec.conf`) to enable the custom email script for alerts with level 12 or higher:

```xml
<integration>
  <name>custom-email.py</name>
  <level>12</level>
  <alert_format>json</alert_format>
  <options>JSON</options>
</integration>
```

### 8. Restart Wazuh Manager

Restart the Wazuh manager to apply the configuration changes:

```bash
systemctl restart wazuh-manager
```

## Usage

- The Python script processes Wazuh alerts in JSON format and sends email notifications to the configured recipient (`socsupport@test.xyz`) with details such as timestamp, location, rule ID, rule level, description, agent name, and agent ID.
- Logs for the script are written to `/var/ossec/logs/custom-email_integration.log` for debugging and monitoring.

## Troubleshooting

- **Postfix Issues**: Check `/var/log/mail.log` or `/var/log/maillog` for errors related to SMTP authentication or connectivity.
- **Wazuh Integration Issues**: Verify the script’s execution by checking `/var/ossec/logs/custom-email_integration.log`.
- **Email Not Sent**: Ensure the App Password is correct and that the Office 365 account has 2-Step Verification enabled.
- **Permissions Errors**: Confirm that file permissions for `/etc/postfix/sasl_passwd`, `/etc/postfix/sasl_passwd.db`, and `/var/ossec/integrations/custom-email.py` are set correctly.

## Security Notes

- The `/etc/postfix/sasl_passwd` and `/etc/postfix/sasl_passwd.db` files contain sensitive credentials in plaintext. Ensure they are only accessible by the root user.
- Use an App Password for the Office 365 account to enhance security.
- Regularly monitor logs for unauthorized access or errors.
