# Wazuh wodles to forward teramind logs

## Table of Contents
  - [Overview](#overview)
  - [Implementation Steps](#implementation-steps)
    - [Create the Custom Script on the Agent](#create-the-custom-script-on-the-agent)
    - [Set Script Permissions](#set-script-permissions)
    - [Configure the Wodle on the Wazuh Agent](#configure-the-wodle-on-the-wazuh-agent)
    - [Restart the Wazuh Agent](#restart-the-wazuh-agent)
    - [Configure Rules on the Wazuh Manager](#configure-rules-on-the-wazuh-manager)

## Overview

This document explains how to configure a custom **Wodle** for teraminds on a **Wazuh agent** to execute a script that forwards endpoint logs to the **Wazuh manager**, making them visible in the **Wazuh dashboard**.

## Implementation Steps

### Create the Custom Script on the Agent:

1. Log in to a server where the Wazuh agent is installed.
2. Navigate to the Wazuh directory:

```bash
cd /var/ossec/
```

3. Create the custom script file:

```bash
vi custom-teraminds.py
```

4. Paste your script into the file and save it.

### Set Script Permissions:

```bash
chown wazuh:wazuh /var/ossec/custom-teraminds.py
chmod +x /var/ossec/custom-teraminds.py
```

### Configure the Wodle on the Wazuh Agent:

1. Navigate to the configuration directory:

```bash
cd /var/ossec/etc/
```

2. Edit the agent configuration file:

```bash
vi ossec.conf
```

3. Add the following Wodle configuration:

```xml
<wodle name="command">
    <disabled>no</disabled>
    <tag>teraminds</tag>
    <command>/var/ossec/custom-teraminds.py</command>
    <interval>15m</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>15</timeout>
</wodle>
```

### Restart the Wazuh Agent:

```bash
systemctl restart wazuh-agent
```

### Configure Rules on the Wazuh Manager:

1. Log in to the **Wazuh Dashboard**.
2. Open the Wazuh Dashboard and click the **☰ (burger menu)**.
3. Navigate to **Server Management → Rules**.
4. Click **Add new rule file** and create a rule with the required settings.
5. Create a new rule file:

```xml
<group name="teraminds">
    <rule id="100027" level="3">
        <decoded_as>json</decoded_as>
        <field name="teramind.endpoint">.*</field>
        <options>no_full_log</options>
        <description>Teraminds logs.</description>
    </rule>
</group>
```

3. Restart the Wazuh manager:

```bash
systemctl restart wazuh-manager
```
