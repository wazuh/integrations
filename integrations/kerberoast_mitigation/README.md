# Kerberoast Mitigation - Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

---

## Introduction

This integration provides automated detection and response for Kerberoasting
attacks (MITRE ATT&CK T1558.003) against Windows Active Directory environments.

Kerberoasting allows any authenticated domain user to request a Kerberos service
ticket for any SPN-registered account. The ticket is encrypted with the service
account password hash and can be cracked offline with no further network
interaction required after the initial request.

The only viable detection window is the ticket request itself: Windows Security
Event ID 4769. This integration filters on RC4-HMAC encryption type 0x17 (the
downgrade forced by Impacket and Rubeus), ignoring legitimate AES traffic
(0x11/0x12). Zero false positives against normal domain traffic.

When Rule 100002 fires at Level 12, Wazuh Active Response executes
kerb-block.ps1 on the Domain Controller, disabling the compromised service
account via Disable-ADAccount. Mean Time to Remediate: hours to under 2 seconds.

---

## Prerequisites

- Wazuh Manager v4.x (tested on Wazuh Cloud v4.14.4)
- Wazuh Agent active and connected on the Windows Domain Controller
- Windows Server 2019 Domain Controller with Active Directory Domain Services
- Sysmon v15.15 deployed on the Domain Controller
- RSAT (Remote Server Administration Tools) installed on the Domain Controller
- PowerShell execution policy allowing script execution on the Domain Controller
- Kerberos Service Ticket Operations auditing enabled via Group Policy:
  Computer Configuration > Advanced Audit Policy Configuration > Account Logon
  > Audit Kerberos Service Ticket Operations: Success and Failure
- At least one SPN-registered service account present in the domain

---

## Installation and Configuration

### 1. Enable Kerberos Audit Policy

On the Domain Controller, open Group Policy Management Console (GPMC):

    Computer Configuration > Policies > Windows Settings > Security Settings
    > Advanced Audit Policy Configuration > Account Logon
    > Audit Kerberos Service Ticket Operations: Success and Failure

Enforce and verify:

    gpupdate /force
    auditpol /get /subcategory:"Kerberos Service Ticket Operations"
    # Expected output: Success and Failure

Without this policy, Event ID 4769 is never generated and the detection
pipeline has no telemetry to act on.

### 2. Deploy the Detection Rule

Copy local_rules.xml to the Wazuh Manager rules directory:

    /var/ossec/etc/rules/local_rules.xml

Restart Wazuh Manager:

    systemctl restart wazuh-manager

### 3. Deploy the Active Response Script

Copy kerb-block.ps1 to the Active Response bin directory on the Domain Controller:

    C:\Program Files (x86)\ossec-agent\active-response\bin\kerb-block.ps1

Add the following configuration to ossec.conf on the Wazuh Manager:

    
      win-disable-user
      kerb-block.ps1
      no
    

    
      win-disable-user
      local
      100002
    

Restart Wazuh Manager after configuration changes:

    systemctl restart wazuh-manager

---

## Integration Steps

1. Attacker requests a Kerberos service ticket using Impacket GetUserSPNs,
   forcing RC4-HMAC (0x17) encryption downgrade.
2. Domain Controller generates Windows Security Event ID 4769 with
   TicketEncryptionType 0x17.
3. Sysmon v15.15 and Windows Security Auditing forward events to the Wazuh Agent.
4. Wazuh Agent forwards telemetry to Wazuh Manager.
5. Rule 100002 matches EventID 4769 with EncryptionType 0x17 and fires at Level 12.
6. Wazuh Active Response triggers kerb-block.ps1 via stdin on the Domain Controller.
7. Script checks the command field, extracts the target account, calls
   Disable-ADAccount, and writes a timestamped entry to C:\Security\SOAR.log.

---

## Integration Testing

### Simulate the Attack

From a Kali Linux machine on the same network segment:

    impacket-GetUserSPNs DOMAIN/username:password -dc-ip DC_IP -request

This forces an RC4 ticket request against all SPN-registered accounts.

### Verify Detection

Check Wazuh Manager for Rule 100002 firing at Level 12 with MITRE T1558.003.

### Verify Automated Response

On the Domain Controller, confirm account status:

    Get-ADUser sql_service | Select-Object Name, Enabled
    # Expected: Enabled : False

Review the audit log:

    Get-Content C:\Security\SOAR.log
    # Expected: [timestamp] - SUCCESS: Disabled account: sql_service

---

## Sources

- MITRE ATT&CK T1558.003:
  https://attack.mitre.org/techniques/T1558/003/
- Wazuh Active Response documentation:
  https://documentation.wazuh.com/current/user-manual/capabilities/active-response/
- Windows Security Event ID 4769:
  https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769
- Full lab implementation and evidence:
  https://github.com/R-Williams-Security/Kerberoast-Detection-Lab
- Portfolio write-up:
  https://sites.google.com/view/williamsransom-portfolio/project-page/active-directory-soar-automated-kerberoast-mitigation