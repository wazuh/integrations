# Wazuh AR - Ansible Integration: Executing Ansible Playbooks via Wazuh Active Response

## Table of Contents
- [Overview](#overview)
- [Set Up Ansible Server](#step-1-set-up-the-ansible-control-node)
- [Install Wazuh Agent](#step-2-install-wazuh-agent-on-ansible-server)
- [Ansible Inventory configurtaion](#step-3-configure-ansible-inventory)
- [Ansible Playbook Creation](#step-4-create-an-ansible-playbook)
- [Deploy Active Response Script](#step-5-deploy-active-response-script-on-ansible-server)
- [Active Response Configurtaion](#step-6-configure-active-response-in-wazuh-manager)
- [Testing](#testing)
- [Conclusion](#conclusion)


## Overview
This document provides step-by-step guidance on how to configure Wazuh to trigger an Ansible playbook using its Active Response feature.  
This setup is particularly useful in scenarios such as detecting brute-force login attempts and automatically blocking the source IP on the affected endpoints.  

> **Note:** This is a sample implementation. You must tailor your custom Wazuh rules, active response scripts, and Ansible playbooks according to your specific use case.

---

## Step 1: Set Up the Ansible Control Node
- Install and configure an Ansible control server.  
- Ensure SSH key-based access is configured for all managed endpoints.  
- Follow the official Wazuh documentation for Ansible setup: [**Install Ansible for Wazuh Deployment**](https://documentation.wazuh.com/current/deployment-options/deploying-with-ansible/guide/install-ansible.html).  

⚠️ Ensure all configurations are correct. Even a small misconfiguration can cause the integration to fail.

---

## Step 2: Install Wazuh Agent on Ansible Server
- Install the Wazuh agent on the Ansible server to enable Active Response functionality.  

-  Reference: [**Install Wazuh Agent on Linux**](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html)

---

## Step 3: Configure Ansible Inventory
1. Edit the Ansible inventory file:  
   ```bash
   vi /etc/ansible/hosts
   ```
2. Add the following entry for each managed endpoint:
   ```bash
   [wazuh-agents]
   agent_1 ansible_host=<ENDPOINT_IP> ansible_ssh_user=<USERNAME>
   ```
   Replace:
   -  `<ENDPOINT_IP>` with the IP address of the endpoint

    - `<USERNAME>` with a user who has sudo privileges

   Repeat this line for each endpoint you want to manage.

---

## Step 4: Create an Ansible Playbook
1. Clone the Wazuh Ansible repository:#
   ```bash
   cd /etc/ansible/roles/
   sudo git clone --branch v4.12.0 https://github.com/wazuh/wazuh-ansible.git
   ```
2. Create the playbook file:
   ```bash
   vi /etc/ansible/roles/wazuh-ansible/playbooks/block_ip.yml
   ```
3. Paste the block_ip.yml code.

   Playbook Features:
   -  Ensures UFW is installed and enabled
   -  Blocks the IP only if not already blocked
   -  Reloads rules for immediate effect

---

## Step 5: Deploy Active Response Script on Ansible Server
1. Create the active response Python script:
   ```bash
   vi /var/ossec/active-response/bin/custom_ansible_response.py
   ```
2. Paste the script content from `custom_ansible_response.py`
3. Make it executable:
   ```bash
   chmod +x /var/ossec/active-response/bin/custom_ansible_response.py
   chown root:wazuh /var/ossec/active-response/bin/custom_ansible_response.py
   ```
4. Restart the Wazuh Agent service:
   ```bash
   systemctl restart wazuh-agent
   ```
---

## Step 6: Configure Active Response in Wazuh Manager
1. Edit the Wazuh manager configuration file:
   ```bash
   vi /var/ossec/etc/ossec.conf
   ```
2. Add the following configuration inside <ossec_config>:
   ```bash
   <command>
     <name>block-with-ansible</name>
     <executable>custom_ansible_response.py</executable>
     <timeout_allowed>no</timeout_allowed>
   </command>

   <active-response>
     <disabled>no</disabled>
     <command>block-with-ansible</command>
     <location>defined-agent</location>
     <agent_id>AGENT_ID_HERE</agent_id>
     <rules_id>5712,5763</rules_id>
   </active-response>
   ```
   Replace:

    - `AGENT_ID_HERE` → Wazuh agent ID of the Ansible server
    - `rules_id` → Appropriate rule IDs you want to respond to (e.g., brute-force SSH detection rules)
3. Restart the Wazuh Manager:
   ```bash
   systemctl restart wazuh-manager
   ```

---

## Testing
1. Simulate a brute-force SSH login attempt to a monitored endpoint.
2. After triggering the alert, check if the IP was blocked:
   ```bash
   sudo ufw status numbered
   ```
   You should see the IP blocked on port 22 if everything is working correctly.

---

## Conclusion 
   You have successfully integrated Wazuh Active Response with Ansible to automate IP blocking using UFW. This setup helps in dynamically responding to security events by leveraging your Ansible infrastructure.

---

## Sources

<details>
<summary>Click to expand source references</summary>

- [Ansible Documentation](https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/2.4/pdf/getting_started_with_ansible_playbooks/Red_Hat_Ansible_Automation_Platform-2.4-Getting_started_with_Ansible_Playbooks-en-US.pdf)
- [Wazuh Agent Installation Guide](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html)
- [Wazuh Active Response Documentation](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html)

</details>