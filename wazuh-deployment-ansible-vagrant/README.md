# Ansible-Wazuh Integration

## Table of Contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Installation and Configuration](#installation-and-configuration)
  - [Installing Ansible](#installing-ansible)
  - [Initial Ansible Configuration](#initial-ansible-configuration)
  - [Installing Wazuh](#installing-wazuh)
  - [Initial Wazuh Configuration](#initial-wazuh-configuration)
  - [Using the Integration Files](#using-the-integration-files)
- [Integration Steps](#integration-steps)
- [Integration Testing](#integration-testing)
- [Sources](#sources)

---

## Introduction

This integration automates the deployment of a Wazuh single-node setup using Ansible within a Vagrant-managed VirtualBox environment. It configures two Ubuntu 24.04 VMs: one as the Wazuh server and another as the Ansible control node. The integration simplifies Wazuh deployment, enabling security monitoring and incident response with minimal manual configuration. It benefits Wazuh users by providing a reproducible, automated setup for testing or production environments.

---

## Prerequisites

- Vagrant 2.3.0 or higher
- VirtualBox 7.0.20 or higher
- Vagrant-vbguest plugin (`vagrant plugin install vagrant-vbguest`)
- Git for cloning the Wazuh Ansible repository
- Internet access for downloading the Wazuh Ansible repository and Vagrant box (`bento/ubuntu-24.04`, version `202508.03.0`)
- 10GB RAM and 6 CPUs available for VMs (8GB/4 CPUs for Wazuh server, 2GB/2 CPUs for Ansible control node)
- Network access to `https:<IP-address>` for Wazuh dashboard
- Administrative access on the host system (Windows or macOS)

---

## Installation and Configuration

### Installing Ansible

Ansible is automatically installed on the Ansible control node (`vm1`) during Vagrant provisioning. No manual installation is required on the host system. The Vagrantfile provisions `ansible` and `sshpass` packages via a shell script on `vm1`:

```bash
sudo apt-get install -y ansible sshpass
```

### Initial Ansible Configuration

The Vagrantfile configures the Ansible control node (`vm1`) to use the Wazuh Ansible playbook. Prepare the Ansible inventory file as follows:

1. Create a directory named `inventory` in the same directory as your Vagrantfile.
2. Create `inventory/inventory.ini` with the following content:

```ini
[wazuh]
192.168.57.200 ansible_user=vagrant ansible_connection=ssh ansible_ssh_common_args='-o StrictHostKeyChecking=no'

[wazuh:vars]
ansible_python_interpreter=/usr/bin/python3
```

3. Clone the Wazuh Ansible repository to the same directory as the Vagrantfile:

```bash
git clone https://github.com/wazuh/wazuh-ansible.git -b v4.12.0
```

The Vagrantfile maps this directory to `/vagrant` on the VMs, making the playbook accessible.

### Installing Wazuh

Wazuh is installed on `vm2` (Wazuh server) via the Ansible playbook `wazuh-single.yml` during Vagrant provisioning. No manual Wazuh installation is required. The Vagrantfile uses the `bento/ubuntu-24.04` box (version `202508.03.0`) for both VMs.

### Initial Wazuh Configuration

The Wazuh server (`vm2`) is pre-configured by the Ansible playbook, which handles the setup of the Wazuh manager, indexer, and dashboard. The Vagrantfile ensures:
- SSH access with `vagrant:vagrant` credentials
- Port forwarding for the Wazuh dashboard (5601)
- Synced folder permissions (`dmode=775,fmode=664`)

No additional Wazuh configuration is needed before running the integration.

### Using the Integration Files

The integration relies on the following files, which must be placed in the same directory as the Vagrantfile:

1. **Vagrantfile**:
   - Located in the root of the repository.
   - Configures two VMs: `vm1` (Ansible control node) and `vm2` (Wazuh server).
   - Ensure the Ansible playbook path (`/vagrant/wazuh-ansible/playbooks/wazuh-single.yml`) and inventory path (`/vagrant/inventory/inventory.ini`) are correct.

2. **Inventory File** (`inventory/inventory.ini`):
   - Place in the `inventory/` directory.
   - Defines the Wazuh server (`192.168.57.200`) as the Ansible target.

3. **Wazuh Ansible Repository**:
   - Clone the repository to `wazuh-ansible/` in the same directory as the Vagrantfile.
   - The playbook `wazuh-single.yml` is referenced by the Vagrantfile.

No additional Wazuh rules, decoders, or scripts are required. After setup, the Wazuh manager on `vm2` is restarted automatically by Ansible:

```bash
systemctl restart wazuh-manager
```

---

## Integration Steps

1. **Prepare the Environment**:
   - Ensure Vagrant, VirtualBox, and the `vagrant-vbguest` plugin are installed.
   - Clone the Wazuh Ansible repository and create the `inventory/inventory.ini` file as described.

2. **Run Vagrant**:
   - Execute the following command in the directory containing the Vagrantfile:

```bash
vagrant up
```

   - This starts both VMs, provisions `vm1` with Ansible, and runs the `wazuh-single.yml` playbook to configure the Wazuh server on `vm2`.

3. **Data Flow**:
   - The Ansible control node (`vm1`) uses SSH to connect to `vm2` (`192.168.57.200`) with `vagrant:vagrant` credentials.
   - The playbook installs and configures the Wazuh manager, indexer, and dashboard on `vm2`.
   - The Wazuh dashboard becomes accessible at `https://<IP-address>` on the host machine.

4. **Verify Operation**:
   - Once provisioning completes, the Wazuh server is fully configured and running.
   - Access the dashboard to confirm functionality.

---

## Integration Testing

To verify the integration:

1. **Trigger Provisioning**:
   - Run `vagrant up` to start and provision the VMs.
   - Monitor the console output for provisioning success messages:
     - `vm1 shell provisioning completed successfully`
     - `vm2 provisioning completed successfully`

2. **Check Wazuh Logs**:
   - SSH into `vm2`:
```bash
vagrant ssh vm2
```
   - Verify Wazuh manager logs for startup:
```bash
sudo tail -f /var/ossec/logs/ossec.log
```
   - Look for entries indicating the manager, indexer, and dashboard services are running.

3. **Access Wazuh Dashboard**:
   - Open `http://<IP-address>` in a browser on the host machine.

## Sources

- [Vagrant Documentation](https://developer.hashicorp.com/vagrant/docs/vagrantfile)
- [Wazuh Ansible Deployment](https://documentation.wazuh.com/current/deployment-options/deploying-with-ansible/index.html)
- [Wazuh Documentation](https://documentation.wazuh.com/current/)
- [Wazuh Ansible Repository](https://github.com/wazuh/wazuh-ansible)
