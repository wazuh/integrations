# Splunk SOAR (On‑Premises) 6.4.1 Installation Guide on RHEL 8

## Table of Contents

- [Introduction](#introduction)  
- [Prerequisites](#prerequisites)  
- [Installation Workflow](#installation-workflow)  
  - [1. Prepare OS & Repos](#1-prepare-os--repos)  
  - [2. Install Dependencies](#2-install-dependencies)  
  - [3. Prepare System via `soar-prepare-system`](#3-prepare-system-via-soar-prepare-system)  
  - [4. Install Splunk SOAR](#4-install-splunk-soar)  
  - [5. Activate Admin User](#5-activate-admin-user)  
- [Post-install Configuration](#post-install-configuration)  
  - [Service Management](#service-management)  
  - [Accessing the UI](#accessing-the-ui)  
- [Troubleshooting](#troubleshooting)  
- [References](#references)  

## Introduction

This guide covers installing **Splunk SOAR 6.4.1** on **RHEL 8.10+** (or compatible), with an unprivileged `phantom` user. It details OS prep, software setup, user activation, and accessing the UI.

## Prerequisites

- **Operating System**  
  - Red Hat Enterprise Linux **8.10 or newer** (6.4+ requires ≥ 8.10) :contentReference  
- **Disk space**  
  - ≥ 500 GiB free under `/opt/phantom`  
- **Subscriptions/repositories**  
  - RHEL base and AppStream repos  
  - EPEL repo  
- **User**  
  - SSH-accessible user (e.g., `vagrant` or `root`) with sudo

## Installation Workflow

### 1. Prepare OS & Repos

```bash
sudo subscription-manager register  
sudo subscription-manager attach --auto  
sudo subscription-manager repos --enable \
  rhel-8-for-x86_64-baseos-rpms \
  rhel-8-for-x86_64-appstream-rpms  
sudo yum install -y epel-release  
sudo yum clean all && sudo yum makecache  
```

### 2. Install Dependencies

```bash
sudo yum install -y fontconfig libicu libxslt mailcap \
  xmlsec1 xmlsec1-openssl zip jq
```

If packages are missing, ensure repos are enabled.

### 3. Prepare System via `soar-prepare-system`

```bash
sudo ./soar-prepare-system \
  --splunk-soar-home /opt/phantom \
  --https-port 8443
```

It:
* Enables ports 80, 8300, 8301, 8302, 4369, 5671, 25672, 15672, 5121 by default
* Optionally forwards 443 → 8443 for browser convenience
* Enables firewall ports, sets up `phantom` user/system limits
* **Important**: Clean `/tmp/maintenance.lock` if stale

After setup, verify active rules:

```bash
# Open HTTPS port
firewall-cmd --permanent --add-port=443/tcp

# Optional: open HTTP (for redirect)
firewall-cmd --permanent --add-port=80/tcp

# Optional: open SSH
firewall-cmd --permanent --add-port=22/tcp

# Reload to apply
firewall-cmd --reload

[root@rhel7 splunk-soar]# firewall-cmd --list-all
public (active)
  target: default
  icmp-block-inversion: no
  interfaces: eth0 eth1
  sources: 
  services: dhcpv6-client ssh
  ports: 22/tcp 80/tcp 443/tcp 8300/tcp 8301/tcp 8302/tcp 4369/tcp 5671/tcp 25672/tcp 15672/tcp 5121/tcp
  protocols: 
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 

```

Expected output:

```bash
  target: default
  icmp-block-inversion: no
  interfaces: eth0 eth1
  sources: 
  services: cockpit dhcpv6-client ssh
  ports: 22/tcp 2222/tcp 8443/tcp 443/tcp 80/tcp 8300/tcp 8301/tcp 8302/tcp 4369/tcp 5671/tcp 25672/tcp 15672/tcp 5121/tcp 3500/tcp
  protocols: 
  forward: no
  masquerade: no
  forward-ports: 
	port=443:proto=tcp:toport=8443:toaddr=
  source-ports: 
  icmp-blocks: 
  rich rules: 
```

### 4. Install Splunk SOAR

Ensure disk space is ≥ 500 GiB on `/opt/phantom`.
Switch to `phantom` user and run installer:

```bash
sudo chown -R phantom:phantom /opt/phantom  
sudo su - phantom
cd /path/to/installer
./soar-install --splunk-soar-home /opt/phantom --https-port 8443
```

Handle errors:

* **RHEL version**: upgrade OS if < 8.10
* **Permissions**: ensure `/opt/phantom` is owned by `phantom`
* **Disk space**: expand VM disk or override (dev/test only)

### 5. Activate Admin User

By default, admin may be inactive. Activate via direct SQL:

```bash
sudo su - phantom
cd /opt/phantom/bin
/opt/phantom/usr/postgresql/15/bin/psql -d phantom \
  -c "UPDATE auth_user SET is_active=TRUE WHERE username='admin';"
```

Confirm in Django shell:

```bash
./phenv python3 ../www/manage.py shell << 'EOF'
from django.contrib.auth import get_user_model
User = get_user_model()
u = User.objects.get(username='admin')
print(u.is_active, u.is_staff, u.is_superuser)
EOF
```

Expected output:

```
True True True
```

## Post-install Configuration

### Service Management

Start or restart Splunk SOAR:

```bash
systemctl status phantom
systemctl list-units --type=service | grep -i phantom
cd /opt/phantom/bin
./stop_phantom.sh
./start_phantom.sh
```

(Optional convenience link for root):

```bash
sudo ln -sf /opt/phantom/bin/start_phantom.sh /usr/local/bin/phantomd
```

### Accessing the UI

Open in browser:

```
https://<server-ip>:8443
```

Accept self-signed TLS warning.
Login with:

* **Username**: `admin`
* **Password**: *(set during `createsuperuser`)*

## Troubleshooting

* **Installation fails**

  * RHEL version < 8.10 → upgrade OS
  * Disk space < 500 GiB → expand storage or bypass (dev only)
  * Permissions errors → correct ownership (`chown -R phantom:phantom /opt/phantom`)
* **Service startup**

  * Missing binaries (`phantomd`, `start_phantom.sh`) → reinstall properly as `phantom`

## References

* Official Splunk SOAR install docs (RHEL 8 upgrade requirement) ([docs.splunk.com][1], [docs.splunk.com][2], [docs.splunk.com][3])
* Installer steps: `soar-prepare-system`, unprivileged install mode ([docs.splunk.com][4])

[1]: https://docs.splunk.com/Documentation/SOARonprem/6.4.0/Install/MigratetoRHEL8 "Migrate a Splunk SOAR (On-premises) install from RHEL 7 or ..."
[2]: https://docs.splunk.com/Documentation/SOARonprem/latest/Install/GetSplunkPhantom "Get Splunk SOAR (On-premises)"
[3]: https://docs.splunk.com/Documentation/UBA/5.4.3/Install/InstallSingleServer "Install Splunk UBA on a single Linux server"
[4]: https://docs.splunk.com/Documentation/SOARonprem/6.4.1/Install/InstallUnprivileged "Install Splunk SOAR (On-premises) as an unprivileged user"
