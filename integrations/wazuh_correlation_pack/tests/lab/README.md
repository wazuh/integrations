# Test lab

The pipeline tests need a Wazuh server and test endpoints running an agent of the same version
(recorded results: 5.0.0-rc1). The recorded results used two LXD containers on the Wazuh server itself. Everything
below is test-only; nothing here is needed to use the pack.

**Memory**: on a 4 GB all-in-one server the containers must be memory-capped. Launching two
uncapped containers caused the kernel to OOM-kill the Wazuh indexer during our setup.

## Create

```bash
# on the Wazuh server (LXD 5.0 snap)
sudo lxc network create wcpbr0 ipv4.address=10.231.40.1/24 ipv4.nat=true ipv6.address=none
sudo lxc profile create wcp-test
sudo lxc profile device add wcp-test eth0 nic network=wcpbr0 name=eth0
sudo lxc profile set wcp-test limits.memory 192MB
for n in wcp-ep1 wcp-ep2; do sudo lxc launch ubuntu:22.04 $n -p default -p wcp-test; done
# avoid update-notifier's apt-check filling the memory cap
for n in wcp-ep1 wcp-ep2; do sudo lxc exec $n -- mv /etc/apt/apt.conf.d/99update-notifier /root/; done
```

Agent (same version as the server; 5.0.0-rc1 here):

```bash
for n in wcp-ep1 wcp-ep2; do
  sudo lxc file push wazuh-agent_5.0.0-rc1_amd64.deb $n/root/
  sudo lxc exec $n -- dpkg -i /root/wazuh-agent_5.0.0-rc1_amd64.deb
done
```

Agent configuration (`/var/ossec/etc/ossec.conf` in each container):

* `<manager><endpoint>` = an address in the manager's listener certificate SAN
  (`openssl x509 -in /var/wazuh-manager/etc/certs/remoted.pem -noout -ext subjectAltName`).
* Keep the default `journald` `<localfile>` (sshd logs are read from the journal) and add:

  ```xml
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/wcp-replay/replay.log</location>
  </localfile>
  ```

  Do **not** also add `/var/log/auth.log`: every sshd line would be collected twice.
* Optional, to save memory: disable rootcheck, syscollector, SCA and syscheck.

Enrollment on 5.0.0-rc1 uses enrollment tokens. Mint a short-lived, limited one on the
manager and copy it to the endpoints without printing it:

```bash
T=$(sudo /var/wazuh-manager/bin/wazuh-manager-authd --create-enrollment-token \
      --address <manager address in SAN> --ttl 2h --max-uses 2 --description "wcp test endpoints" | tail -1)
for n in wcp-ep1 wcp-ep2; do printf '%s' "$T" | sudo lxc exec $n -- tee /var/ossec/etc/enrollment_token >/dev/null
  sudo lxc exec $n -- systemctl enable --now wazuh-agent; done; unset T
```

Test identities and sshd (containers only):

```bash
for n in wcp-ep1 wcp-ep2; do sudo lxc exec $n -- sh -c '
  for u in wcpt-alice wcpt-bob wcpt-carol wcpt-dave wcpt-erin wcpt-frank; do useradd -M -s /usr/sbin/nologin $u; passwd -l $u; done
  printf "PasswordAuthentication yes\nKbdInteractiveAuthentication no\nMaxAuthTries 6\n" > /etc/ssh/sshd_config.d/01-wcp-test.conf
  systemctl restart ssh
  mkdir -p /var/log/wcp-replay && touch /var/log/wcp-replay/replay.log
  printf "#!/bin/sh\necho wcp-not-a-password\n" > /usr/local/bin/wcp-askpass && chmod 755 /usr/local/bin/wcp-askpass'; done
```

The accounts are locked: no password can succeed. Never use a real administrative account as
the target of the tests.

## Driver configuration

```bash
export WCP_LAB_SSH='ssh -o BatchMode=yes -i ~/.ssh/<lab key> <user>@<wazuh server>'
export WCP_LAB_SUDO=sudo
```

## Remove

```bash
for n in wcp-ep1 wcp-ep2; do sudo lxc delete --force $n; done
sudo lxc profile delete wcp-test
sudo lxc network delete wcpbr0
sudo /var/wazuh-manager/bin/wazuh-manager-authd --list-enrollment-tokens    # revoke leftovers:
sudo /var/wazuh-manager/bin/wazuh-manager-authd --revoke-enrollment-token <id>
```

Then remove the two agents from the manager in the dashboard (Agents management) or with the
server API. The API call `DELETE /agents?agents_list=001,002&status=all&older_than=0s` is the 4.x
form; it was not verified on 5.0.0-rc1.
