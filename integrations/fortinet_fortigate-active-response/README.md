# Fortinet FortiGate — Wazuh Active Response Integration

Automatically blocks malicious source IPs on a Fortinet FortiGate firewall in response to Wazuh alerts. When a matching rule fires, the Wazuh Manager executes the active response script, which creates a `/32` host address object on the FortiGate and appends it to a pre-configured block group via the REST API — all within seconds, without modifying any existing firewall policies.

---

## How it works

```
Wazuh Alert (e.g. SSH brute force, web attack)
         │
         ▼
  wazuh-analysisd        - rule match fires
         │
         ▼
  wazuh-execd            - dispatches active response, full alert JSON via STDIN
         │
         ▼
  fortigate-block.sh     - extracts srcip, calls FortiGate REST API
         │
         ├─ POST /api/v2/cmdb/firewall/address
         │       creates host object  "wazuh-{ip}"
         │
         └─ POST /api/v2/cmdb/firewall/addrgrp/{group}/member
                 appends to block group (never overwrites existing members)

  [timeout expires — Wazuh calls script with "delete"/optional]
         │
         ├─ DELETE /api/v2/cmdb/firewall/addrgrp/{group}/member/{addr}
         └─ DELETE /api/v2/cmdb/firewall/address/{addr}
```

> **Key design note:** The member-append endpoint (`POST .../addrgrp/{group}/member`) is used deliberately. Using `PUT` on the group object replaces all existing members — a common mistake in earlier implementations. The append endpoint only adds the new member without touching others.

---

## Requirements

| Component | Minimum version |
|-----------|----------------|
| Wazuh Manager | 4.2+ |
| FortiOS | 6.4+ |
| bash | 4.0+ |
| curl | Any recent version |
| jq | 1.5+ |

---

## FortiGate prerequisites

### 1. Create the block address group

**Policy & Objects - Addresses - Create New - Address Group**

| Field | Value |
|-------|-------|
| Name | `Wazuh-Blocked-IPs` *(must match `FGT_BLOCK_GROUP` in config)* |
| Members | Add a placeholder (e.g. `FIREWALL`) — FortiGate requires at least one member |

### 2. Create a DENY policy referencing the group

**Policy & Objects - Firewall Policy - Create New**

| Field | Value |
|-------|-------|
| Source | `Wazuh-Blocked-IPs` |
| Destination | `all` |
| Action | **DENY** |
| Position | **Above** any ALLOW rules for the same traffic |
| Logging | Enable |

> Policy order matters on FortiGate — the deny rule must be evaluated before permissive rules.

### 3. Create a REST API administrator

**System - Administrators - Create New  REST API Admin**

| Field | Value |
|-------|-------|
| Username |  any name |
| Profile | Custom profile with **Read/Write** on Firewall Address + Firewall Address Group |
| Trusted Hosts | **Add the Wazuh Manager IP** — required or all API calls return 403 |

Copy the generated token — to be placed on the config file.

---

## Installation


```bash
# 1. Script
sudo cp integrations/fortinet_fortigate-active-response/active-response/fortigate-block.sh \
        /var/ossec/active-response/bin/
sudo chown root:wazuh /var/ossec/active-response/bin/fortigate-block.sh
sudo chmod 750        /var/ossec/active-response/bin/fortigate-block.sh

# 2. Config
sudo cp integrations/fortinet_fortigate-active-response/active-response/fortigate-ar.conf \
        /var/ossec/etc/fortigate-ar.conf
sudo chown root:wazuh /var/ossec/etc/fortigate-ar.conf
sudo chmod 640        /var/ossec/etc/fortigate-ar.conf

# 3. Whitelist
sudo cp integrations/fortinet_fortigate-active-response/active-response/fortigate-ar-whitelist.example \
        /var/ossec/etc/lists/fortigate-ar-whitelist
sudo chown root:wazuh /var/ossec/etc/lists/fortigate-ar-whitelist
sudo chmod 640        /var/ossec/etc/lists/fortigate-ar-whitelist
```

---

## Configuration

### Edit `/var/ossec/etc/fortigate-ar.conf`

Minimum required settings:

```bash
FGT_HOST="1.1.1.1"               # FortiGate management IP or FQDN
FGT_API_TOKEN="xxxxxxxxxxxxxxxxxxxx"  # Token from REST API admin
FGT_BLOCK_GROUP="Wazuh-Blocked-IPs"  # Must already exist on FortiGate
FGT_VDOM="root"                       # VDOM name (root if not using VDOMs)
```

All available options are documented in
[`active-response/fortigate-ar.conf`](active-response/fortigate-ar.conf).

### Add to `/var/ossec/etc/ossec.conf`

```xml
<!-- Command definition -->
<command>
  <name>fortigate-block</name>
  <executable>fortigate-block.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<!-- Active response — SSH brute force, block for 1 hour -->
<active-response>
  <command>fortigate-block</command>
  <location>server</location>
  <rules_id>5960</rules_id>
  <timeout>3600</timeout>
</active-response>
```

`<location>server</location>` is required — the script runs on the Manager because it needs to reach the FortiGate API. See [`active-response/ossec-fortigate-ar.conf`](active-response/ossec-fortigate-ar.conf) for more trigger examples.

### Whitelist your infrastructure

Edit `/var/ossec/etc/lists/fortigate-ar-whitelist` — one IP per line. Loopback addresses are always exempt regardless of this file.

### Restart Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
```

---

## Testing

```bash
# Dry-run — prints the JSON without calling the API
sudo bash integrations/fortinet_fortigate/tests/test-ar.sh block 198.51.100.99 dry

# Live block test
sudo bash integrations/fortinet_fortigate/tests/test-ar.sh block 198.51.100.99

# Verify on FortiGate
curl -sk -H "Authorization: Bearer YOUR_TOKEN" \
  "https://YOUR_FGT/api/v2/cmdb/firewall/addrgrp/Wazuh-Blocked-IPs" \
  | jq '.results[0].member[].name'

# Live unblock test
sudo bash integrations/fortinet_fortigate/tests/test-ar.sh unblock 198.51.100.99

# Monitor the AR log
sudo tail -f /var/ossec/logs/active-responses.log
```

---

## Repository structure

```
integrations/
└── fortinet_fortigate/
    ├── active-response/
    │   ├── fortigate-block.sh              - AR script - /var/ossec/active-response/bin/
    │   ├── fortigate-ar.conf       - config template - /var/ossec/etc/
    │   ├── fortigate-ar-whitelist  - whitelist template
    │   └── ossec-fortigate-ar.conf         - ossec.conf snippets
    ├── tests/
    │   └── test-ar.sh                      - manual test 
    └── README.md
```

---

## Common use cases:

```
- SSH brute force
- Web attacks
- Port scans
- Threat intelligence matches
- Repeated authentication failures

```

---

## Security considerations

- **Protect the API token** — `fortigate-ar.conf` is `root:wazuh 640`. Do not commit the live file; it is in `.gitignore`.
- **Least-privilege API profile** — scope the FortiGate REST API admin to only Address and Address Group objects, not `super_admin`.
- **Restrict Trusted Hosts** — only the Wazuh Manager IP should be listed in the FortiGate API admin's Trusted Hosts.
- **use timeouts** — set `<timeout>` in ossec.conf so blocks automatically expire. Permanent blocks (`timeout=0`) require manual cleanup (optional).
- **Whitelist your infrastructure** — scanners, monitoring servers, and jump hosts should be in the whitelist to prevent self-lockout.
- **Enable SSL verification** — set `FGT_VERIFY_SSL=true` with a CA-signed certificate on the FortiGate management interface for production environments.

---

## Troubleshooting

Enable debug mode on the Wazuh Manager:

```bash
echo "execd.debug=2" >> /var/ossec/etc/local_internal_options.conf
systemctl restart wazuh-manager
tail -f /var/ossec/logs/ossec.log | grep -E "execd|fortigate"
cat  /var/ossec/logs/active-responses.log
```

Common errors:

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| HTTP 401 | Wrong API token | Regenerate token in FortiGate GUI |
| HTTP 403 | Wazuh Manager IP not in Trusted Hosts | Add IP to REST API admin Trusted Hosts |
| `curl failed exit 7` | FortiGate unreachable | Check routing/firewall between Manager and FortiGate |
| `Duplicate block attempts are safely ignored using Wazuh check_keys handling.` | Duplicate in-flight block | Normal — Wazuh deduplication working correctly |

---

## Tested environment

- FortiOS 7.4.11 (FG201FT)
- Wazuh Manager 4.14 on Ubuntu 22.04
- Triggered by rule 5760 (SSH authentication failure)

---

## License

MIT — see [LICENSE](../../LICENSE).
