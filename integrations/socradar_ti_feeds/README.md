# SOCRadar → Wazuh IOC Sync

Automatically fetches threat intelligence feeds from [SOCRadar](https://platform.socradar.com) and syncs malicious IOCs (IP, domain, URL, hash) into [Wazuh](https://wazuh.com) CDB lists. Runs once daily via systemd timer.

## How It Works

```
                         ┌──────────────────────────┐
                         │   IOC Database            │
                         │   (ioc_db.json)           │
                         │                           │
                         │  ip:                      │
  SOCRadar Feeds ──────► │    1.2.3.4:               │ ──────► Wazuh CDB Lists
  (daily fetch)          │      first_seen: Jan 01   │         /var/ossec/etc/lists/
    UUID-1               │      last_seen:  Mar 05   │           socradar-ip
    UUID-2               │    5.6.7.8:               │           socradar-domain
    UUID-N               │      first_seen: Feb 10   │           socradar-url
                         │      last_seen:  Mar 05   │           socradar-hash
                         │  domain:                  │
                         │    evil.com: ...           │
                         └──────────────────────────┘
                                    │
                           TTL expiry (30 days)
                           Not seen → auto-remove
```

**Cumulative + TTL Strategy:**
1. Downloads `.raw` feed files from SOCRadar for each configured UUID
2. Classifies every line as **IP**, **domain**, **URL**, or **hash**
3. **New IOCs** → added to persistent database with `first_seen` timestamp
4. **Existing IOCs** → `last_seen` refreshed to today
5. **Stale IOCs** (not seen in feeds for TTL days) → automatically expired
6. Wazuh CDB lists rebuilt from active database, Wazuh restarted only on changes

## Quick Start

### One-Line Install

```bash
git clone https://github.com/wazuh/integrations.git
cd integrations/integrations/socradar_ti_feeds
sudo bash install.sh
```

### Configure

```bash
sudo nano /etc/socradar-wazuh-sync/config.yaml
```

Set your **API key** and **feed UUIDs**:

```yaml
socradar:
  api_key: "your-actual-api-key"
  feed_uuids:
    - "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    - "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
```

### Test

```bash
# Dry run — fetch & classify without writing
sudo socradar-wazuh-sync --dry-run -v

# First real sync
sudo socradar-wazuh-sync -v
```

### Verify Timer

```bash
systemctl status socradar-wazuh-sync.timer
systemctl list-timers socradar-wazuh-sync*
```

## Wazuh Configuration

After installation, add CDB lists to `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <ruleset>
    <list>etc/lists/socradar-ip</list>
    <list>etc/lists/socradar-domain</list>
    <list>etc/lists/socradar-url</list>
    <list>etc/lists/socradar-hash</list>
  </ruleset>
</ossec_config>
```

Then create custom rules (e.g., `/var/ossec/etc/rules/socradar_rules.xml`):

```xml
<group name="socradar,threat_intel,">

  <!-- Alert on connections from malicious IPs -->
  <rule id="100200" level="10">
    <if_sid>5700</if_sid>
    <list field="srcip" lookup="address_match_key">etc/lists/socradar-ip</list>
    <description>SOCRadar: Connection from malicious IP $(srcip)</description>
    <group>threat_intel,socradar,</group>
  </rule>

  <!-- Alert on DNS queries to malicious domains -->
  <rule id="100201" level="10">
    <if_sid>5700</if_sid>
    <list field="url" lookup="address_match_key">etc/lists/socradar-domain</list>
    <description>SOCRadar: DNS query to malicious domain</description>
    <group>threat_intel,socradar,</group>
  </rule>

  <!-- Alert on malicious file hash detected -->
  <rule id="100202" level="12">
    <if_sid>550</if_sid>
    <list field="md5" lookup="address_match_key">etc/lists/socradar-hash</list>
    <description>SOCRadar: Malicious file hash detected</description>
    <group>threat_intel,socradar,</group>
  </rule>

</group>
```

## CLI Usage

```
socradar-wazuh-sync [-c CONFIG] [-v] [--dry-run] [--force] [--status]
                    [--purge-expired] [--reset-db] [--version]

Options:
  -c, --config      Config file path (default: /etc/socradar-wazuh-sync/config.yaml)
  -v, --verbose     Debug-level logging
  --dry-run         Fetch & classify only, don't write lists or save database
  --force           Write lists even if content hasn't changed
  --status          Show IOC database summary (counts, expiring soon, dates)
  --purge-expired   Run TTL expiry only (no fetch), then rewrite lists
  --reset-db        Delete IOC database and start fresh
  --version         Show version
```

## Configuration Reference

| Key | Default | Description |
|-----|---------|-------------|
| `socradar.api_key` | — | SOCRadar API key (required) |
| `socradar.feed_uuids` | — | List of feed UUIDs (required) |
| `wazuh.list_dir` | `/var/ossec/etc/lists` | CDB list output directory |
| `wazuh.restart_on_update` | `true` | Auto-restart Wazuh on changes |
| `wazuh.restart_command` | `systemctl restart wazuh-manager` | Restart command |
| `ioc_types.ip` | `true` | Sync IP indicators |
| `ioc_types.domain` | `true` | Sync domain indicators |
| `ioc_types.url` | `true` | Sync URL indicators |
| `ioc_types.hash` | `true` | Sync hash indicators |
| `list_files.ip` | `socradar-ip` | CDB filename for IPs |
| `list_files.domain` | `socradar-domain` | CDB filename for domains |
| `list_files.url` | `socradar-url` | CDB filename for URLs |
| `list_files.hash` | `socradar-hash` | CDB filename for hashes |
| `sync.request_timeout` | `120` | HTTP timeout (seconds) |
| `sync.verify_ssl` | `true` | Verify TLS certificates |
| `sync.ttl_days` | `30` | Days to keep IOCs not seen in feeds (0 = forever) |

## File Layout

```
/opt/socradar-wazuh-sync/           # Application
  socradar_wazuh_sync.py
/etc/socradar-wazuh-sync/           # Configuration
  config.yaml                        # ← edit this
/var/log/socradar-wazuh-sync/       # Logs
  socradar-wazuh-sync.log
/var/lib/socradar-wazuh-sync/       # State (change detection + IOC DB)
  state.json
  ioc_db.json                        # ← persistent IOC database with timestamps
/var/ossec/etc/lists/               # Wazuh CDB lists (output)
  socradar-ip
  socradar-domain
  socradar-url
  socradar-hash
```

## Uninstall

```bash
sudo bash uninstall.sh
```

## Requirements

- Python 3.8+
- Wazuh Manager (tested with 4.x)
- SOCRadar platform account with API access
- Root/sudo access on the Wazuh manager host

## License

MIT
