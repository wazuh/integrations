#!/usr/bin/env python3
"""
SOCRadar → Wazuh IOC Sync (Cumulative + TTL)

Fetches threat intelligence feeds from SOCRadar and syncs malicious IOCs
(IP, domain, URL, hostname, hash) into Wazuh CDB lists.

Strategy: Cumulative with TTL
  - New IOCs are ADDED to existing database
  - IOCs still present in feeds get their last_seen updated
  - IOCs NOT seen in feeds for X days (TTL) are automatically expired
  - Wazuh CDB lists are rebuilt from the active IOC database

Designed to run once daily via systemd timer or cron.
"""

import os
import sys
import re
import json
import hashlib
import logging
import argparse
import ipaddress
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Set, Optional

try:
    import yaml
except ImportError:
    print("[ERROR] PyYAML is required. Install with: pip3 install pyyaml")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("[ERROR] requests is required. Install with: pip3 install requests")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────
APP_NAME = "socradar-wazuh-sync"
VERSION = "2.0.0"

DEFAULT_CONFIG_PATH = "/etc/socradar-wazuh-sync/config.yaml"
DEFAULT_WAZUH_LIST_DIR = "/var/ossec/etc/lists"
DEFAULT_LOG_DIR = "/var/log/socradar-wazuh-sync"
DEFAULT_STATE_DIR = "/var/lib/socradar-wazuh-sync"
DEFAULT_TTL_DAYS = 30

SOCRADAR_FEED_URL = (
    "https://platform.socradar.com/api/threat/intelligence/"
    "feed_list/{uuid}.raw?key={api_key}&v=2"
)

# ──────────────────────────────────────────────────────────────────────
# IOC Classification Patterns
# ──────────────────────────────────────────────────────────────────────
RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_URL = re.compile(r"^https?://", re.IGNORECASE)
RE_DOMAIN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)

# ──────────────────────────────────────────────────────────────────────
# Logger setup
# ──────────────────────────────────────────────────────────────────────
logger = logging.getLogger(APP_NAME)


def setup_logging(log_dir: str, verbose: bool = False) -> None:
    """Configure file + console logging."""
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    log_file = os.path.join(log_dir, f"{APP_NAME}.log")

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    fh = logging.FileHandler(log_file)
    fh.setFormatter(fmt)

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)

    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.addHandler(fh)
    logger.addHandler(ch)


# ──────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────
def load_config(path: str) -> dict:
    """Load and validate YAML configuration."""
    p = Path(path)
    if not p.exists():
        logger.error("Config file not found: %s", path)
        sys.exit(1)

    with open(p, "r") as f:
        cfg = yaml.safe_load(f)

    # Validate required keys
    if not cfg.get("socradar", {}).get("api_key"):
        logger.error("socradar.api_key is required in config.")
        sys.exit(1)

    if not cfg.get("socradar", {}).get("feed_uuids"):
        logger.error("socradar.feed_uuids list is required in config.")
        sys.exit(1)

    # Apply defaults
    cfg.setdefault("wazuh", {})
    cfg["wazuh"].setdefault("list_dir", DEFAULT_WAZUH_LIST_DIR)
    cfg["wazuh"].setdefault("restart_on_update", True)
    cfg["wazuh"].setdefault("restart_command", "systemctl restart wazuh-manager")

    cfg.setdefault("sync", {})
    cfg["sync"].setdefault("log_dir", DEFAULT_LOG_DIR)
    cfg["sync"].setdefault("state_dir", DEFAULT_STATE_DIR)
    cfg["sync"].setdefault("request_timeout", 120)
    cfg["sync"].setdefault("verify_ssl", True)
    cfg["sync"].setdefault("ttl_days", DEFAULT_TTL_DAYS)

    # IOC type toggles
    cfg.setdefault("ioc_types", {})
    cfg["ioc_types"].setdefault("ip", True)
    cfg["ioc_types"].setdefault("domain", True)
    cfg["ioc_types"].setdefault("url", True)
    cfg["ioc_types"].setdefault("hash", True)

    # CDB list file names
    cfg.setdefault("list_files", {})
    cfg["list_files"].setdefault("ip", "socradar-ip")
    cfg["list_files"].setdefault("domain", "socradar-domain")
    cfg["list_files"].setdefault("url", "socradar-url")
    cfg["list_files"].setdefault("hash", "socradar-hash")

    return cfg


# ──────────────────────────────────────────────────────────────────────
# IOC Classification
# ──────────────────────────────────────────────────────────────────────
def classify_ioc(value: str) -> str:
    """Classify an IOC string into ip | domain | url | hash | unknown."""
    value = value.strip()
    if not value or value.startswith("#"):
        return "skip"

    # Check IP (v4 / v6) — also handles CIDR notation
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return "ip"
    except ValueError:
        pass

    # Check hash
    if RE_MD5.match(value) or RE_SHA1.match(value) or RE_SHA256.match(value):
        return "hash"

    # Check URL
    if RE_URL.match(value):
        return "url"

    # Check domain / hostname
    if RE_DOMAIN.match(value):
        return "domain"

    return "unknown"


# ──────────────────────────────────────────────────────────────────────
# SOCRadar Feed Fetcher
# ──────────────────────────────────────────────────────────────────────
def fetch_feed(uuid: str, api_key: str, timeout: int, verify_ssl: bool) -> List[str]:
    """Download a single SOCRadar feed and return raw lines."""
    url = SOCRADAR_FEED_URL.format(uuid=uuid, api_key=api_key)
    logger.info("Fetching feed: %s", uuid)

    try:
        resp = requests.get(url, timeout=timeout, verify=verify_ssl)
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.error("Failed to fetch feed %s: %s", uuid, exc)
        return []

    lines = resp.text.strip().splitlines()
    logger.info("Feed %s returned %d lines", uuid, len(lines))
    return lines


def fetch_all_feeds(cfg: dict) -> Dict[str, Set[str]]:
    """Fetch all configured feeds and return classified IOC sets."""
    api_key = cfg["socradar"]["api_key"]
    uuids = cfg["socradar"]["feed_uuids"]
    timeout = cfg["sync"]["request_timeout"]
    verify_ssl = cfg["sync"]["verify_ssl"]

    ioc_buckets: Dict[str, Set[str]] = {
        "ip": set(),
        "domain": set(),
        "url": set(),
        "hash": set(),
        "unknown": set(),
    }

    for uuid in uuids:
        uuid = uuid.strip()
        if not uuid:
            continue

        lines = fetch_feed(uuid, api_key, timeout, verify_ssl)
        for line in lines:
            val = line.strip()
            if not val or val.startswith("#"):
                continue

            ioc_type = classify_ioc(val)
            if ioc_type == "skip":
                continue
            ioc_buckets[ioc_type].add(val)

    for t, s in ioc_buckets.items():
        if t != "unknown":
            logger.info("Classified IOCs from feeds — %s: %d", t, len(s))

    if ioc_buckets["unknown"]:
        logger.warning(
            "Could not classify %d IOC(s). Samples: %s",
            len(ioc_buckets["unknown"]),
            list(ioc_buckets["unknown"])[:5],
        )

    return ioc_buckets


# ══════════════════════════════════════════════════════════════════════
# IOC Database — Cumulative + TTL Engine
# ══════════════════════════════════════════════════════════════════════
#
# Database structure (ioc_db.json):
# {
#   "ip": {
#     "1.2.3.4": {
#       "first_seen": "2025-01-01T00:00:00+00:00",
#       "last_seen":  "2025-03-05T03:00:00+00:00"
#     },
#     ...
#   },
#   "domain": { ... },
#   "url": { ... },
#   "hash": { ... }
# }
# ══════════════════════════════════════════════════════════════════════

IOC_DB_FILE = "ioc_db.json"


def load_ioc_db(state_dir: str) -> Dict[str, Dict[str, dict]]:
    """Load the persistent IOC database from disk."""
    p = Path(state_dir) / IOC_DB_FILE
    if p.exists():
        try:
            with open(p, "r") as f:
                db = json.load(f)
            for t in ("ip", "domain", "url", "hash"):
                db.setdefault(t, {})
            return db
        except (json.JSONDecodeError, ValueError) as exc:
            logger.error("Corrupted IOC database, starting fresh: %s", exc)

    return {"ip": {}, "domain": {}, "url": {}, "hash": {}}


def save_ioc_db(state_dir: str, db: Dict[str, Dict[str, dict]]) -> None:
    """Persist IOC database to disk (atomic write)."""
    Path(state_dir).mkdir(parents=True, exist_ok=True)
    p = Path(state_dir) / IOC_DB_FILE

    tmp = p.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(db, f, indent=2, default=str)
    tmp.rename(p)
    logger.debug("IOC database saved (%s)", p)


def update_ioc_db(
    db: Dict[str, Dict[str, dict]],
    fresh_buckets: Dict[str, Set[str]],
    ttl_days: int,
) -> Dict[str, int]:
    """
    Merge fresh feed IOCs into the persistent database.
    Expire IOCs whose last_seen is older than TTL.

    Returns stats dict with counts for logging.
    """
    now = datetime.now(timezone.utc).isoformat()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=ttl_days)).isoformat()

    stats = {
        "new": 0,
        "refreshed": 0,
        "expired": 0,
        "active": 0,
    }

    for ioc_type in ("ip", "domain", "url", "hash"):
        fresh_set = fresh_buckets.get(ioc_type, set())
        type_db = db.setdefault(ioc_type, {})

        # Step 1: Add new + refresh existing
        for ioc in fresh_set:
            if ioc in type_db:
                type_db[ioc]["last_seen"] = now
                stats["refreshed"] += 1
            else:
                type_db[ioc] = {
                    "first_seen": now,
                    "last_seen": now,
                }
                stats["new"] += 1

        # Step 2: Expire stale IOCs
        expired_keys = [
            ioc for ioc, meta in type_db.items()
            if meta["last_seen"] < cutoff
        ]
        for ioc in expired_keys:
            del type_db[ioc]
            stats["expired"] += 1

        stats["active"] += len(type_db)

    return stats


def get_active_iocs(db: Dict[str, Dict[str, dict]]) -> Dict[str, Set[str]]:
    """Extract active IOC sets from the database for CDB writing."""
    return {
        ioc_type: set(entries.keys())
        for ioc_type, entries in db.items()
    }


def get_db_summary(db: Dict[str, Dict[str, dict]], ttl_days: int) -> str:
    """Return a human-readable summary of the IOC database."""
    warn_cutoff = (datetime.now(timezone.utc) - timedelta(days=max(0, ttl_days - 7))).isoformat()
    lines = []
    total = 0
    total_expiring = 0

    for ioc_type in ("ip", "domain", "url", "hash"):
        entries = db.get(ioc_type, {})
        count = len(entries)
        total += count

        stale = sum(1 for m in entries.values() if m["last_seen"] < warn_cutoff)
        total_expiring += stale

        stale_str = f"  ({stale} expiring within 7d)" if stale > 0 else ""
        lines.append(f"  {ioc_type:8s}: {count:>6d} active{stale_str}")

    header = f"  {'TOTAL':8s}: {total:>6d} active"
    if total_expiring > 0:
        header += f"  ({total_expiring} expiring within 7d)"
    lines.insert(0, header)

    # Show oldest and newest IOC dates
    all_dates = []
    for entries in db.values():
        for meta in entries.values():
            all_dates.append(meta.get("first_seen", ""))
    if all_dates:
        all_dates.sort()
        lines.append(f"\n  Oldest IOC first_seen : {all_dates[0][:19]}")
        lines.append(f"  Newest IOC first_seen : {all_dates[-1][:19]}")

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────
# State Management (CDB change detection)
# ──────────────────────────────────────────────────────────────────────
def compute_hash(iocs: Set[str]) -> str:
    """Compute a deterministic SHA-256 hash of a sorted IOC set."""
    blob = "\n".join(sorted(iocs)).encode()
    return hashlib.sha256(blob).hexdigest()


def load_state(state_dir: str) -> dict:
    """Load previous run state."""
    p = Path(state_dir) / "state.json"
    if p.exists():
        with open(p, "r") as f:
            return json.load(f)
    return {}


def save_state(state_dir: str, state: dict) -> None:
    """Persist current run state."""
    Path(state_dir).mkdir(parents=True, exist_ok=True)
    p = Path(state_dir) / "state.json"
    with open(p, "w") as f:
        json.dump(state, f, indent=2)


# ──────────────────────────────────────────────────────────────────────
# Wazuh CDB List Writer
# ──────────────────────────────────────────────────────────────────────
def write_cdb_list(list_dir: str, list_name: str, iocs: Set[str]) -> Path:
    """Write IOCs to a Wazuh CDB list file. Format: "<ioc>":malicious

    Keys are wrapped in double quotes so that IOCs containing colons
    (IPv6 addresses, URLs) are treated as a single key by Wazuh.
    """
    path = Path(list_dir) / list_name
    lines = sorted(f'"{ioc}":malicious' for ioc in iocs)

    with open(path, "w") as f:
        f.write("\n".join(lines))
        f.write("\n")

    logger.info("Wrote %d entries → %s", len(lines), path)
    return path


def update_wazuh_lists(cfg: dict, active_iocs: Dict[str, Set[str]]) -> bool:
    """Write CDB lists from active IOC database. Returns True if any changed."""
    list_dir = cfg["wazuh"]["list_dir"]
    state_dir = cfg["sync"]["state_dir"]

    Path(list_dir).mkdir(parents=True, exist_ok=True)
    old_state = load_state(state_dir)
    new_state: dict = {
        "last_run": datetime.now(timezone.utc).isoformat(),
        "hashes": {},
        "counts": {},
    }
    changed = False

    type_map = {
        "ip": cfg["list_files"]["ip"],
        "domain": cfg["list_files"]["domain"],
        "url": cfg["list_files"]["url"],
        "hash": cfg["list_files"]["hash"],
    }

    for ioc_type, list_name in type_map.items():
        if not cfg["ioc_types"].get(ioc_type, True):
            logger.info("Skipping disabled IOC type: %s", ioc_type)
            continue

        iocs = active_iocs.get(ioc_type, set())
        h = compute_hash(iocs)
        new_state["hashes"][ioc_type] = h
        new_state["counts"][ioc_type] = len(iocs)

        old_hash = old_state.get("hashes", {}).get(ioc_type)
        if h == old_hash:
            logger.info(
                "No change for %s list (%d entries), skipping write.",
                ioc_type, len(iocs),
            )
            continue

        write_cdb_list(list_dir, list_name, iocs)
        changed = True

    save_state(state_dir, new_state)
    return changed


# ──────────────────────────────────────────────────────────────────────
# Wazuh Restart
# ──────────────────────────────────────────────────────────────────────
def restart_wazuh(cfg: dict) -> None:
    """Restart Wazuh manager to reload CDB lists."""
    cmd = cfg["wazuh"]["restart_command"]
    logger.info("Restarting Wazuh manager: %s", cmd)

    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    if result.returncode == 0:
        logger.info("Wazuh manager restarted successfully.")
    else:
        logger.error(
            "Wazuh restart failed (rc=%d): %s", result.returncode, result.stderr
        )


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description=(
            "Sync SOCRadar threat intelligence feeds into Wazuh CDB lists. "
            "Uses cumulative strategy with TTL-based expiry."
        ),
    )
    parser.add_argument(
        "-c", "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to config file (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and classify IOCs without writing to Wazuh",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force CDB list rewrite even if content hasn't changed",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show IOC database summary and exit",
    )
    parser.add_argument(
        "--purge-expired",
        action="store_true",
        help="Only run TTL expiry (no fetch), then rewrite lists",
    )
    parser.add_argument(
        "--reset-db",
        action="store_true",
        help="Delete IOC database and start fresh",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{APP_NAME} {VERSION}",
    )
    return parser.parse_args()


# ──────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────
def main() -> None:
    args = parse_args()

    # Pre-load log_dir from config before full validation
    log_dir = DEFAULT_LOG_DIR
    try:
        with open(args.config, "r") as f:
            pre_cfg = yaml.safe_load(f)
            log_dir = pre_cfg.get("sync", {}).get("log_dir", DEFAULT_LOG_DIR)
    except Exception:
        pass

    setup_logging(log_dir, args.verbose)
    logger.info("═" * 60)
    logger.info("%s v%s — starting (cumulative + TTL mode)", APP_NAME, VERSION)
    logger.info("═" * 60)

    cfg = load_config(args.config)
    state_dir = cfg["sync"]["state_dir"]
    ttl_days = cfg["sync"]["ttl_days"]

    logger.info("TTL: %d days — IOCs not seen for %d days will be expired", ttl_days, ttl_days)

    # ── --reset-db ──────────────────────────────────────────────
    if args.reset_db:
        db_path = Path(state_dir) / IOC_DB_FILE
        if db_path.exists():
            db_path.unlink()
            logger.info("IOC database deleted: %s", db_path)
        else:
            logger.info("No IOC database found — nothing to reset.")
        sys.exit(0)

    # ── Load existing IOC database ──────────────────────────────
    db = load_ioc_db(state_dir)
    existing_total = sum(len(v) for v in db.values())
    logger.info("Loaded IOC database: %d existing entries", existing_total)

    # ── --status ────────────────────────────────────────────────
    if args.status:
        summary = get_db_summary(db, ttl_days)
        print(f"\n{APP_NAME} — IOC Database Status (TTL: {ttl_days} days)\n")
        print(summary)
        print()
        sys.exit(0)

    # ── --purge-expired ─────────────────────────────────────────
    if args.purge_expired:
        logger.info("Running TTL expiry only (no fetch)...")
        empty_buckets: Dict[str, Set[str]] = {
            "ip": set(), "domain": set(), "url": set(), "hash": set()
        }
        stats = update_ioc_db(db, empty_buckets, ttl_days)
        logger.info(
            "Purge result — expired: %d, remaining active: %d",
            stats["expired"], stats["active"],
        )
        save_ioc_db(state_dir, db)
        active_iocs = get_active_iocs(db)
        changed = update_wazuh_lists(cfg, active_iocs)
        if changed and cfg["wazuh"]["restart_on_update"]:
            restart_wazuh(cfg)
        sys.exit(0)

    # ── Normal sync flow ────────────────────────────────────────

    # 1. Fetch feeds
    fresh_buckets = fetch_all_feeds(cfg)

    total_fresh = sum(len(v) for k, v in fresh_buckets.items() if k != "unknown")
    if total_fresh == 0:
        logger.warning("No IOCs fetched from feeds. Database preserved.")
        sys.exit(0)

    logger.info("Total IOCs from feeds today: %d", total_fresh)

    # 2. Update IOC database (merge new + refresh existing + expire stale)
    stats = update_ioc_db(db, fresh_buckets, ttl_days)

    logger.info("─" * 50)
    logger.info("Database update summary:")
    logger.info("  New IOCs added    : %d", stats["new"])
    logger.info("  Existing refreshed: %d", stats["refreshed"])
    logger.info("  Expired (TTL=%dd) : %d", ttl_days, stats["expired"])
    logger.info("  Total active IOCs : %d", stats["active"])
    logger.info("─" * 50)

    # 3. Dry-run check
    if args.dry_run:
        logger.info("[DRY-RUN] Would write the following CDB lists:")
        for t in ("ip", "domain", "url", "hash"):
            logger.info("  %s: %d entries", t, len(db.get(t, {})))
        logger.info("[DRY-RUN] Database NOT saved. No changes applied.")
        sys.exit(0)

    # 4. Save updated IOC database
    save_ioc_db(state_dir, db)

    # 5. Write CDB lists from active database
    active_iocs = get_active_iocs(db)

    if args.force:
        state_file = Path(state_dir) / "state.json"
        if state_file.exists():
            state_file.unlink()

    changed = update_wazuh_lists(cfg, active_iocs)

    # 6. Restart Wazuh if needed
    if changed and cfg["wazuh"]["restart_on_update"]:
        restart_wazuh(cfg)
    elif not changed:
        logger.info("CDB lists unchanged — Wazuh restart skipped.")

    logger.info("Sync complete.")


if __name__ == "__main__":
    main()
