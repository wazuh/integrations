import os
import json
import configparser
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timedelta, timezone

import requests
from filelock import FileLock

WAZUH_HOME = os.environ.get("WAZUH_HOME", "/var/ossec")
pwd = os.path.dirname(os.path.realpath(__file__))
DEFAULT_MAX_CONCURRENT = 10
MAX_BACKLOG_HOURS = 7 * 24
API_LIMIT = 4000
IOC_FIELDS = {
    "v": "gti_assessment.verdict.value",
    "s": "gti_assessment.severity.value",
    "ts": "gti_assessment.threat_score.value",
    "lmd": "last_modification_date",
    "c": "country",
    "asn": "asn",
    "ao": "as_owner",
    "cd": "creation_date",
    "lsd": "last_submission_date",
    "lad": "last_analysis_date",
    "md5": "md5",
    "sha256": "sha256",
    "mn": "meaningful_name"
}
THREAT_LIST_IDS = [
    "ransomware",
    "malicious-network-infrastructure",
    "malware",
    "threat-actor",
    "trending",
    "mobile",
    "osx",
    "linux",
    "iot",
    "cryptominer",
    "phishing",
    "first-stage-delivery-vectors",
    "vulnerability-weaponization",
    "infostealer"
]

utc_now = datetime.now(timezone.utc)


def build_requests_verify() -> object:
    ca_bundle = os.environ.get("GTI_CA_BUNDLE")
    if ca_bundle:
        return ca_bundle
    return True


def load_config(path: str) -> Dict[str, Any]:
    parser = configparser.ConfigParser()
    parser.read(path)

    def get_list(section: str, key: str) -> List[str]:
        value = parser.get(section, key, fallback="")
        return [v.strip() for v in value.split(",") if v.strip()]

    api_params = {"limit": API_LIMIT}
    threat_score_raw = parser.get("api", "threat_score", fallback="").strip()
    threat_score_warning: Optional[str] = None
    threat_score: Optional[int] = None
    if threat_score_raw:
        try:
            threat_score = int(threat_score_raw)
            if threat_score < 0 or threat_score > 100:
                threat_score_warning = f"Ignoring invalid threat_score '{threat_score_raw}' (must be between 0 to 100)"
                threat_score = None
        except ValueError:
            threat_score_warning = (f"Ignoring invalid threat_score '{threat_score_raw}' (must be an integer between 0 "
                                    f"to 100)")
            threat_score = None

    if threat_score is not None:
        api_params["query"] = f"gti_score:{threat_score}+"

    return {
        "api_key": parser.get("api", "api_key"),
        "base_url": parser.get("api", "base_url"),
        "threat_list_ids": get_list("api", "threat_list_ids"),
        "api_params": api_params,
        "threat_score_warning": threat_score_warning,
        "severity": set(get_list("filters", "severity")),
        "verdict": set(get_list("filters", "verdict")),
        "ioc_lifetime": parser.getint("runtime", "ioc_lifetime_days", fallback=7),
        "max_concurrent": DEFAULT_MAX_CONCURRENT,
        "log_file": f"{pwd}/{parser.get('runtime', 'log_file', fallback='gti_sync.log')}",
        "log_level": parser.get("runtime", "log_level", fallback="INFO"),
        "files": {
            "ip": os.path.join(WAZUH_HOME, "integrations", "gti_iocs", "malicious_ips.json"),
            "domain": os.path.join(WAZUH_HOME, "integrations", "gti_iocs", "malicious_domains.json"),
            "url": os.path.join(WAZUH_HOME, "integrations", "gti_iocs", "malicious_urls.json"),
            "file": os.path.join(WAZUH_HOME, "integrations", "gti_iocs", "malicious_filehashes.json"),
        },
        "checkpoint_file": f"{pwd}/{parser.get('files', 'checkpoint_file', fallback='checkpoint.json')}",
    }


# ================= LOGGING =================
def setup_logging(log_file: str, log_level: str) -> None:
    os.makedirs(os.path.dirname(log_file), exist_ok=True) if os.path.dirname(log_file) else None
    logger = logging.getLogger()

    level_name = (log_level or "INFO").strip().upper()
    level = getattr(logging, level_name, None)
    if not isinstance(level, int):
        level = logging.INFO
    logger.setLevel(level)
    if logger.handlers:
        logger.handlers.clear()

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(level)
    fh.setFormatter(formatter)
    logger.addHandler(fh)


# ================= UTILITIES ===============
def t2_hour_utc() -> str:
    """Return the T-2 UTC hour timestamp as YYYYMMDDHH string"""
    dt = utc_now - timedelta(hours=2)
    return dt.strftime("%Y%m%d%H")


def generate_timestamps(last_ts_str) -> List[str]:
    """
    Generate hourly UTC timestamps in YYYYMMDDHH format for VT hourly API.

    :param last_ts_str: Last checkpoint timestamp in YYYYMMDDHH UTC
    :return: List of hourly timestamps in YYYYMMDDHH format exclusive of last_ts_str
    """
    timestamps: List[str] = []
    # Parse last checkpoint string to UTC datetime
    last_dt = datetime.strptime(last_ts_str, "%Y%m%d%H").replace(tzinfo=timezone.utc)
    # Current UTC minus 2 hours (VT API only returns up to T-2)
    now_dt = datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(hours=2)
    current = last_dt + timedelta(hours=1)
    while current <= now_dt:
        timestamps.append(current.strftime("%Y%m%d%H"))
        current += timedelta(hours=1)
    return timestamps


def load_json(path: str, default: Any) -> Any:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse JSON file {path}: {e}")
            return default
    return default


def save_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, separators=(",", ":"), ensure_ascii=False)
    logging.debug(f"Saved JSON file {path} with {len(data)} entries.")


def extract_fields(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract specified fields from an IOC item.
    Supports dot notation for nested fields (like attributes.url).
    If the field doesn't exist, it is skipped.
    """
    result: Dict[str, Any] = {}
    for key, path in IOC_FIELDS.items():
        value = item
        for part in path.split("."):
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
        if value is not None:
            result[key] = value
    return result


def classify_ioc(item: Dict[str, Any]) -> Optional[str]:
    t = item.get("type", "").lower()
    if "ip" in t:
        return "ip"
    if "domain" in t:
        return "domain"
    if "url" in t:
        return "url"
    if "file" in t or "hash" in t:
        return "file"
    return None


def normalize_key(ioc_type: str, key: str) -> str:
    if ioc_type == "domain":
        return key.lower().strip()
    if ioc_type == "url":
        return key.strip()
    return key


def get_ioc_key(item: Dict[str, Any], ioc_type: str) -> Optional[str]:
    if ioc_type == "url":
        return item.get("attributes", {}).get("url")
    return item.get("id")


def filter_ioc(item: Dict[str, Any], cfg: Dict[str, Any]) -> bool:
    attr = item.get("attributes", {})
    gti_assessment = attr.get("gti_assessment", {})
    if cfg["severity"] and (gti_assessment.get("severity") or {}).get("value") not in cfg["severity"]:
        return False
    if cfg["verdict"] and (gti_assessment.get("verdict") or {}).get("value") not in cfg["verdict"]:
        return False
    return True


# ================= PROCESSING =================
def upsert(store: Dict[str, Dict[str, Any]], items: List[Dict[str, Any]], cfg: Dict[str, Any], tl_id: str) -> Tuple[
    int, int]:
    added = updated = filtered = 0
    expiry_iso = (utc_now + timedelta(days=cfg["ioc_lifetime"])).strftime("%Y%m%d%H")
    logging.debug(f"Upserting {len(items)} IOCs from Threat List {tl_id}")
    for item in items:
        data = item.get("data", {})
        if not filter_ioc(data, cfg):
            filtered += 1
            continue
        ioc_type = classify_ioc(data)
        if not ioc_type:
            continue
        key = get_ioc_key(data, ioc_type)
        if not key:
            continue
        key = normalize_key(ioc_type, key)
        value = {"exp": expiry_iso, **extract_fields(data.get("attributes", {}))}
        if key in store[ioc_type]:
            if store[ioc_type][key] != value:
                store[ioc_type][key] = value
                updated += 1
        else:
            store[ioc_type][key] = value
            added += 1
    logging.info(f"Threat List {tl_id}: added={added}, updated={updated}, filtered={filtered}")
    return added, updated


def atomic_write(path: str, data: Any) -> None:
    """
    Atomic write with file locking to prevent concurrent corruption.
    """
    lock_path = f"{path}.lock"
    lock = FileLock(lock_path, timeout=10)
    with lock:
        tmp = Path(path).with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, separators=(",", ":"), ensure_ascii=False)
        tmp.replace(path)


def remove_expired(store: Dict[str, Dict[str, Any]]) -> int:
    removed = 0
    for ioc_type, iocs in store.items():
        for key in list(iocs.keys()):
            try:
                expiry_dt = datetime.strptime(iocs[key]["exp"], "%Y%m%d%H").replace(tzinfo=timezone.utc)
                if expiry_dt.tzinfo is None:
                    expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
                if expiry_dt < utc_now:
                    del iocs[key]
                    removed += 1
            except (ValueError, KeyError):
                del iocs[key]
                removed += 1
    logging.info(f"Removed expired IOCs: {removed}")
    return removed



# Create a thread-local storage object
thread_data = threading.local()

def get_thread_session():
    """Returns a session unique to the current thread, creating it if necessary."""
    if not hasattr(thread_data, "session"):
        thread_data.session = requests.Session()
        # You can still mount adapters here for specific thread-level tuning if needed
    return thread_data.session

# ================= HTTP =================
def fetch(api_object: Dict[str, Any], verify: object) -> List[Dict[str, Any]]:
    # Get the session specific to this worker thread
    session = get_thread_session()

    resp = session.get(
        api_object["url"],
        headers={"x-apikey": api_object["key"]},
        params=api_object["params"],
        timeout=60,
        verify=verify,
    )

    resp.raise_for_status()
    data = resp.json()
    iocs = data.get("iocs", [])
    logging.info(f"Fetched {api_object['url']}, received {len(iocs)} IOCs")
    return iocs


def process_threat_list(tl_id, cfg, store, checkpoint, verify: object, update_lock: threading.Lock):
    api_object = {"key": cfg["api_key"], "params": cfg["api_params"]}

    if tl_id not in checkpoint:
        api_object["url"] = f"{cfg['base_url']}/threat_lists/{tl_id}/latest"
        resp = fetch(api_object, verify)
        with update_lock:
            upsert(store, resp, cfg, tl_id)
            checkpoint[tl_id] = t2_hour_utc()
            logging.info(f"Checkpoint initialized: {tl_id}={checkpoint[tl_id]}")
        return

    # Backlog processing
    timestamps = generate_timestamps(checkpoint[tl_id])
    if len(timestamps) > MAX_BACKLOG_HOURS:
        skipped = len(timestamps) - MAX_BACKLOG_HOURS
        logging.warning(
            f"{tl_id} backlog capped: skipping {skipped} hours (processing most recent {MAX_BACKLOG_HOURS} hours)"
        )
        timestamps = timestamps[-MAX_BACKLOG_HOURS:]
    counter = 0
    for ts in timestamps:
        try:
            api_object["url"] = f"{cfg['base_url']}/threat_lists/{tl_id}/{ts}"
            resp = fetch(api_object, verify)
            with update_lock:
                upsert(store, resp, cfg, tl_id)
                # update checkpoint ONLY after success
                checkpoint[tl_id] = ts
                logging.debug(f"{tl_id} checkpoint -> {ts}")
            counter += 1
        except Exception as e:
            logging.error(f"{tl_id} failed at {ts}: {e}")
            break  # stop this TL, others continue


# ================= MAIN =================
def run(cfg: Dict[str, Any]) -> None:
    # Load once
    store = {k: load_json(v, {}) for k, v in cfg["files"].items()}
    checkpoint = load_json(cfg["checkpoint_file"], {})
    verify = build_requests_verify()
    update_lock = threading.Lock()
    try:
        with ThreadPoolExecutor(max_workers=cfg["max_concurrent"]) as executor:
            futures_map = {
                executor.submit(
                    process_threat_list,
                    tl_id,
                    cfg,
                    store,
                    checkpoint,
                    verify,
                    update_lock,
                ): tl_id for tl_id in cfg["threat_list_ids"]
            }
            for fut in as_completed(futures_map):
                tl_id = futures_map[fut]
                try:
                    fut.result() # This will only throw for the specific thread being checked
                except Exception as e:
                    # Log the specific thread failure but allow the loop to continue to the next future
                    logging.error(f"Thread for {tl_id} encountered an error: {e}")
    except Exception as e:
        logging.error(f"Fatal error during execution : {e}")
    finally:
        # FINAL SAFETY FLUSH (CRITICAL)
        try:
            removed = remove_expired(store)
            for t, path in cfg["files"].items():
                atomic_write(path, store[t])
            atomic_write(cfg["checkpoint_file"], checkpoint)
            logging.info(f"Final flush complete. Expired removed={removed}")
        except Exception:
            logging.exception("Failed during final flush")


def validate_config(cfg: Dict[str, Any]) -> list[str]:
    missing = []
    SEVERITY_LEVELS = ["SEVERITY_NONE", "SEVERITY_LOW", "SEVERITY_MEDIUM", "SEVERITY_HIGH", "SEVERITY_UNKNOWN"]
    VERDICT_LEVELS = ["VERDICT_BENIGN", "VERDICT_UNDETECTED", "VERDICT_SUSPICIOUS", "VERDICT_MALICIOUS",
                      "VERDICT_UNKNOWN"]
    if not cfg.get("api_key"):
        missing.append("api.api_key")
    if not cfg.get("base_url"):
        missing.append("api.base_url")
    if not cfg.get("threat_list_ids"):
        logging.warning(f"No threat list selected; falling back to default all Threat Lists - {THREAT_LIST_IDS}")
        cfg["threat_list_ids"] = THREAT_LIST_IDS
    if cfg.get("severity") and not set(cfg.get("severity")).issubset(set(SEVERITY_LEVELS)):
        logging.warning(f"Invalid Severity levels detected; falling back to the default (SEVERITY_HIGH). ")
    if cfg.get("verdict") and not set(cfg.get("verdict")).issubset(set(VERDICT_LEVELS)):
        logging.warning(f"Invalid Verdict levels detected; falling back to the default (VERDICT_SUSPICIOUS,"
                        f"VERDICT_MALICIOUS). ")
    if not cfg.get("checkpoint_file"):
        missing.append("files.checkpoint_file")

    if cfg.get("threat_score_warning"):
        logging.warning(cfg["threat_score_warning"])

    log_level = str(cfg.get("log_level", "INFO") or "INFO").strip().upper()
    if log_level == "WARN":
        log_level = "WARNING"
    if log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        log_level = "INFO"
        logging.warning("Invalid runtime.log_level; defaulting to INFO")
    cfg["log_level"] = log_level
    return missing


def main() -> None:
    global utc_now
    utc_now = datetime.now(timezone.utc)
    cfg = load_config(f"{pwd}/gti-config.ini")
    setup_logging(cfg["log_file"], cfg.get("log_level", "INFO"))
    logging.info("Starting GTI IOC sync")
    try:
        missing = validate_config(cfg)
        if missing:
            raise ValueError(f"Invalid configuration, missing: {', '.join(missing)}")
        logging.info(
            "Config loaded: "
            f"threat_lists={len(cfg.get('threat_list_ids', []))}, "
            f"max_concurrent={cfg.get('max_concurrent')}, "
            f"log_level={cfg.get('log_level')}, "
            f"checkpoint_file={cfg.get('checkpoint_file')}, "
            f"output_files={cfg.get('files')}"
        )
        run(cfg)
    except Exception as e:
        logging.error(f"{e}")
    finally:
        logging.info("GTI IOC sync completed")


if __name__ == "__main__":
    main()
