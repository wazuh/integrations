#!/usr/bin/env python3
import os, json, sqlite3, datetime, logging, traceback, ipaddress, hmac
from logging.handlers import RotatingFileHandler
from flask import Flask, request, abort
import requests
from typing import Dict, Any, List, Tuple, Optional

# ---- Config (envs) ----------------------------------------------------------
OS_URL         = os.getenv("OS_URL", "https://localhost:9200")
OS_USER        = os.getenv("OS_USER", "admin")
OS_PASS        = os.getenv("OS_PASS", "admin")
OS_VERIFY_SSL  = os.getenv("OS_VERIFY_SSL", "false").lower() == "true"
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "replace-with-a-shared-secret")

IPS_DB_PATH     = os.getenv("IPS_DB_PATH", "/var/ossec/integrations/ioc/ips.db")
HASHES_DB_PATH  = os.getenv("HASHES_DB_PATH", "/var/ossec/integrations/ioc/hashes.db")
DOMAINS_DB_PATH = os.getenv("DOMAINS_DB_PATH", "/var/ossec/integrations/ioc/domains.db")
URLS_DB_PATH    = os.getenv("URLS_DB_PATH", "/var/ossec/integrations/ioc/urls.db")

ENRICHER_PORT   = int(os.getenv("ENRICHER_PORT", "3000"))
REG_ROOT_ONLY   = os.getenv("REGISTRABLE_ONLY", "false").lower() == "true"

LOG_ENABLED     = os.getenv("ENRICHER_LOG_ENABLED", "true").lower() == "true"
LOG_LEVEL_NAME  = os.getenv("ENRICHER_LOG_LEVEL", "INFO").upper()
LOG_PATH        = os.getenv("ENRICHER_LOG_PATH", "/var/wazuh-ioc/enricher-ioc.log")
LOG_MAX_MB      = int(os.getenv("ENRICHER_LOG_MAX_MB", "10"))
LOG_BACKUPS     = int(os.getenv("ENRICHER_LOG_BACKUPS", "5"))

def _level_from_name(name: str) -> int:
    if name == "OFF": return 100  
    return getattr(logging, name, logging.INFO)

def _ensure_dir_for(path: str):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)

def init_logger() -> logging.Logger:
    logger = logging.getLogger("enricher-ioc")
    if logger.handlers: return logger
    level = _level_from_name(LOG_LEVEL_NAME)
    logger.setLevel(level)
    if LOG_ENABLED and level < 100:
        try:
            _ensure_dir_for(LOG_PATH)
            fh = RotatingFileHandler(LOG_PATH, maxBytes=LOG_MAX_MB * 1024 * 1024, backupCount=LOG_BACKUPS, encoding="utf-8")
            fh.setFormatter(logging.Formatter("%(message)s"))
            fh.setLevel(level)
            logger.addHandler(fh)
        except Exception as e:
            sh = logging.StreamHandler()
            sh.setFormatter(logging.Formatter("%(message)s"))
            sh.setLevel(level)
            logger.addHandler(sh)
            logger.error(json.dumps({"ts": datetime.datetime.utcnow().isoformat() + "Z", "event": "log_init_error", "error": str(e)}))
    return logger

log = init_logger()

def log_event(event: str, **fields):
    if not LOG_ENABLED or _level_from_name(LOG_LEVEL_NAME) >= 100: return
    rec = {"ts": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z", "event": event, **{k: v for k, v in fields.items() if k != "level"}}
    level = fields.get("level", "INFO").upper()
    line = json.dumps(rec, ensure_ascii=False)
    if level == "DEBUG": log.debug(line)
    elif level == "WARNING": log.warning(line)
    elif level == "ERROR": log.error(line)
    else: log.info(line)


IP_SRC_KEYS = ["srcip", "src_ip", "source_ip", "data.srcip", "data.src_ip", "data.source_ip", "source.ip", "client.ip", "network.client.ip", "observer.ip"]
IP_DST_KEYS = ["dstip", "dst_ip", "destination_ip", "data.dstip", "data.dst_ip", "data.destination_ip", "destination.ip", "server.ip", "network.destination.ip", "target.ip"]
MD5_KEYS    = ["syscheck.md5_after", "syscheck.md5", "data.md5", "md5"]
SHA1_KEYS   = ["syscheck.sha1_after", "syscheck.sha1", "data.sha1", "sha1"]
SHA256_KEYS = ["syscheck.sha256_after", "syscheck.sha256", "data.sha256", "sha256"]
DOMAIN_KEYS = ["domain", "data.domain", "dns.question.name", "dns.question", "host.name"]
URL_KEYS    = ["data.url", "url", "urls", "http.url", "request.url"]

app = Flask(__name__)

def now_iso(): return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def field_get(doc: Dict[str, Any], dotted: str):
    cur = doc
    for p in dotted.split("."):
        if isinstance(cur, dict) and p in cur: cur = cur[p]
        else: return None
    return cur

def _sqlite_fetch_all(c: sqlite3.Connection, query: str, params: Tuple = (), dict_mode: bool = False) -> List[Any]:
    try:
        if dict_mode: c.row_factory = sqlite3.Row
        cur = c.execute(query, params)
        if dict_mode: return [dict(r) for r in cur.fetchall()]
        return cur.fetchall()
    except sqlite3.OperationalError as e:
        msg = str(e).lower()
        if "no such table" in msg or "no such column" in msg:
            log_event("sqlite_missing_schema", query=query, error=str(e), level="DEBUG")
            return []
        raise

def _flat_file_rows(path: str) -> List[List[str]]:
    rows = []
    if not os.path.exists(path): return rows
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"): continue
            rows.append(line.split("|"))
    return rows

def registrable_suffix(domain: str) -> str:
    d = (domain or "").strip().lower().rstrip(".")
    parts = d.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else d

def norm_domain(d: str) -> str:
    d = (d or "").strip().lower().rstrip(".")
    return registrable_suffix(d) if REG_ROOT_ONLY else d

def format_enrichment_dict(row: dict) -> dict:
    return {k: v for k, v in row.items() if v}

def lookup_ip(ip: str, c: Optional[sqlite3.Connection]) -> Optional[Dict[str, str]]:
    ip = (ip or "").strip()
    if not ip: return None

    if c:
        rows = _sqlite_fetch_all(c, "SELECT indicator, source, updated_at as last_seen, event_id, event_info, comment, category, tags, country FROM ips WHERE indicator=?", (ip,), True)
        if rows: return format_enrichment_dict(rows[0])
        
        try:
            ip_int = int(ipaddress.IPv4Address(ip))
            range_query = "SELECT cidr as indicator, source, updated_at as last_seen, event_id, event_info, comment, category, tags, country FROM ips_range WHERE CAST(start_int AS INTEGER) <= ? AND CAST(end_int AS INTEGER) >= ? LIMIT 1"
            rows = _sqlite_fetch_all(c, range_query, (ip_int,), True)
            if rows: return format_enrichment_dict(rows[0])
        except Exception:
            pass
            
        rows = _sqlite_fetch_all(c, "SELECT indicator, source, updated_at FROM ips WHERE indicator=?", (ip,), True)
        if rows:
            res = format_enrichment_dict(rows[0])
            res['last_seen'] = res.pop('updated_at', None)
            return res
            
        try:
            range_query_fallback = "SELECT cidr as indicator, source, updated_at FROM ips_range WHERE CAST(start_int AS INTEGER) <= ? AND CAST(end_int AS INTEGER) >= ? LIMIT 1"
            rows = _sqlite_fetch_all(c, range_query_fallback, (ip_int,), True)
            if rows:
                res = format_enrichment_dict(rows[0])
                res['last_seen'] = res.pop('updated_at', None)
                return res
        except Exception:
            pass

    if not c and os.path.exists(IPS_DB_PATH):
        for parts in _flat_file_rows(IPS_DB_PATH):
            if len(parts) >= 3 and parts[0].strip() == ip:
                return {"indicator": parts[0].strip(), "source": parts[1].strip(), "last_seen": parts[2].strip()}
    return None

def lookup_hash(h: str, htype: str, c: Optional[sqlite3.Connection]) -> Optional[Dict[str, str]]:
    h = (h or "").strip().lower()
    htype = (htype or "").strip().lower()
    if not h or htype not in {"md5", "sha1", "sha256"}: return None

    if c:
        rows = _sqlite_fetch_all(c, "SELECT indicator, type, source, updated_at as last_seen, event_id, event_info, comment, category, tags FROM hashes WHERE indicator=? AND type=?", (h, htype), True)
        if rows: return format_enrichment_dict(rows[0])
        rows = _sqlite_fetch_all(c, "SELECT indicator, type, source, updated_at FROM hashes WHERE indicator=? AND type=?", (h, htype), True)
        if rows:
            res = format_enrichment_dict(rows[0])
            res['last_seen'] = res.pop('updated_at', None)
            return res
            
    if not c and os.path.exists(HASHES_DB_PATH):
        for parts in _flat_file_rows(HASHES_DB_PATH):
            if len(parts) >= 4 and parts[0].strip().lower() == h and parts[1].strip().lower() == htype:
                return {"indicator": parts[0].strip().lower(), "type": parts[1].strip().lower(), "source": parts[2].strip(), "last_seen": parts[3].strip()}
    return None

def lookup_domain(d: str, c: Optional[sqlite3.Connection]) -> Optional[Dict[str, str]]:
    d = norm_domain(d)
    if not d: return None

    if c:
        rows = _sqlite_fetch_all(c, "SELECT indicator, source, updated_at as last_seen, event_id, event_info, comment, category, tags, resolved_ip, country FROM domains WHERE indicator=?", (d,), True)
        if rows: return format_enrichment_dict(rows[0])
        rows = _sqlite_fetch_all(c, "SELECT indicator, source, updated_at FROM domains WHERE indicator=?", (d,), True)
        if rows:
            res = format_enrichment_dict(rows[0])
            res['last_seen'] = res.pop('updated_at', None)
            return res

    if not c and os.path.exists(DOMAINS_DB_PATH):
        for parts in _flat_file_rows(DOMAINS_DB_PATH):
            if len(parts) >= 3 and parts[0].strip().lower() == d:
                return {"indicator": parts[0].strip().lower(), "source": parts[1].strip(), "last_seen": parts[2].strip()}
    return None

def lookup_url(u: str, c: Optional[sqlite3.Connection]) -> Optional[Dict[str, str]]:
    u = (u or "").strip()
    if not u: return None

    if c:
        rows = _sqlite_fetch_all(c, "SELECT indicator, source, updated_at as last_seen, event_id, event_info, comment, category, tags FROM urls WHERE indicator=?", (u,), True)
        if rows: return format_enrichment_dict(rows[0])
        rows = _sqlite_fetch_all(c, "SELECT indicator, source, updated_at FROM urls WHERE indicator=?", (u,), True)
        if rows:
            res = format_enrichment_dict(rows[0])
            res['last_seen'] = res.pop('updated_at', None)
            return res

    if not c and os.path.exists(URLS_DB_PATH):
        for parts in _flat_file_rows(URLS_DB_PATH):
            if len(parts) >= 3 and parts[0].strip() == u:
                return {"indicator": parts[0].strip(), "source": parts[1].strip(), "last_seen": parts[2].strip()}
    return None

def _collect_values(doc: Dict[str, Any], keys: List[str]) -> List[Tuple[str, str]]:
    out = []
    for k in keys:
        v = field_get(doc, k)
        if v is None: continue
        if isinstance(v, list):
            for item in v:
                if isinstance(item, str) and item.strip():
                    out.append((item.strip(), k))
        elif isinstance(v, str):
            if v.strip(): out.append((v.strip(), k))
    return out

def update_doc(index, _id, enrichment):
    url = f"{OS_URL}/{index}/_update/{_id}"
    body = {"doc": enrichment}
    r = requests.post(url, json=body, auth=(OS_USER, OS_PASS), verify=OS_VERIFY_SSL, timeout=15)
    if r.status_code == 404:
        logging.warning("Update skipped for missing document %s/%s: %s", index, _id, r.text)
        return
    if not r.ok: raise RuntimeError(f"Update failed: {r.status_code} {r.text}")

def _is_sqlite_db(path):
    try:
        with open(path, "rb") as f:
            return f.read(16) == b"SQLite format 3\x00"
    except Exception: return False

@app.route("/health", methods=["GET"])
def health(): return {"ok": True}, 200

@app.route("/enrich", methods=["POST"])
def enrich():
    try: payload = request.get_json(force=True)
    except Exception: abort(400, "Invalid JSON")

    req_secret = str(payload.get("secret", ""))
    if not hmac.compare_digest(req_secret, WEBHOOK_SECRET):
        log_event("auth_failed", reason="bad_secret", level="WARNING")
        abort(403, "Forbidden")

    hits = payload.get("hits", [])
    if not isinstance(hits, list): abort(400, "hits must be a list")

    log_event("webhook_received", hits=len(hits), remote_addr=request.remote_addr)

    # 🚀 Performance Initialization: Open active SQL connections exactly ONCE per request block 
    conns = {"ips": None, "hashes": None, "domains": None, "urls": None}
    for key, path in [("ips", IPS_DB_PATH), ("hashes", HASHES_DB_PATH), ("domains", DOMAINS_DB_PATH), ("urls", URLS_DB_PATH)]:
        if os.path.exists(path) and _is_sqlite_db(path):
            conns[key] = sqlite3.connect(path)

    updated = 0

    try:
        for h in hits:
            index = h.get("_index")
            _id   = h.get("_id")
            src   = h.get("_source", {})

            if not index or not _id: continue
            if isinstance(src, dict) and "ioc_updated_at" in src: continue

            try:
                ioc_hits = {}

                for val, fieldname in _collect_values(src, IP_SRC_KEYS + IP_DST_KEYS):
                    found = lookup_ip(val, conns["ips"])
                    if found and "ips" not in ioc_hits:
                        found["field_matched"] = fieldname
                        ioc_hits["ips"] = found

                for val, fieldname in _collect_values(src, MD5_KEYS):
                    found = lookup_hash(val.lower(), "md5", conns["hashes"])
                    if found and "hashes" not in ioc_hits:
                        found["field_matched"] = fieldname
                        ioc_hits["hashes"] = found

                for val, fieldname in _collect_values(src, SHA1_KEYS):
                    found = lookup_hash(val.lower(), "sha1", conns["hashes"])
                    if found and "hashes" not in ioc_hits:
                        found["field_matched"] = fieldname
                        ioc_hits["hashes"] = found

                for val, fieldname in _collect_values(src, SHA256_KEYS):
                    found = lookup_hash(val.lower(), "sha256", conns["hashes"])
                    if found and "hashes" not in ioc_hits:
                        found["field_matched"] = fieldname
                        ioc_hits["hashes"] = found

                for val, fieldname in _collect_values(src, DOMAIN_KEYS):
                    found = lookup_domain(val.lower(), conns["domains"])
                    if found and "domains" not in ioc_hits:
                        found["field_matched"] = fieldname
                        ioc_hits["domains"] = found

                for val, fieldname in _collect_values(src, URL_KEYS):
                    found = lookup_url(val, conns["urls"])
                    if found and "urls" not in ioc_hits:
                        found["field_matched"] = fieldname
                        ioc_hits["urls"] = found

                hits_out = ioc_hits

                if hits_out:
                    total_hits = len(hits_out)
                    type_map = {"ips": "ip", "hashes": "hash", "domains": "domain", "urls": "url"}
                    types_present = sorted({type_map[k] for k in hits_out.keys()})
                    dynamic_type_tags = [f"ioc:{t}" for t in types_present]

                    collected_tags = [t.strip() for v in hits_out.values() for t in v.get("tags", "").split(",") if t.strip()]
                    unique_tags = sorted(set(["threatintel", "ioc:hit"] + dynamic_type_tags + collected_tags))

                    enrichment = {
                        "ioc_check_status": True,
                        "ioc_updated_at": now_iso(),
                        "ioc_hits": hits_out,
                        "ioc_sources": list(sorted({v.get("source", "MISP") for v in hits_out.values()})) or ["MISP"],
                        "ioc_warning": f"{total_hits} indicator(s) matched local IOC databases. Treat as malicious.",
                        "enrichment": {"tags": unique_tags, "confidence": "high"}
                    }
                    
                    try:
                        update_doc(index, _id, enrichment)
                        updated += 1
                    except Exception as e:
                        log_event("reindex_failed", index=index, id=_id, error=str(e), level="ERROR")

            except Exception as e:
                log_event("processing_error", index=index, id=_id, error=str(e), traceback=traceback.format_exc(), level="ERROR")
    finally:
        for c in conns.values():
            if c: c.close()

    log_event("webhook_processed", hits=len(hits), updated=updated)
    return {"updated": updated}, 200

if __name__ == "__main__":
    flask_logger = logging.getLogger("werkzeug")
    flask_logger.setLevel(_level_from_name(LOG_LEVEL_NAME))
    app.run(host="0.0.0.0", port=ENRICHER_PORT, debug=False)
