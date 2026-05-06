#!/usr/bin/env python3
import os, time, shutil, sqlite3, requests, datetime as dt, ipaddress, socket, gzip, csv
from io import BytesIO
import bisect
import concurrent.futures

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Load local .env file natively if it exists
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(env_path):
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip()
                # Strip matching surrounding single/double quotes so .env values like KEY="val" work as expected
                if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
                    v = v[1:-1]
                os.environ.setdefault(k, v)

# ===================== Config via ENV =====================
MISP_URL      = os.getenv("MISP_URL")
MISP_AUTH_KEY = os.getenv("MISP_AUTH_KEY")
MISP_VERIFY   = os.getenv("MISP_VERIFYCERT", "true").lower() == "true"
LAST_DAYS     = os.getenv("LAST_DAYS", "30")
TO_IDS        = os.getenv("TO_IDS", "true").lower() == "true"

IOC_DIR       = os.getenv("IOC_DIR", "/var/ossec/integrations/ioc")

PAGE_LIMIT    = int(os.getenv("PAGE_LIMIT", "0"))   
REG_ROOT_ONLY = os.getenv("REGISTRABLE_ONLY", "false").lower() == "true"   

FULL_RESET    = os.getenv("FULL_RESET", "true").lower() == "true"   
BACKUP_BEFORE_RESET = os.getenv("BACKUP_BEFORE_RESET", "true").lower() == "true"
# ==========================================================

IPS_DB      = os.path.join(IOC_DIR, "ips.db")
HASHES_DB   = os.path.join(IOC_DIR, "hashes.db")
DOMAINS_DB  = os.path.join(IOC_DIR, "domains.db")
URLS_DB     = os.path.join(IOC_DIR, "urls.db")

if not MISP_VERIFY:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===================== GEOIP OFFLINE DOWNLOADER =====================
def load_dbip_memory():
    """ Downloads DB-IP Lite CSV dynamically and formats into memory lists for binary search. """
    y, m = dt.datetime.now().year, dt.datetime.now().month
    urls = []
    for _ in range(3):
        urls.append(f"https://download.db-ip.com/free/dbip-country-lite-{y}-{m:02d}.csv.gz")
        m -= 1
        if m == 0:
            m = 12
            y -= 1
            
    print(f"[*] Fetching offline GeoIP database...")
    csv_data = None
    for url in urls:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                csv_data = r.content
                break
        except Exception:
            pass

    start_ips = []
    countries = []

    if not csv_data:
        print("[WARN] Could not download DB-IP CSV. Extra geographical fields will be empty.")
        return start_ips, countries
        
    print("[*] Parsing DB-IP database to memory...")
    try:
        with gzip.GzipFile(fileobj=BytesIO(csv_data)) as gz:
            reader = csv.reader(gz.read().decode('utf-8', errors='ignore').splitlines())
            for row in reader:
                if len(row) >= 4:
                    try:
                        # Extract exclusively numeric IPv4 starting ranges
                        ip_int = int(ipaddress.IPv4Address(row[0]))
                        start_ips.append(ip_int)
                        # Last column is usually the Country Code (row[3])
                        countries.append(row[3])
                    except ipaddress.AddressValueError:
                        pass # Ignore non-IPv4 blocks
    except Exception as e:
        print(f"[WARN] Error parsing GeoIP Data: {e}")

    return start_ips, countries

def geolocate(ip_str, start_ips, countries):
    if not start_ips: return ""
    try:
        ip_int = int(ipaddress.IPv4Address(ip_str))
        idx = bisect.bisect_right(start_ips, ip_int) - 1
        if idx >= 0:
            return countries[idx]
    except Exception:
        pass
    return ""

def resolve_domain(d):
    """ Worker function to resolve DNS tightly """
    try:
        socket.setdefaulttimeout(1.5)
        ip = socket.gethostbyname(d)
        return d, ip
    except Exception:
        return d, ""

def format_domain_cache_enrichment(domains_dict, start_ips, countries):
    """ Batches DNS resolution using a massive thread pool to conquer timeouts """
    print(f"[*] Processing Domains DNS ({len(domains_dict)}) ...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ext:
        futures = {ext.submit(resolve_domain, d): d for d in domains_dict.keys() if d}
        for f in concurrent.futures.as_completed(futures):
            d, ip = f.result()
            domains_dict[d]['resolved_ip'] = ip
            domains_dict[d]['country'] = geolocate(ip, start_ips, countries) if ip else ""
# ====================================================================

def make_session(timeout=60):
    s = requests.Session()
    retry_kwargs = dict(total=5, connect=5, read=5, backoff_factor=1.5,
                        status_forcelist=[429, 500, 502, 503, 504])
    try:
        r = Retry(allowed_methods=["GET", "POST"], **retry_kwargs)
    except TypeError:
        r = Retry(method_whitelist=["GET", "POST"], **retry_kwargs)
    s.mount("https://", HTTPAdapter(max_retries=r))
    s.mount("http://",  HTTPAdapter(max_retries=r))
    s.request_timeout = timeout
    return s

def sql(db_path, stmt, params=(), many=None):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as c:
        if many:
            c.executemany(stmt, many)
        else:
            cur = c.execute(stmt, params)
            return cur.fetchall()

def init_dbs_full_reset():
    for p in (IPS_DB, HASHES_DB, DOMAINS_DB, URLS_DB):
        if BACKUP_BEFORE_RESET and os.path.exists(p):
            ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            shutil.copy2(p, f"{p}.{ts}.bak")
        try:
            if os.path.exists(p): os.remove(p)
        except OSError:
            pass

    sql(IPS_DB, """
    CREATE TABLE ips_exact(
      ip TEXT PRIMARY KEY,
      source TEXT, confidence INTEGER,
      event_id TEXT, event_info TEXT, comment TEXT, category TEXT, tags TEXT,
      country TEXT,
      updated_at TEXT
    );""")
    sql(IPS_DB, """
    CREATE TABLE ips_range(
      start_int TEXT NOT NULL, end_int TEXT NOT NULL,
      cidr TEXT, source TEXT, confidence INTEGER,
      event_id TEXT, event_info TEXT, comment TEXT, category TEXT, tags TEXT,
      country TEXT,
      updated_at TEXT,
      PRIMARY KEY(start_int, end_int)
    );""")
    sql(IPS_DB, "CREATE INDEX idx_ips_range_start ON ips_range(start_int);")
    sql(IPS_DB, "CREATE INDEX idx_ips_range_end   ON ips_range(end_int);")

    sql(HASHES_DB, """
    CREATE TABLE hashes_exact(
      hash TEXT PRIMARY KEY, algo TEXT, source TEXT, confidence INTEGER,
      event_id TEXT, event_info TEXT, comment TEXT, category TEXT, tags TEXT,
      updated_at TEXT
    );""")

    sql(DOMAINS_DB, """
    CREATE TABLE domains_exact(
      domain TEXT PRIMARY KEY, source TEXT, confidence INTEGER,
      event_id TEXT, event_info TEXT, comment TEXT, category TEXT, tags TEXT,
      resolved_ip TEXT, country TEXT,
      updated_at TEXT
    );""")

    sql(URLS_DB, """
    CREATE TABLE urls_exact(
      url TEXT PRIMARY KEY, source TEXT, confidence INTEGER,
      event_id TEXT, event_info TEXT, comment TEXT, category TEXT, tags TEXT,
      updated_at TEXT
    );""")

    # Views explicitly pick up specific variables and extra properties
    sql(IPS_DB, """
    CREATE VIEW ips AS
    SELECT ip AS indicator, source, updated_at, event_id, event_info, comment, category, tags, country FROM ips_exact
    UNION ALL
    SELECT cidr AS indicator, source, updated_at, event_id, event_info, comment, category, tags, country FROM ips_range;
    """)
    sql(HASHES_DB, "CREATE VIEW hashes AS SELECT hash AS indicator, LOWER(algo) AS type, source, updated_at, event_id, event_info, comment, category, tags FROM hashes_exact;")
    sql(DOMAINS_DB,"CREATE VIEW domains AS SELECT domain AS indicator, source, updated_at, event_id, event_info, comment, category, tags, resolved_ip, country FROM domains_exact;")
    sql(URLS_DB,   "CREATE VIEW urls AS SELECT url AS indicator, source, updated_at, event_id, event_info, comment, category, tags FROM urls_exact;")

def registrable_suffix(domain: str) -> str:
    d = (domain or "").strip().lower().rstrip(".")
    parts = d.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else d

def norm_domain(d: str) -> str:
    d = (d or "").strip().lower().rstrip(".")
    return registrable_suffix(d) if REG_ROOT_ONLY else d

def is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False

def cidr_to_range(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    return str(int(net.network_address)), str(int(net.broadcast_address))

def tag_list_to_str(tags):
    if not tags: return ""
    return ",".join(t.get("name", "") for t in tags if "name" in t)

def upsert_ips(ips_exact, cidrs, src, stamp):
    if ips_exact:
        rows = [(ip, src, 100, md.get('event_id'), md.get('event_info'), md.get('comment'), md.get('category'), md.get('tags'), md.get('country'), stamp) for ip, md in ips_exact.items()]
        sql(IPS_DB, "INSERT OR REPLACE INTO ips_exact(ip,source,confidence,event_id,event_info,comment,category,tags,country,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)", many=rows)
    if cidrs:
        rows = []
        for c, md in cidrs.items():
            try:
                s, e = cidr_to_range(c)
                rows.append((s, e, c, src, 100, md.get('event_id'), md.get('event_info'), md.get('comment'), md.get('category'), md.get('tags'), md.get('country'), stamp))
            except Exception:
                pass
        if rows:
            sql(IPS_DB, "INSERT OR REPLACE INTO ips_range(start_int,end_int,cidr,source,confidence,event_id,event_info,comment,category,tags,country,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", many=rows)

def upsert_hashes(hset, algo, src, stamp):
    if not hset: return
    rows = [(h.lower(), algo, src, 100, md.get('event_id'), md.get('event_info'), md.get('comment'), md.get('category'), md.get('tags'), stamp) for h, md in hset.items()]
    sql(HASHES_DB, "INSERT OR REPLACE INTO hashes_exact(hash,algo,source,confidence,event_id,event_info,comment,category,tags,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)", many=rows)

def upsert_domains(domains, src, stamp):
    if not domains: return
    dmap = {}
    for d, md in domains.items():
        if not d: continue
        nd = norm_domain(d)
        if nd and nd not in dmap:
            dmap[nd] = md
    rows = [(d, src, 90, md.get('event_id'), md.get('event_info'), md.get('comment'), md.get('category'), md.get('tags'), md.get('resolved_ip'), md.get('country'), stamp) for d, md in dmap.items()]
    sql(DOMAINS_DB, "INSERT OR REPLACE INTO domains_exact(domain,source,confidence,event_id,event_info,comment,category,tags,resolved_ip,country,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", many=rows)

def upsert_urls(urls, src, stamp):
    if not urls: return
    rows = [(u, src, 95, md.get('event_id'), md.get('event_info'), md.get('comment'), md.get('category'), md.get('tags'), stamp) for u, md in urls.items()]
    sql(URLS_DB, "INSERT OR REPLACE INTO urls_exact(url,source,confidence,event_id,event_info,comment,category,tags,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)", many=rows)

TYPE_IPS       = {"ip-src", "ip-dst", "ip-src|port", "ip-dst|port"}
TYPE_DOMAIN    = {"domain", "hostname"}
TYPE_URL       = {"url"}
TYPE_HASH_MD5  = {"md5", "filename|md5"}
TYPE_HASH_SHA1 = {"sha1", "filename|sha1"}
TYPE_HASH_S256 = {"sha256", "filename|sha256"}


def extract_ioc_value(t, raw):
    if "|" in t:
        parts_t = t.split("|")
        parts_v = raw.split("|")
        if len(parts_t) == len(parts_v):
            for pt, pv in zip(parts_t, parts_v):
                if pt in {"md5", "sha1", "sha256", "ip-src", "ip-dst"}:
                    return pv
        return parts_v[0]
    return raw

def collect_from_misp(start_ips, countries):
    if not MISP_URL or not MISP_AUTH_KEY:
        raise SystemExit("Set MISP_URL and MISP_AUTH_KEY")

    s = make_session(timeout=90)
    s.verify = MISP_VERIFY
    headers = {"Authorization": MISP_AUTH_KEY, "Accept": "application/json", "Content-Type": "application/json"}
    url = f"{MISP_URL.rstrip('/')}/attributes/restSearch"
    
    ips, cidrs, domains, urls, md5, sha1, sha256 = {}, {}, {}, {}, {}, {}, {}
    page = 1
    limit = 5000
    total_attrs = 0
    all_types = list(TYPE_IPS | TYPE_DOMAIN | TYPE_URL | TYPE_HASH_MD5 | TYPE_HASH_SHA1 | TYPE_HASH_S256)

    print(f"[*] Polling MISP API endpoint ({limit}/page)...")
    while True:
        payload = {"returnFormat": "json", "type": all_types, "includeEventTags": 1, "includeContext": 1, "page": page, "limit": limit}
        if TO_IDS: payload["to_ids"] = 1
        if LAST_DAYS: payload["last"] = f"{LAST_DAYS}d"

        r = s.post(url, headers=headers, json=payload, timeout=s.request_timeout)
        if not r.ok:
            print(f"[ERR] MISP API Error page {page}: {r.status_code} {r.text[:200]}")
            break

        data = r.json()
        results = data.get("response", {}).get("Attribute", []) if "response" in data else data
        if not results: break

        total_attrs += len(results)
        for attr in results:
            raw = (attr.get("value") or "").strip()
            t   = (attr.get("type") or "").strip().lower()
            if not raw or not t: continue
            raw = extract_ioc_value(t, raw)

            event = attr.get("Event", {})
            all_tags = []
            if "Tag" in attr: all_tags.extend(attr["Tag"])
            if "Tag" in event: all_tags.extend(event["Tag"])
            
            seen_tags, uniq_tags = set(), []
            for tag in all_tags:
                nm = tag.get("name")
                if nm and nm not in seen_tags:
                    seen_tags.add(nm)
                    uniq_tags.append(tag)
                    
            tag_str = tag_list_to_str(uniq_tags)

            md = {
                "event_id": str(attr.get("event_id") or ""),
                "event_info": str(event.get("info") or ""),
                "comment": str(attr.get("comment") or ""),
                "category": str(attr.get("category") or ""),
                "tags": tag_str
            }

            if t in TYPE_IPS:
                if "/" in raw:
                    md["country"] = ""
                    cidrs[raw] = md
                else:
                    md["country"] = geolocate(raw, start_ips, countries)
                    try:
                        ipaddress.ip_address(raw)
                        ips[raw] = md
                    except Exception:
                        pass
            elif t in TYPE_DOMAIN:
                domains[raw] = md
            elif t in TYPE_URL:
                urls[raw] = md
            elif t in TYPE_HASH_MD5: md5[raw.lower()] = md
            elif t in TYPE_HASH_SHA1: sha1[raw.lower()] = md
            elif t in TYPE_HASH_S256: sha256[raw.lower()] = md

        if len(results) < limit: break
        page += 1
        if PAGE_LIMIT and page > PAGE_LIMIT: break

    # Enrich domains offline
    format_domain_cache_enrichment(domains, start_ips, countries)

    return {
        "ips": ips, "cidrs": cidrs, "domains": domains, "urls": urls,
        "md5": md5, "sha1": sha1, "sha256": sha256, "total": total_attrs
    }

def main():
    os.makedirs(IOC_DIR, exist_ok=True)
    if not FULL_RESET:
        raise SystemExit("This build expects FULL_RESET=true (drop & rebuild every run).")

    start = time.time()
    v_url = MISP_URL or "UNSET"
    print(f"[*] Booting MISP advanced fetcher against {v_url}...")
    
    start_ips, countries = load_dbip_memory()
    
    try:
        data = collect_from_misp(start_ips, countries)
    except Exception as e:
        raise SystemExit(f"[ERR] Failed to collect from MISP: {e}")
        
    print("[*] Rebuilding Databases...")
    init_dbs_full_reset()
        
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    upsert_ips(data["ips"], data["cidrs"], "MISP", stamp)
    upsert_domains(data["domains"], "MISP", stamp)
    upsert_urls(data["urls"], "MISP", stamp)
    upsert_hashes(data["md5"], "md5", "MISP", stamp)
    upsert_hashes(data["sha1"], "sha1", "MISP", stamp)
    upsert_hashes(data["sha256"], "sha256", "MISP", stamp)

    elapsed = int(time.time() - start)
    print(f"[DONE] attr={data['total']} ip={len(data['ips'])} cidr={len(data['cidrs'])} "
          f"dom={len(data['domains'])} url={len(data['urls'])} md5={len(data['md5'])} "
          f"sha1={len(data['sha1'])} sha256={len(data['sha256'])} in {elapsed}s")

if __name__ == "__main__":
    main()
