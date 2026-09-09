#!/var/ossec/framework/python/bin/python3
"""Microsoft 365 tenant / license inventory collector for Wazuh.

Emits newline-delimited JSON to a log file that a Wazuh agent tails with
<log_format>json</log_format>. Multi-tenant: one host, N tenants.

Graph endpoints (all v1.0, application permissions):
  /organization                     tenant name and domain
  /users?$count=true[&$filter=...]  user and licence counts
  /subscribedSkus                   licence pools per SKU
  /directory/subscriptions          renewal dates

Required permissions: Organization.Read.All, User.Read.All.

Event types: license (per SKU per tenant), sku_removed, tenant_summary,
collection_summary (per run, cross-tenant), error (per failed tenant).

Exits non-zero if any tenant failed, so the scheduler sees it even when the log
pipeline is broken.
"""

import argparse
import fcntl
import inspect
import json
import logging
import os
import re
import sys
from datetime import datetime, timedelta, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

INTEGRATION_NAME = "m365_inventory"
COLLECTOR_VERSION = "1.5"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
LOGIN_BASE = "https://login.microsoftonline.com"

# Everything lives under /var/ossec, in the directories Wazuh already uses for
# each purpose: the wodle keeps its own files beside the script, as the aws wodle
# does with its state database, logs go in logs/ and the lock in var/run/.
WODLE_DIR = "/var/ossec/wodles/m365_inventory"
DEFAULT_CONFIG = WODLE_DIR + "/config.json"
DEFAULT_LOG_FILE = "/var/ossec/logs/m365_inventory.log"
DEFAULT_LOCK_FILE = "/var/ossec/var/run/m365_inventory.lock"
# Beside the script. RPM and DEB only manage files they own, so this directory is
# not touched by a Wazuh upgrade; losing it costs one baseline re-flush anyway.
DEFAULT_STATE_FILE = WODLE_DIR + "/state.json"
STATE_VERSION = 1

# Per-SKU fields whose change is worth reporting. days_to_next_lifecycle is
# deliberately absent: it decrements daily, which would mark every dated SKU
# changed every day. expiry_bucket carries the same signal as a transition.
TRACKED_SKU_FIELDS = (
    "usable_units", "assigned_units", "capability_status", "expiry_bucket",
    "next_lifecycle_date", "license_class", "pool_exhausted", "overassigned",
    "service_plans_degraded", "subscription_count", "is_trial",
)

TRACKED_TENANT_FIELDS = (
    "total_users", "member_users", "guest_users", "licensed_users",
    "disabled_licensed_users", "sku_count", "total_usable_units",
    "total_assigned_units",
)

# HTTP timeouts: (connect, read). Graph can be slow on large tenants.
TIMEOUT = (10, 60)

# Subscription states that should not contribute a renewal date.
DEAD_SUBSCRIPTION_STATES = {"Deleted"}

# Free / self-service SKUs carry nominal pools (often 10,000 or 1,000,000 seats)
# granted at no cost. Including them in tenant totals produces meaningless figures.
DEFAULT_FREE_SKUS = [
    "FLOW_FREE", "POWER_BI_STANDARD", "POWERAPPS_DEV", "POWERAPPS_VIRAL",
    "MICROSOFT_BUSINESS_CENTER", "TEAMS_EXPLORATORY", "STREAM",
    "WINDOWS_STORE", "MCOMEETADV_FREE", "RMSBASIC",
]
DEFAULT_NOMINAL_UNIT_THRESHOLD = 10000
DEFAULT_MIN_POOL_FOR_EXHAUSTION = 5
DEFAULT_THRESHOLDS = {"critical_days": 30, "warning_days": 90}

log = logging.getLogger("m365_inventory")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def load_config(path):
    """Load config from a root-owned 0600 JSON file. Secrets never live in code."""
    if not os.path.exists(path):
        raise SystemExit(f"Config file not found: {path}")

    st = os.stat(path)
    if st.st_mode & 0o077:
        log.warning("Config %s is group/world accessible (mode %o); chmod 600 it.",
                    path, st.st_mode & 0o777)

    with open(path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)

    tenants = cfg.get("tenants") or []
    if not tenants:
        raise SystemExit("Config contains no tenants.")

    for i, tenant in enumerate(tenants):
        for key in ("name", "tenant_id", "client_id", "client_secret"):
            if not tenant.get(key):
                raise SystemExit(f"tenants[{i}] is missing required key '{key}'.")

    cfg.setdefault("log_file", DEFAULT_LOG_FILE)
    cfg.setdefault("lock_file", DEFAULT_LOCK_FILE)
    # Days-to-renewal thresholds used to bucket each SKU for the dashboard.
    cfg.setdefault("thresholds", dict(DEFAULT_THRESHOLDS))
    cfg.setdefault("free_sku_part_numbers", list(DEFAULT_FREE_SKUS))
    cfg.setdefault("nominal_unit_threshold", DEFAULT_NOMINAL_UNIT_THRESHOLD)
    cfg.setdefault("min_pool_size_for_exhaustion", DEFAULT_MIN_POOL_FOR_EXHAUSTION)
    # Optional per-seat monthly cost keyed by SKU part number. Purely local -- Graph
    # exposes no pricing. Enables "you are paying for N unassigned seats" reporting.
    cfg.setdefault("sku_costs", {})
    cfg.setdefault("currency", "EUR")
    # Days before client-secret expiry to start warning.
    cfg.setdefault("secret_expiry_warning_days", 30)
    # Optional {"ENTERPRISEPACK": "Office 365 E3"} display-name overrides.
    cfg.setdefault("sku_display_names", {})
    cfg.setdefault("state_file", DEFAULT_STATE_FILE)

    cfg["thresholds"] = {
        "critical_days": _as_number(cfg["thresholds"].get("critical_days"), int,
                                    DEFAULT_THRESHOLDS["critical_days"],
                                    "thresholds.critical_days"),
        "warning_days": _as_number(cfg["thresholds"].get("warning_days"), int,
                                   DEFAULT_THRESHOLDS["warning_days"],
                                   "thresholds.warning_days"),
    }
    for key, default in (("nominal_unit_threshold", DEFAULT_NOMINAL_UNIT_THRESHOLD),
                         ("min_pool_size_for_exhaustion", DEFAULT_MIN_POOL_FOR_EXHAUSTION),
                         ("secret_expiry_warning_days", 30)):
        cfg[key] = _as_number(cfg.get(key), int, default, key)

    # A bad price drops that SKU's cost fields rather than the tenant.
    costs = {}
    for part_number, value in (cfg.get("sku_costs") or {}).items():
        price = _as_number(value, float, None, f"sku_costs.{part_number}")
        if price is not None and price >= 0:
            costs[part_number] = price
        elif price is not None:
            log.warning("sku_costs.%s is negative (%s); ignoring it.", part_number, value)
    cfg["sku_costs"] = costs

    return cfg


def _as_number(value, kind, default, label):
    """Coerce a config value to int/float, else `default` with a warning.

    Config is hand-edited JSON, so a number written as a string is routine.
    Coercing here stops it failing far away from the cause.
    """
    if value is None:
        return default
    if isinstance(value, bool):   # bool is an int subclass; never a valid threshold
        log.warning("%s is a boolean (%r); using %r.", label, value, default)
        return default
    try:
        return kind(value)
    except (TypeError, ValueError):
        log.warning("%s is not a number (%r); using %r.", label, value, default)
        return default


def redact(text, secrets):
    """Strip any client secret that may have leaked into an exception string."""
    out = str(text)
    for secret in secrets:
        if secret and secret in out:
            out = out.replace(secret, "***REDACTED***")
    return out


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------

def build_session():
    """Session with backoff on 429/5xx, honouring Retry-After.

    urllib3 renamed method_whitelist to allowed_methods in 1.26 and RHEL-family
    distros still ship 1.24/1.25, so the kwargs are built from the actual Retry
    signature.
    """
    retry_kwargs = {
        "total": 5,
        "backoff_factor": 2,
        "status_forcelist": (429, 500, 502, 503, 504),
    }

    params = inspect.signature(Retry.__init__).parameters
    methods = frozenset(["GET", "POST"])
    if "allowed_methods" in params:
        retry_kwargs["allowed_methods"] = methods
    elif "method_whitelist" in params:
        retry_kwargs["method_whitelist"] = methods

    for optional in ("respect_retry_after_header", "raise_on_status"):
        if optional in params:
            retry_kwargs[optional] = True if optional == "respect_retry_after_header" else False

    retry = Retry(**retry_kwargs)
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=4)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": "wazuh-m365-inventory/1.1"})
    return session


def get_token(session, tenant):
    url = f"{LOGIN_BASE}/{tenant['tenant_id']}/oauth2/v2.0/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": tenant["client_id"],
        "client_secret": tenant["client_secret"],
        "scope": "https://graph.microsoft.com/.default",
    }
    resp = session.post(url, data=payload, timeout=TIMEOUT)
    resp.raise_for_status()
    token = resp.json().get("access_token")
    if not token:
        raise RuntimeError("Token endpoint returned no access_token.")
    return token


def graph_get(session, token, path, advanced=False):
    """Single Graph GET. `advanced` adds the ConsistencyLevel header required
    by $count and by the ne / assignedLicenses filters."""
    headers = {"Authorization": f"Bearer {token}"}
    if advanced:
        headers["ConsistencyLevel"] = "eventual"
    url = path if path.startswith("http") else f"{GRAPH_BASE}{path}"
    resp = session.get(url, headers=headers, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def graph_get_all(session, token, path, advanced=False):
    """Follow @odata.nextLink and return the concatenated value arrays."""
    items = []
    url = path
    pages = 0
    while url:
        data = graph_get(session, token, url, advanced=advanced)
        items.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        pages += 1
        if pages > 200:  # runaway pagination guard
            raise RuntimeError(f"Pagination exceeded 200 pages for {path}")
    return items


# ---------------------------------------------------------------------------
# Graph collection
# ---------------------------------------------------------------------------

def get_organization(session, token, tenant):
    """Resolve the tenant's own identity from Graph.

    Graph attaches no tenant context to user or SKU objects, so the name has to be
    fetched separately and stitched onto each record. Also catches a config/tenant
    mismatch, which is otherwise invisible.
    """
    data = graph_get(session, token, "/organization")
    orgs = data.get("value") or []
    if not orgs:
        log.warning("[%s] /organization returned no objects.", tenant["name"])
        return {}

    org = orgs[0]
    domains = org.get("verifiedDomains") or []
    default_domain = next(
        (d.get("name") for d in domains if d.get("isDefault")),
        next((d.get("name") for d in domains), None),
    )

    graph_tenant_id = org.get("id")
    mismatch = bool(graph_tenant_id) and graph_tenant_id.lower() != tenant["tenant_id"].lower()
    if mismatch:
        log.warning("[%s] configured tenant_id %s but Graph reports %s -- "
                    "check the config entry.",
                    tenant["name"], tenant["tenant_id"], graph_tenant_id)

    return {
        "tenant_display_name": org.get("displayName"),
        "tenant_default_domain": default_domain,
        "tenant_verified_domain_count": len(domains),
        "tenant_type": org.get("tenantType"),
        "tenant_country": org.get("countryLetterCode") or org.get("country"),
        "tenant_created": (org.get("createdDateTime") or "").split("T")[0] or None,
        "tenant_graph_id": graph_tenant_id,
        "tenant_id_mismatch": mismatch,
    }


def count_users(session, token, odata_filter=None):
    """Return @odata.count without downloading the user objects.

    $top=1 and $select=id keep the payload to one stub record.
    ConsistencyLevel: eventual is mandatory for $count.
    """
    query = "/users?$count=true&$top=1&$select=id"
    if odata_filter:
        query += f"&$filter={requests.utils.quote(odata_filter, safe='/()= ,')}"
    data = graph_get(session, token, query, advanced=True)
    return int(data.get("@odata.count", 0))


def get_user_counts(session, token, tenant):
    counts = {
        "total_users": count_users(session, token),
        "member_users": count_users(session, token, "userType eq 'Member'"),
        "guest_users": count_users(session, token, "userType eq 'Guest'"),
        # Distinct users holding at least one license. NOT the same as the sum
        # of consumedUnits across SKUs, since a user can hold several SKUs.
        "licensed_users": count_users(session, token, "assignedLicenses/$count ne 0"),
    }

    # The most fragile query here: it combines a standard filter with an advanced
    # one, so it degrades to an absent field rather than failing the tenant.
    try:
        counts["disabled_licensed_users"] = count_users(
            session, token, "accountEnabled eq false and assignedLicenses/$count ne 0")
    except (requests.HTTPError, requests.RequestException, ValueError) as exc:
        log.warning("[%s] disabled-licensed-user count unavailable: %s",
                    tenant["name"], exc)

    return counts


def get_subscribed_skus(session, token):
    return graph_get_all(session, token, "/subscribedSkus")


def get_subscriptions(session, token):
    """Commercial subscriptions, indexed for joining against subscribedSkus.

    Returns (by_id, by_commerce_id, by_sku_id).
    """
    subs = graph_get_all(session, token, "/directory/subscriptions")
    by_id, by_commerce_id, by_sku_id = {}, {}, {}
    for sub in subs:
        if sub.get("id"):
            by_id[sub["id"]] = sub
        if sub.get("commerceSubscriptionId"):
            by_commerce_id[sub["commerceSubscriptionId"]] = sub
        if sub.get("skuId"):
            by_sku_id.setdefault(sub["skuId"], []).append(sub)
    return by_id, by_commerce_id, by_sku_id


def match_subscriptions(sku, by_id, by_commerce_id, by_sku_id):
    """Resolve the subscriptions backing a SKU.

    subscriptionIds is the explicit link, but Microsoft does not document whether
    those GUIDs are companySubscription.id or .commerceSubscriptionId, so both
    indexes are tried. skuId is a last resort: it is not unique.
    """
    matched, seen = [], set()

    for sub_id in sku.get("subscriptionIds") or []:
        sub = by_id.get(sub_id) or by_commerce_id.get(sub_id)
        if sub and id(sub) not in seen:
            seen.add(id(sub))
            matched.append(sub)

    if not matched:
        for sub in by_sku_id.get(sku.get("skuId"), []):
            if id(sub) not in seen:
                seen.add(id(sub))
                matched.append(sub)

    return matched


_GRAPH_TS = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?"
    r"(Z|[+-]\d{2}:?\d{2})?$"
)


def parse_graph_datetime(value):
    """Parse a Graph timestamp into an aware UTC datetime.

    Not fromisoformat(): before 3.11 it rejects a trailing Z and accepts only 3 or 6
    fractional digits, while Graph returns 7. On a stock enterprise interpreter that
    would silently blank every renewal date.
    """
    if not value:
        return None

    match = _GRAPH_TS.match(str(value).strip())
    if not match:
        log.warning("Unparseable Graph datetime: %r", value)
        return None

    date_part, time_part, fraction, offset = match.groups()
    try:
        dt = datetime.strptime(f"{date_part}T{time_part}", "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        log.warning("Unparseable Graph datetime: %r", value)
        return None

    if fraction:
        dt = dt.replace(microsecond=int(fraction[:6].ljust(6, "0")))

    if offset in (None, "Z", "z"):
        return dt.replace(tzinfo=timezone.utc)

    sign = 1 if offset[0] == "+" else -1
    body = offset[1:].replace(":", "")
    delta = timedelta(hours=int(body[:2]), minutes=int(body[2:4]))
    # Normalise to UTC so date arithmetic against `now` is always consistent.
    return (dt - sign * delta).replace(tzinfo=timezone.utc)


def bucket_expiry(days, thresholds):
    if days is None:
        return "unknown"
    if days < 0:
        return "expired"
    if days <= thresholds["critical_days"]:
        return "critical"
    if days <= thresholds["warning_days"]:
        return "warning"
    return "ok"


def tenant_identity(tenant, org):
    """Tenant context stamped onto every event.

    tenant_name stays the config label, because the dashboards filter on it and it
    must survive the customer renaming the tenant in Microsoft.
    """
    block = {
        "tenant_name": tenant["name"],
        "tenant_id": tenant["tenant_id"],
    }
    block.update(org or {})
    return block


def prune_nulls(value):
    """Drop keys whose value is None, blank, or an empty list.

    analysisd stringifies decoded values, so a JSON null reaches the indexer as the
    string "null". A long or date mapping rejects that, and a rejected field
    discards the WHOLE alert, so a SKU with no renewal date would vanish from the
    index. Omitting the key loses nothing: expiry_bucket "unknown" already says no
    date was available. Empty strings and empty arrays go the same way.
    """
    def empty(v):
        if v is None:
            return True
        if isinstance(v, str):
            return not v.strip()
        if isinstance(v, (list, dict)):
            return len(v) == 0
        return False            # 0 and False are values, not absences

    # Post-order: a list whose only members were empty is itself empty.
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if empty(item):
                continue
            pruned = prune_nulls(item)
            if not empty(pruned):
                out[key] = pruned
        return out
    if isinstance(value, list):
        out = []
        for item in value:
            if empty(item):
                continue
            pruned = prune_nulls(item)
            if not empty(pruned):
                out.append(pruned)
        return out
    return value


def iso_millis(dt):
    """ISO-8601 at millisecond precision.

    Microsecond output has a history of date-parser edge cases.
    """
    return dt.isoformat(timespec="milliseconds")


def classify_sku(part_number, usable_units, has_lifecycle_date, cfg):
    """Separate purchased SKUs from free ones, as (class, source).

    Free SKUs carry nominal pools (10,000 seats for Power Automate Free, 1,000,000
    for Fabric Free) that swamp any tenant total: "1,030,019 available licences"
    for a 309-user tenant is confidently wrong.
    """
    if part_number in set(cfg.get("free_sku_part_numbers", DEFAULT_FREE_SKUS)):
        return "free", "configured"

    threshold = cfg.get("nominal_unit_threshold", DEFAULT_NOMINAL_UNIT_THRESHOLD)
    if usable_units >= threshold and not has_lifecycle_date:
        return "free", "heuristic"

    return "paid", "default"


def build_license_event(sku, subs, tenant, org, user_counts, now, cfg):
    """One dashboard row: a SKU in a tenant, with pool maths and renewal state."""
    prepaid = sku.get("prepaidUnits") or {}
    enabled = int(prepaid.get("enabled") or 0)
    warning_units = int(prepaid.get("warning") or 0)
    suspended = int(prepaid.get("suspended") or 0)
    locked_out = int(prepaid.get("lockedOut") or 0)
    consumed = int(sku.get("consumedUnits") or 0)

    # "warning" units are past term but still assignable during grace.
    usable = enabled + warning_units
    available = max(0, usable - consumed)

    # A Deleted subscription would pin a stale past date onto an active SKU.
    live = [s for s in subs if s.get("status") not in DEAD_SUBSCRIPTION_STATES]
    dates = sorted(
        d for d in (parse_graph_datetime(s.get("nextLifecycleDateTime")) for s in live)
        if d is not None
    )

    next_date = dates[0] if dates else None
    days_to_next = (next_date - now).days if next_date else None
    part_number = sku.get("skuPartNumber") or "Unknown"

    license_class, class_source = classify_sku(
        part_number, usable, bool(next_date), cfg)

    # A SKU can be Enabled while plans inside it are not provisioned, which users
    # experience as one broken app.
    plans = sku.get("servicePlans") or []
    plans_not_success = sorted({
        p.get("servicePlanName") for p in plans
        if p.get("provisioningStatus") not in (None, "Success")
        and p.get("servicePlanName")
    })

    # Optional local cost model. Graph exposes no pricing, so this is config-driven.
    unit_cost = (cfg.get("sku_costs") or {}).get(part_number)

    # Only flag exhaustion for purchased pools big enough for it to mean anything.
    pool_exhausted = (
        license_class == "paid"
        and available == 0
        and usable >= cfg.get("min_pool_size_for_exhaustion", DEFAULT_MIN_POOL_FOR_EXHAUSTION)
    )

    event = {
        "integration": INTEGRATION_NAME,
        "m365": {
            "event_type": "license",
            "collected_at": iso_millis(now),

            "sku_part_number": part_number,
            "sku_display_name": cfg["sku_display_names"].get(part_number, part_number),
            "sku_id": sku.get("skuId"),
            "applies_to": sku.get("appliesTo"),
            "capability_status": sku.get("capabilityStatus") or "Unknown",
            "license_class": license_class,
            "license_class_source": class_source,
            "counted_in_totals": license_class == "paid",
            "pool_exhausted": pool_exhausted,

            "prepaid_enabled_units": enabled,
            "prepaid_warning_units": warning_units,
            "prepaid_suspended_units": suspended,
            "prepaid_locked_out_units": locked_out,
            "usable_units": usable,
            "assigned_units": consumed,
            "available_units": available,
            "utilization_pct": round(consumed / usable * 100, 1) if usable else 0.0,
            "overassigned": consumed > usable,

            # Repeated on every row so one table can show tenant totals.
            "total_users": user_counts["total_users"],
            "member_users": user_counts["member_users"],
            "guest_users": user_counts["guest_users"],
            "licensed_users": user_counts["licensed_users"],
            "disabled_licensed_users": user_counts.get("disabled_licensed_users"),

            "next_lifecycle_date": next_date.date().isoformat() if next_date else None,
            "next_lifecycle_datetime": iso_millis(next_date) if next_date else None,
            "days_to_next_lifecycle": days_to_next,
            "expiry_bucket": bucket_expiry(days_to_next, cfg["thresholds"]),
            "subscription_count": len(live),
            "subscription_statuses": sorted({s.get("status", "Unknown") for s in live}),
            "is_trial": any(s.get("isTrial") for s in live),
            "all_lifecycle_dates": [d.date().isoformat() for d in dates],
            "date_source": ("subscription" if next_date else "unavailable"),

            "service_plan_count": len(plans),
            "service_plans_not_provisioned": plans_not_success,
            "service_plans_degraded": bool(plans_not_success),

            # You pay for the pool, not for what is assigned.
            "unit_cost": unit_cost,
            "currency": cfg.get("currency") if unit_cost is not None else None,
            "committed_monthly_cost": (
                round(usable * unit_cost, 2) if unit_cost is not None else None),
            "wasted_monthly_cost": (
                round(available * unit_cost, 2) if unit_cost is not None else None),
        },
    }
    event["m365"].update(tenant_identity(tenant, org))
    return event


def _cost_total(rows, field):
    """Sum a cost field, or None when no SKU is priced.

    None rather than 0.0: a zero would read as "this estate is free".
    """
    values = [r[field] for r in rows if r.get(field) is not None]
    return round(sum(values), 2) if values else None


def secret_expiry_days(tenant, now):
    """Days until the client secret expires, from config not Graph.

    Reading it from /applications would need Application.Read.All just to learn a
    date the operator already has. An expired secret silently kills collection.
    """
    raw = tenant.get("client_secret_expires")
    if not raw:
        return None
    expiry = parse_graph_datetime(raw if "T" in str(raw) else f"{raw}T00:00:00Z")
    if expiry is None:
        log.warning("[%s] unparseable client_secret_expires: %r", tenant["name"], raw)
        return None
    return (expiry - now).days


def secret_expiry_bucket(days, cfg):
    """Bucket the client-secret expiry, mirroring bucket_expiry().

    A bucket, not a raw number, because os_regex has no grouping so a range like
    "negative or 0-30" cannot be written as a rule regex. It also keeps the
    threshold in config instead of hardcoded in the ruleset.
    """
    if days is None:
        return None
    if days < 0:
        return "expired"
    if days <= cfg.get("secret_expiry_warning_days", 30):
        return "critical"
    return "ok"


def build_summary_event(tenant, org, user_counts, sku_events, now, cfg):
    """Heartbeat: proves the tenant was polled successfully.

    Headline totals cover purchased SKUs only; the *_all variants include free ones
    for reconciliation.
    """
    paid = [e["m365"] for e in sku_events if e["m365"]["counted_in_totals"]]
    every = [e["m365"] for e in sku_events]
    secret_days = secret_expiry_days(tenant, now)

    event = {
        "integration": INTEGRATION_NAME,
        "m365": {
            "event_type": "tenant_summary",
            "collected_at": iso_millis(now),
            "collection_status": "success",
            "total_users": user_counts["total_users"],
            "member_users": user_counts["member_users"],
            "guest_users": user_counts["guest_users"],
            "licensed_users": user_counts["licensed_users"],
            "disabled_licensed_users": user_counts.get("disabled_licensed_users"),

            "sku_count": len(paid),
            "free_sku_count": len(every) - len(paid),
            "sku_count_all": len(every),

            "total_usable_units": sum(d["usable_units"] for d in paid),
            "total_assigned_units": sum(d["assigned_units"] for d in paid),
            "total_available_units": sum(d["available_units"] for d in paid),
            "total_usable_units_all": sum(d["usable_units"] for d in every),
            "total_assigned_units_all": sum(d["assigned_units"] for d in every),

            "overall_utilization_pct": (
                round(sum(d["assigned_units"] for d in paid)
                      / sum(d["usable_units"] for d in paid) * 100, 1)
                if sum(d["usable_units"] for d in paid) else 0.0),

            "skus_expiring_critical": sum(
                1 for d in paid if d["expiry_bucket"] == "critical"),
            "skus_expiring_warning": sum(
                1 for d in paid if d["expiry_bucket"] == "warning"),
            "skus_expired": sum(1 for d in paid if d["expiry_bucket"] == "expired"),
            "skus_pool_exhausted": sum(1 for d in paid if d["pool_exhausted"]),
            "skus_overassigned": sum(1 for d in paid if d["overassigned"]),
            "skus_service_plans_degraded": sum(
                1 for d in paid if d["service_plans_degraded"]),

            "committed_monthly_cost": _cost_total(paid, "committed_monthly_cost"),
            "wasted_monthly_cost": _cost_total(paid, "wasted_monthly_cost"),
            "currency": cfg.get("currency") if _cost_total(paid, "unit_cost") else None,

            "days_to_secret_expiry": secret_days,
            "secret_expiry_bucket": secret_expiry_bucket(secret_days, cfg),
            "collector_version": COLLECTOR_VERSION,
        },
    }
    event["m365"].update(tenant_identity(tenant, org))
    return event


def build_collection_summary(summaries, failed_tenants, now, duration_ms, cfg):
    """One event per RUN, aggregating every tenant.

    Dashboard aggregations cannot express "sum of the latest value per tenant": a
    bucket-less Top Hit returns one arbitrary tenant, right with one tenant and
    wrong from the second onward. Precomputing it here fixes that.
    """
    def total(field):
        """Sum a field, or None when no tenant reported it.

        None rather than 0, because a rolled-up 0 would read as a measurement ("no
        licences on disabled accounts") rather than "not collected".
        """
        values = [s[field] for s in summaries if s.get(field) is not None]
        return sum(values) if values else None

    def cost_total(field):
        values = [s[field] for s in summaries if s.get(field) is not None]
        return round(sum(values), 2) if values else None

    secret_days = [s["days_to_secret_expiry"] for s in summaries
                   if s.get("days_to_secret_expiry") is not None]
    usable = total("total_usable_units")
    assigned = total("total_assigned_units")

    return {
        "integration": INTEGRATION_NAME,
        "m365": {
            "event_type": "collection_summary",
            "collected_at": iso_millis(now),
            "collector_version": COLLECTOR_VERSION,
            "collection_duration_ms": duration_ms,

            "tenants_total": len(summaries) + len(failed_tenants),
            "tenants_succeeded": len(summaries),
            "tenants_failed": len(failed_tenants),
            "failed_tenant_names": sorted(failed_tenants),
            "collection_complete": not failed_tenants,

            "total_users": total("total_users"),
            "member_users": total("member_users"),
            "guest_users": total("guest_users"),
            "licensed_users": total("licensed_users"),
            "disabled_licensed_users": total("disabled_licensed_users"),

            "paid_sku_count": total("sku_count"),
            "free_sku_count": total("free_sku_count"),
            "total_usable_units": usable,
            "total_assigned_units": assigned,
            "total_available_units": total("total_available_units"),
            "overall_utilization_pct": (
                round(assigned / usable * 100, 1) if usable else None),

            "skus_expiring_critical": total("skus_expiring_critical"),
            "skus_expiring_warning": total("skus_expiring_warning"),
            "skus_expired": total("skus_expired"),
            "skus_pool_exhausted": total("skus_pool_exhausted"),
            "skus_overassigned": total("skus_overassigned"),
            "skus_service_plans_degraded": total("skus_service_plans_degraded"),

            "committed_monthly_cost": cost_total("committed_monthly_cost"),
            "wasted_monthly_cost": cost_total("wasted_monthly_cost"),
            "currency": cfg.get("currency") if cost_total("committed_monthly_cost") else None,

            "min_days_to_secret_expiry": min(secret_days) if secret_days else None,
        },
    }


def build_error_event(tenant, stage, message, now):
    return {
        "integration": INTEGRATION_NAME,
        "m365": {
            "event_type": "error",
            "collected_at": iso_millis(now),
            "tenant_name": tenant["name"],
            "tenant_id": tenant["tenant_id"],
            "collection_status": "failure",
            "stage": stage,
            "error_message": message[:1000],
        },
    }


# ---------------------------------------------------------------------------
# Run-to-run state: what changed since the previous poll
# ---------------------------------------------------------------------------

def load_state(path):
    """Previous run's snapshot, or empty if there is no usable one.

    Never raises: a missing or corrupt file degrades the run to a baseline rather
    than stopping collection.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        log.warning("State file %s unreadable (%s); treating this run as a baseline.",
                    path, exc)
        return {}

    if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
        log.warning("State file %s has unexpected version %r; treating this run as "
                    "a baseline.", path, (state or {}).get("version"))
        return {}
    return state.get("tenants") or {}


def save_state(path, tenants):
    """Write the state atomically, by rename or not at all.

    Called only after this run's events are written: re-reporting a change is
    harmless, losing one is not.
    """
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"version": STATE_VERSION, "tenants": tenants}, fh,
                      separators=(",", ":"))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except OSError as exc:
        # Non-fatal: the collection itself succeeded. The next run baselines again.
        log.warning("Could not write state file %s (%s); the next run will not be "
                    "able to report changes.", path, exc)


def snapshot_sku(data, fields=TRACKED_SKU_FIELDS):
    return {f: data.get(f) for f in fields}


def diff_fields(previous, current):
    """Field names whose value differs, ignoring keys absent from both."""
    return sorted(k for k in current if previous.get(k) != current.get(k))


def apply_sku_changes(sku_events, previous_skus, baseline):
    """Stamp each licence event with what changed since the previous run.

    state_changed is the gate the alerting rules hang off, which is what turns 144
    alerts a day per SKU into one per transition. A baseline run sets it true so
    currently-true conditions are reported once, but not first_seen, or every SKU
    would look newly purchased.
    """
    for event in sku_events:
        data = event["m365"]
        current = snapshot_sku(data)
        previous = previous_skus.get(data["sku_part_number"])

        if baseline or previous is None:
            data["state_changed"] = True
            data["baseline"] = True if baseline else None
            data["first_seen"] = True if not baseline else None
            # state_changed is true with no field list, and a newly appearing free SKU
            # matches no specific rule, so the gate rule needs text to show.
            data["changed_summary"] = ("baseline, no previous snapshot" if baseline
                                       else "first observation of this SKU")
            continue

        changed = diff_fields(previous, current)
        data["state_changed"] = bool(changed)
        data["changed_fields"] = changed or None
        data["changed_summary"] = ", ".join(changed) or None
        if "assigned_units" in changed:
            data["assigned_units_delta"] = (
                data["assigned_units"] - (previous.get("assigned_units") or 0))


def apply_tenant_changes(summary, previous_tenant, baseline):
    """The same gate at tenant level, since user and seat counts move
    independently of any single SKU.
    """
    current = {f: summary.get(f) for f in TRACKED_TENANT_FIELDS}
    if baseline or not previous_tenant:
        summary["state_changed"] = True
        summary["baseline"] = True if baseline else None
        return

    changed = diff_fields(previous_tenant, current)
    summary["state_changed"] = bool(changed)
    summary["changed_fields"] = changed or None
    summary["changed_summary"] = ", ".join(changed) or None
    for field in ("total_users", "licensed_users"):
        if field in changed:
            summary[f"{field}_delta"] = (
                (summary.get(field) or 0) - (previous_tenant.get(field) or 0))


def build_removal_events(tenant, org, previous_skus, seen_parts, now, cfg):
    """A SKU that was there last run and is not there now.

    subscribedSkus stops returning a cancelled SKU, so the row just stops being
    emitted. Absence is invisible on a latest-value dashboard, so it needs its own
    event.
    """
    events = []
    for part_number, previous in sorted(previous_skus.items()):
        if part_number in seen_parts:
            continue
        event = {
            "integration": INTEGRATION_NAME,
            "m365": {
                "event_type": "sku_removed",
                "collected_at": iso_millis(now),
                "sku_part_number": part_number,
                "sku_display_name": cfg["sku_display_names"].get(part_number, part_number),
                "state_changed": True,
                "last_usable_units": previous.get("usable_units"),
                "last_assigned_units": previous.get("assigned_units"),
                "last_expiry_bucket": previous.get("expiry_bucket"),
                "license_class": previous.get("license_class"),
            },
        }
        event["m365"].update(tenant_identity(tenant, org))
        events.append(event)
    return events


# ---------------------------------------------------------------------------
# Per-tenant orchestration
# ---------------------------------------------------------------------------

def collect_tenant(session, tenant, cfg, now, previous_state):
    """Collect one tenant. Returns (events, summary_or_None, new_state).

    new_state is None on failure, so a failed tenant keeps its previous snapshot and
    the next good run diffs against that rather than reporting everything as
    changed. Never raises: one broken tenant must not stop the others.
    """
    previous_skus = (previous_state or {}).get("skus") or {}
    previous_tenant = (previous_state or {}).get("tenant") or {}
    baseline = not previous_state
    secrets = [tenant["client_secret"]]
    stage = "init"
    try:
        stage = "authentication"
        token = get_token(session, tenant)

        stage = "organization"
        try:
            org = get_organization(session, token, tenant)
        except (requests.HTTPError, requests.RequestException) as exc:
            # Cosmetic only: never fail a tenant over its display name.
            log.warning("[%s] /organization unavailable (%s); falling back to the "
                        "configured label.", tenant["name"], redact(exc, secrets))
            org = {}

        stage = "user_counts"
        user_counts = get_user_counts(session, token, tenant)

        stage = "subscribed_skus"
        skus = get_subscribed_skus(session, token)

        stage = "directory_subscriptions"
        try:
            by_id, by_commerce, by_sku = get_subscriptions(session, token)
        except requests.HTTPError as exc:
            # A 403 here usually means the app lacks Organization.Read.All.
            # Degrade so licence counts still reach the dashboard.
            if exc.response is not None and exc.response.status_code in (401, 403):
                log.warning("[%s] No access to /directory/subscriptions (%s); "
                            "renewal dates will be unavailable.",
                            tenant["name"], exc.response.status_code)
                by_id, by_commerce, by_sku = {}, {}, {}
            else:
                raise

        stage = "build_events"
        sku_events = []
        for sku in skus:
            subs = match_subscriptions(sku, by_id, by_commerce, by_sku)
            sku_events.append(
                build_license_event(sku, subs, tenant, org, user_counts, now, cfg))

        stage = "change_detection"
        apply_sku_changes(sku_events, previous_skus, baseline)
        summary = build_summary_event(tenant, org, user_counts, sku_events, now, cfg)
        apply_tenant_changes(summary["m365"], previous_tenant, baseline)

        seen = {e["m365"]["sku_part_number"] for e in sku_events}
        removals = build_removal_events(tenant, org, previous_skus, seen, now, cfg)

        new_state = {
            "collected_at": iso_millis(now),
            "tenant": {f: summary["m365"].get(f) for f in TRACKED_TENANT_FIELDS},
            "skus": {e["m365"]["sku_part_number"]: snapshot_sku(e["m365"])
                     for e in sku_events},
        }

        events = [prune_nulls(e) for e in sku_events + removals + [summary]]
        changed = sum(1 for e in sku_events if e["m365"].get("state_changed"))
        log.info("[%s] (%s) %d SKUs, %d users, %d licensed users, %d changed, "
                 "%d removed%s",
                 tenant["name"], org.get("tenant_default_domain") or "domain unknown",
                 len(sku_events), user_counts["total_users"],
                 user_counts["licensed_users"], changed, len(removals),
                 " (baseline)" if baseline else "")
        return events, summary["m365"], new_state

    except Exception as exc:  # noqa: BLE001 - deliberate per-tenant isolation
        message = redact(exc, secrets)
        log.error("[%s] failed at stage '%s': %s", tenant["name"], stage, message)
        return [prune_nulls(build_error_event(tenant, stage, message, now))], None, None


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_events(path, events):
    """Append NDJSON and fsync, so a crash cannot leave a torn line for
    logcollector to read as invalid JSON."""
    if not events:
        return
    with open(path, "a", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event, separators=(",", ":")) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def acquire_lock(path):
    """Prevent overlapping runs; a slow tenant must not be polled twice at once."""
    fh = open(path, "w", encoding="utf-8")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        raise SystemExit("Another collector run holds the lock; exiting.")
    fh.write(str(os.getpid()))
    fh.flush()
    return fh


def main():
    # The log, the state file and the lock all land under /var/ossec, where Wazuh
    # keeps nothing world-readable. They carry tenant names and seat counts.
    os.umask(0o027)

    parser = argparse.ArgumentParser(description="M365 license inventory collector for Wazuh")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG)
    parser.add_argument("--log-file", help="Override log_file from config")
    parser.add_argument("--stdout", action="store_true",
                        help="Print events to stdout instead of writing the log file")
    parser.add_argument("--state-file", help="Override state_file from config")
    parser.add_argument("--no-state", action="store_true",
                        help="Do not read or write the state file. Every run is then a "
                             "baseline, so no change reporting. For ad-hoc testing.")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        stream=sys.stderr,
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    log.debug("python %s | requests %s | urllib3 %s",
              sys.version.split()[0], requests.__version__,
              getattr(__import__("urllib3"), "__version__", "unknown"))

    cfg = load_config(args.config)
    log_file = args.log_file or cfg["log_file"]
    state_file = args.state_file or cfg["state_file"]
    lock = None if args.stdout else acquire_lock(cfg["lock_file"])

    now = datetime.now(timezone.utc)
    session = build_session()
    failures = 0

    summaries, failed_names = [], []
    previous_state = {} if args.no_state else load_state(state_file)
    new_state = dict(previous_state)

    def emit(events):
        if args.stdout:
            for event in events:
                print(json.dumps(event, separators=(",", ":")))
        else:
            # Flush per tenant, so a later failure discards nothing.
            write_events(log_file, events)

    try:
        for tenant in cfg["tenants"]:
            events, summary, tenant_state = collect_tenant(
                session, tenant, cfg, now, previous_state.get(tenant["name"]))
            if summary is None:
                failures += 1
                failed_names.append(tenant["name"])
            else:
                summaries.append(summary)
                new_state[tenant["name"]] = tenant_state
            emit(events)

        # Run-level rollup goes last, so it is only written once every tenant has
        # been attempted and its counts are final.
        duration_ms = int((datetime.now(timezone.utc) - now).total_seconds() * 1000)
        emit([prune_nulls(build_collection_summary(
            summaries, failed_names, now, duration_ms, cfg))])

        # After emitting on purpose: a crash here re-reports changes rather than
        # losing them.
        if not args.no_state:
            save_state(state_file, new_state)
    finally:
        session.close()
        if lock:
            lock.close()

    if failures:
        log.error("%d of %d tenants failed.", failures, len(cfg["tenants"]))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
