"""Pack profile: backend settings that are not part of the Sigma content.

The Sigma rules say *what* to correlate (selection, group-by, timespan,
threshold). The profile says *how this deployment runs it*: indices, schedule,
allowed lateness, notification actions. A local override file can change any
value without editing the shipped profile.
"""

import copy
import os
import re

import yaml

DUR_RE = re.compile(r"^([1-9][0-9]*)([smh])$")
DUR_UNITS = {"s": 1, "m": 60, "h": 3600}

DEFAULTS = {
    "indices": ["wazuh-events-v5-system-activity"],
    "timestamp_field": "event.start",
    "interval": "1m",
    "allowed_lateness": "2m",
    "composite_size": 500,
    "max_events_per_group": 100000,
    "event_identity_field": None,
    "enabled": True,
    "actions": [],
    "extra_filters": [],
    "context_fields": [],
}
ALLOWED_KEYS = set(DEFAULTS)


class ConfigError(ValueError):
    pass


def parse_duration(value, key):
    m = DUR_RE.match(str(value).strip())
    if not m:
        raise ConfigError("%s: %r is not <positive int><s|m|h>" % (key, value))
    return int(m.group(1)) * DUR_UNITS[m.group(2)]


def _merge(base, override):
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        out[k] = copy.deepcopy(v)
    return out


def load_profile(path, override_path=None):
    with open(path, "r", encoding="utf-8") as fh:
        prof = yaml.safe_load(fh) or {}
    if override_path:
        with open(override_path, "r", encoding="utf-8") as fh:
            ov = yaml.safe_load(fh) or {}
        prof["defaults"] = _merge(prof.get("defaults") or {}, ov.get("defaults") or {})
        corr = dict(prof.get("correlations") or {})
        for name, vals in (ov.get("correlations") or {}).items():
            corr[name] = _merge(corr.get(name) or {}, vals)
        prof["correlations"] = corr
    for key in ("pack", "version"):
        if not prof.get(key):
            raise ConfigError("profile: missing %r" % key)
    return prof


def settings_for(profile, corr_name):
    """Effective settings for one correlation (defaults <- profile defaults <- per-correlation)."""
    pdef = profile.get("defaults") or {}
    pc = (profile.get("correlations") or {}).get(corr_name) or {}
    for src, label in ((pdef, "defaults"), (pc, corr_name)):
        unknown = set(src) - ALLOWED_KEYS
        if unknown:
            raise ConfigError("profile %s: unknown key(s) %s" % (label, ", ".join(sorted(unknown))))
    s = _merge(_merge(DEFAULTS, pdef), pc)
    s["interval_s"] = parse_duration(s["interval"], corr_name + ".interval")
    s["allowed_lateness_s"] = parse_duration(s["allowed_lateness"], corr_name + ".allowed_lateness") \
        if str(s["allowed_lateness"]) not in ("0", "0s") else 0
    if s["interval_s"] < 60:
        raise ConfigError("%s: interval must be at least 1m (Alerting minimum)" % corr_name)
    if not s["indices"] or not isinstance(s["indices"], list):
        raise ConfigError("%s: indices must be a non-empty list" % corr_name)
    for a in s["actions"]:
        if not isinstance(a, dict) or not a.get("name") or not a.get("channel_id"):
            raise ConfigError("%s: each action needs name and channel_id" % corr_name)
    return s


def default_state_dir():
    base = os.environ.get("WCP_STATE_DIR")
    if base:
        return base
    return os.path.join(os.path.expanduser("~"), ".config", "wazuh_correlation_pack", "state")
