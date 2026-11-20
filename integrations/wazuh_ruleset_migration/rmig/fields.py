"""4.x fields and the WCS field list.

The static table comes from the official migration guide
(``wazuh@main:docs/guide/migration/rules-4x-to-5x.md:269-330`` and
``:1201-1238``). A destination of ``None`` means the guide gives no fixed
destination ("context-dependent" or "no direct equivalent"): the field goes to
``decisions.json`` like a dynamic one.

``rmig/data/wcs-fields.csv`` is a copy of
``wazuh-indexer-plugins@5.0.0:wcs/stateless/events/main/docs/fields.csv`` with a
provenance header (lines starting with ``#``).
"""

import csv
import io
import os

from .stock import DATA_DIR

WCS_FIELDS_PATH = os.path.join(DATA_DIR, "wcs-fields.csv")

# Rule elements and decoder <order> words with a fixed WCS destination.
STATIC_TO_WCS = {
    "srcip": "source.ip",
    "dstip": "destination.ip",
    "srcport": "source.port",
    "dstport": "destination.port",
    "srcuser": "user.name",
    "user": "user.name",
    "dstuser": "user.target.name",
    "protocol": "network.protocol",
    "action": "event.action",
    "status": "event.outcome",
    "id": "event.code",
    "url": "url.original",
    "system_name": "host.name",
    "program_name": "process.name",
    "hostname": "observer.hostname",
    "location": "wazuh.protocol.location",
    "srcgeoip": "source.geo.country_iso_code",
    "dstgeoip": "destination.geo.country_iso_code",
    "data": None,
    "extra_data": None,
}

# Rule elements that are conditions on a field (the others are on the text).
RULE_FIELD_ELEMENTS = tuple(k for k in STATIC_TO_WCS)

CATEGORIES = (
    "access-management", "applications", "cloud-services", "network-activity",
    "security", "system-activity", "other", "unclassified",
)

# Default category of a generated integration from the 4.x decoder <type>.
# Documented default (category_source: "default"); the user can change it.
TYPE_TO_CATEGORY = {
    "firewall": "network-activity",
    "squid": "network-activity",
    "ids": "security",
    "web-log": "applications",
    "windows": "system-activity",
    "host-information": "system-activity",
    "syslog": "other",
    "ossec": "other",
}


def static_destination(name):
    """(is_static, wcs or None)."""
    if name in STATIC_TO_WCS:
        return True, STATIC_TO_WCS[name]
    return False, None


class WcsFields:
    def __init__(self, path=None):
        path = path or WCS_FIELDS_PATH
        with open(path, "r", encoding="utf-8") as fh:
            lines = [ln for ln in fh.read().split("\n") if not ln.startswith("#")]
        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        self.types = {}
        for row in reader:
            name = (row.get("Field") or "").strip()
            if name:
                self.types[name] = (row.get("Type") or "").strip()

    def exists(self, name):
        return name in self.types

    def type_of(self, name):
        return self.types.get(name)


_WCS = {}


def wcs_fields(path=None):
    key = path or WCS_FIELDS_PATH
    if key not in _WCS:
        _WCS[key] = WcsFields(path)
    return _WCS[key]
