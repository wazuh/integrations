"""Metadata of migrated content: local ids, the ownership mark,
levels, groups to ``tags``/``compliance``, ``<mitre>`` to ``mitre`` and
titles with ``$(field)`` placeholders."""

import hashlib
import html
import json
import os
import re
import uuid

from ..stock import DATA_DIR

MARKER_AUTHOR = "wazuh-ruleset-migration"
REF_PREFIX = "wazuh4-migration:"
PREFIX = "wazuh4-"
# Fixed namespace of the local ids: uuid5(NAMESPACE_URL, "https://wazuh.com/ruleset-migration/4x").
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://wazuh.com/ruleset-migration/4x")

MITRE_PATH = os.path.join(DATA_DIR, "mitre.json")


def local_id(kind, key):
    """``uuid5(fixed namespace, "<kind>:<source key>")``."""
    return str(uuid.uuid5(NAMESPACE, "%s:%s" % (kind, key)))


def marker_references(lid, extra=()):
    refs = [REF_PREFIX + lid]
    for r in extra:
        if r not in refs:
            refs.append(r)
    return refs


def metadata(title, lid, description, references=(), date=None):
    meta = {
        "title": title,
        "author": MARKER_AUTHOR,
        "description": description,
        "documentation": "",
        "references": marker_references(lid, references),
    }
    if date:
        meta["date"] = date
    return meta


# -- levels (rules-4x-to-5x.md "Step 3") --------------------------------

def level_keyword(level):
    lvl = level or 0
    if lvl <= 3:
        return "informational"
    if lvl <= 6:
        return "low"
    if lvl <= 9:
        return "medium"
    if lvl <= 13:
        return "high"
    return "critical"


# -- groups (rules-4x-to-5x.md "Step 8", "Step 9") ---------------------------

COMPLIANCE_PREFIXES = (
    ("pci_dss_", "pci_dss"),
    ("gdpr_", "gdpr"),
    ("nist_800_53_", "nist_800_53"),
    ("nist_800_171_", "nist_800_171"),
    ("hipaa_", "hipaa"),
    ("tsc_", "tsc"),
    ("cmmc_", "cmmc"),
    ("iso_27001_", "iso_27001"),
    ("nis2_", "nis2"),
    ("fedramp_", "fedramp"),
)


_TAG_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]")


def group_tag(group):
    """The 5.x tag of a 4.x group: ``wazuh4.group.<name>``, entities decoded and every character outside
    ``[A-Za-z0-9_.-]`` made ``_``. Security Analytics refuses a detector whose rule tag holds a space, ``[``, ``]``,
    ``{``, ``}``, ``(`` or ``)`` (HTTP 500 "The query tag, wazuh4.group.MITRE ATT&amp;CK_sysmon, contains an invalid
    character", POST /_plugins/_security_analytics/detectors, 5.0.0 rc3)."""
    return "wazuh4.group.%s" % tag_part(group)


def tag_part(name):
    """A 4.x name as part of a 5.x tag (see :func:`group_tag`)."""
    return _TAG_UNSAFE.sub("_", html.unescape(name.strip()))


def groups_to_tags(groups):
    """(tags, compliance) from the 4.x group list. ``gpg13_`` has no 5.x
    framework and stays a tag, like every functional group."""
    tags, comp = [], {}
    for g in groups:
        g = g.strip()
        if not g:
            continue
        for prefix, key in COMPLIANCE_PREFIXES:
            if g.startswith(prefix) and len(g) > len(prefix):
                vals = comp.setdefault(key, [])
                ctl = g[len(prefix):]
                if ctl not in vals:
                    vals.append(ctl)
                break
        else:
            # Security Analytics reads a Sigma tag as <namespace>.<value>: a tag without a dot makes
            # POST /rules answer 500 "Index 1 out of bounds for length 1" (5.0.0-rc1).
            tag = group_tag(g)
            if tag not in tags:
                tags.append(tag)
    return tags, comp


# -- MITRE ---------------------------------------------------------------------

_MITRE = {}


def mitre_data(path=None):
    path = path or MITRE_PATH
    if path not in _MITRE:
        with open(path, "r", encoding="utf-8") as fh:
            _MITRE[path] = json.load(fh)
    return _MITRE[path]


def mitre_block(entries, data=None):
    """``mitre`` object from the parsed ``<mitre>`` entries (``id``,
    ``techniqueid``, ``tacticid``). Returns (block or None, notes)."""
    data = data or mitre_data()
    techniques = data["techniques"]
    tactics_by_short = data["tactics"]
    tactics_by_id = {v["id"]: v for v in tactics_by_short.values()}
    tech_ids, sub_ids, tac_ids, notes = [], [], [], []
    for e in entries:
        for key in ("id", "techniqueid"):
            for tid in e.get(key, []):
                tid = tid.strip().upper()
                info = techniques.get(tid)
                if info is None:
                    notes.append("MITRE technique %s is not in ATT&CK %s: left out" % (tid, data.get("attack_version")))
                    continue
                if info.get("revoked_by"):
                    notes.append("MITRE technique %s is revoked by %s in ATT&CK %s" % (tid, info["revoked_by"], data.get("attack_version")))
                if info.get("parent"):
                    if tid not in sub_ids:
                        sub_ids.append(tid)
                    parent = info["parent"]
                    if parent not in tech_ids:
                        tech_ids.append(parent)
                elif tid not in tech_ids:
                    tech_ids.append(tid)
                for short in info.get("tactics", []):
                    t = tactics_by_short.get(short)
                    if t and t["id"] not in tac_ids:
                        tac_ids.append(t["id"])
        for tid in e.get("tacticid", []):
            tid = tid.strip().upper()
            if tid in tactics_by_id:
                if tid not in tac_ids:
                    tac_ids.append(tid)
            else:
                notes.append("MITRE tactic %s is not in ATT&CK %s: left out" % (tid, data.get("attack_version")))
    if not (tech_ids or tac_ids):
        return None, notes
    block = {}
    if tac_ids:
        block["tactic"] = {"id": tac_ids, "name": [tactics_by_id[t]["name"] for t in tac_ids]}
    if tech_ids:
        block["technique"] = {"id": tech_ids, "name": [techniques[t]["name"] for t in tech_ids]}
    if sub_ids:
        block["subtechnique"] = {"id": sub_ids, "name": [
            "%s: %s" % (techniques[techniques[s]["parent"]]["name"], techniques[s]["name"]) for s in sub_ids]}
    return block, notes


# -- titles ---------------------------------------------------------------------

_PLACEHOLDER = re.compile(r"\$\(([^)\s]+)\)")


def title_from_description(description, resolve):
    """``$(field)`` -> ``{{ wcs }}``; ``resolve(field)`` gives the WCS name or
    None: then the value is not stored and the placeholder becomes the 4.x
    field name as text, ``<field>``, so the sentence keeps its words and no
    hole. Returns (title, unresolved fields)."""
    missing = []

    def sub(m):
        wcs = resolve(m.group(1))
        if wcs:
            return "{{ %s }}" % wcs
        missing.append(m.group(1))
        return "<%s>" % m.group(1)

    text = _PLACEHOLDER.sub(sub, description or "")
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"\(\s*\)", "", text)
    text = re.sub(r"\s+([,.;:])", r"\1", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text, missing


def safe_name(text):
    """A file and resource name fragment: lower case, [a-z0-9._-]."""
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")
    return s or "item"


SLUG_MAX = 64
_SLUG_OK = re.compile(r"[a-z0-9][a-z0-9_-]*\Z")


def slug(name):
    """The only form in which a name read from the input (a 4.x decoder name, an integration of
    ``decisions.json``, a list path) becomes part of an integration key, a resource name, a file name or an index
    name: ``[a-z0-9][a-z0-9_-]*``, at most :data:`SLUG_MAX` characters.

    A name already in that form is kept as is. Any other name is lower-cased, every other character becomes
    ``-``, and ``-`` plus the first 8 hex characters of the sha256 of the original name are added: two different
    names never share a slug by accident (``Foo`` and ``foo`` differ, which matters on a case-insensitive file
    system), and the result does not depend on the order of the input."""
    name = "" if name is None else str(name)
    if len(name) <= SLUG_MAX and _SLUG_OK.match(name):
        return name
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:8]
    base = re.sub(r"[^a-z0-9_-]+", "-", name.lower()).strip("-_")[:SLUG_MAX - 9].rstrip("-_") or "item"
    return "%s-%s" % (base, digest)


def is_slug(name):
    return isinstance(name, str) and len(name) <= SLUG_MAX and bool(_SLUG_OK.match(name))
