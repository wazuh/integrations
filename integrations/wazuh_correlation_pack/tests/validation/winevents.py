"""Windows 4625 test records: build, parse, model the stock decoding, sanitize captures.

Pure functions, no network. Used by the P1/P2/P3 validation tests and by the offline self-tests.

* ``build_4625``: a 4625 record in the form the Wazuh agent sends (``EvtRenderEventXml``, one
  line, single-quoted attributes), derived from the first event of the real capture
  ``samples/windows/4625_smb_bruteforce.sanitized.xml.log``. Only the fields given are changed;
  ``None`` removes a ``<Data>`` element. Records built here are **synthetic** (provenance
  ``synthetic-derived``), never captured.
* ``decoder_model``: the identity fields the stock decoders are expected to produce for a 4625
  record. It restates the decoder steps recorded on 5.0.0-rc1
  (``evidence/2026-11-22-rc1-105573d/windows_decoder_identity_steps.json``, decoders
  ``decoder/windows-event/0`` step 2 and ``decoder/windows-security/0`` steps 5-13). It is an
  expectation to be checked against the real pipeline (P1), not a substitute for it.
* ``sanitize``: rewrite a captured record before it is saved (computer, workstation, configured
  names, non-documentation IPv4 addresses, domain SIDs) and report anything that remains.
"""

import ipaddress
import os
import re
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.abspath(os.path.join(HERE, "..", ".."))
SAMPLE = os.path.join(PACK, "samples", "windows", "4625_smb_bruteforce.sanitized.xml.log")
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
NULL_SID = "S-1-0-0"

IDENTITY_FIELDS = ("host.name", "user.name", "user.domain", "user.id", "user.target.name", "user.target.domain",
                   "user.target.id")


def template():
    with open(SAMPLE, "r", encoding="utf-8") as fh:
        return fh.readline().rstrip("\r\n")


def _esc(v):
    return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("'", "&apos;")


def set_data(xml, name, value):
    """Set ``<Data Name='name'>`` to value; None removes the element; '' leaves it empty."""
    pat = re.compile(r"<Data Name='%s'>[^<]*</Data>|<Data Name='%s'/>" % (re.escape(name), re.escape(name)))
    if not pat.search(xml):
        raise KeyError("no <Data Name='%s'> in the template" % name)
    if value is None:
        return pat.sub("", xml, count=1)
    return pat.sub(lambda _m: "<Data Name='%s'>%s</Data>" % (name, _esc(value)), xml, count=1)


def time_created(dt):
    """Windows SystemTime with 7 fractional digits, as in the capture."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%07dZ" % (dt.microsecond * 10)


def build_4625(dt, record_id, computer, data, tmpl=None):
    """A 4625 record from the capture template with TimeCreated, EventRecordID, Computer and the
    given EventData values replaced (``data``: {Data name: value or None})."""
    x = tmpl or template()
    x = re.sub(r"<TimeCreated SystemTime='[^']*'/>", "<TimeCreated SystemTime='%s'/>" % time_created(dt), x)
    x = re.sub(r"<EventRecordID>\d+</EventRecordID>", "<EventRecordID>%d</EventRecordID>" % record_id, x)
    x = re.sub(r"<Computer>[^<]*</Computer>", "<Computer>%s</Computer>" % _esc(computer), x)
    for k, v in data.items():
        x = set_data(x, k, v)
    return x


def parse_4625(xml):
    """{'record_id', 'time_created', 'computer', 'event_id', 'channel', 'data': {name: value or ''}}."""
    root = ET.fromstring(xml)
    sysn = root.find(NS + "System")
    out = {"event_id": sysn.findtext(NS + "EventID"), "record_id": sysn.findtext(NS + "EventRecordID"),
           "computer": sysn.findtext(NS + "Computer"), "channel": sysn.findtext(NS + "Channel"),
           "time_created": (sysn.find(NS + "TimeCreated").get("SystemTime")
                            if sysn.find(NS + "TimeCreated") is not None else None), "data": {}}
    ed = root.find(NS + "EventData")
    for d in (ed if ed is not None else []):
        out["data"][d.get("Name")] = d.text or ""
    out["has_rendering_info"] = root.find(NS + "RenderingInfo") is not None
    return out


def record_id_of(text):
    m = re.search(r"<EventRecordID>(\d+)</EventRecordID>", text or "")
    return m.group(1) if m else None


def decoder_model(computer, data):
    """Identity fields expected from the stock decoders for one 4625 record (RC1 decoder steps).

    ``data``: EventData values; a missing key means the element is absent. Returns {field: value};
    fields the decoders would not set are absent. Empty strings are kept (the comparison treats
    '' and absent as equal, because how the engine maps an empty element was never observed).
    """
    out = {}

    def put(k, v):
        if v is not None:
            out[k] = v

    g = data.get
    # decoder/windows-event/0 step 2
    put("host.name", computer)
    put("user.domain", g("SubjectDomainName"))
    put("user.id", g("SubjectUserSid"))
    put("user.target.name", g("TargetUserName"))
    put("user.target.id", g("TargetUserSid"))
    # decoder/windows-security/0 (4625 is in the kvdb list target_user_1)
    if g("SubjectUserName") is not None and g("SubjectUserName") != "-":          # step 5
        out["user.name"] = g("SubjectUserName")
    if "user.id" not in out or out["user.id"] == NULL_SID:                        # step 8 (step 7: no change)
        put("user.id", g("TargetUserSid"))
    tun = g("TargetUserName")
    if "user.name" in out and tun is not None and tun != "-":                     # step 9
        out["user.target.name"] = tun
    elif "user.name" not in out and tun is not None and tun != "-":               # step 10
        out["user.name"] = tun
    if "user.domain" in out and out["user.domain"] != "-":                        # step 12
        put("user.target.domain", g("TargetDomainName"))
    else:                                                                         # step 13
        put("user.domain", g("TargetDomainName"))
    return out


def get_field(doc, path):
    """Value of a dotted field in a nested (or flattened) _source; first element of a list."""
    if path in doc:
        v = doc[path]
    else:
        v = doc
        for p in path.split("."):
            if not isinstance(v, dict) or p not in v:
                return None
            v = v[p]
    if isinstance(v, list):
        v = v[0] if v else None
    return None if isinstance(v, dict) else v


def compare_identity(decoded_doc, expected):
    """[(field, expected, decoded)] for every identity field that differs ('' == absent)."""
    diffs = []
    for f in IDENTITY_FIELDS:
        want = expected.get(f)
        got = get_field(decoded_doc, f)
        w = None if want in (None, "") else str(want)
        h = None if got in (None, "") else str(got)
        if w != h:
            diffs.append((f, want, got))
    return diffs


def flat_identity(decoded_doc):
    return {f: get_field(decoded_doc, f) for f in IDENTITY_FIELDS if get_field(decoded_doc, f) is not None}


# ------------------------------------------------------------------ sanitizing captured records

DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
KEEP_IPS = {"127.0.0.1", "0.0.0.0", "::1", "-"}


class Sanitizer(object):
    """Deterministic rewriting of captured records (same input -> same placeholder within a run)."""

    def __init__(self, names=None, forbidden=None):
        self.names = dict(names or {})            # real (case-insensitive) -> placeholder
        self.forbidden = [f for f in (forbidden or []) if f]
        self.ip_map = {}

    def _ip(self, m):
        s = m.group(0)
        try:
            ip = ipaddress.ip_address(s)
        except ValueError:
            return s
        if s in KEEP_IPS or any(ip in n for n in DOC_NETS):
            return s
        if s not in self.ip_map:
            self.ip_map[s] = "203.0.113.%d" % (200 + len(self.ip_map))
        return self.ip_map[s]

    def __call__(self, xml):
        x = re.sub(r"<Computer>[^<]*</Computer>", "<Computer>WCP-WIN-LAB</Computer>", xml)
        x = re.sub(r"(<Data Name='WorkstationName'>)[^<]*(</Data>)", r"\1WCP-WS\2", x)
        x = re.sub(r"S-1-5-21-\d+-\d+-\d+", "S-1-5-21-1000000001-1000000002-1000000003", x)
        for real in sorted(self.names, key=len, reverse=True):
            x = re.sub(re.escape(real), lambda _m, r=self.names[real]: r, x, flags=re.IGNORECASE)
        x = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", self._ip, x)
        return x

    def leftovers(self, text):
        """Forbidden strings (configured names, addresses, access accounts) still present."""
        low = text.lower()
        return sorted({f for f in self.forbidden if f.lower() in low})
