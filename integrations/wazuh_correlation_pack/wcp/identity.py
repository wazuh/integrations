r"""Backend-derived values usable as Sigma ``value_count`` fields (prefix ``wcp.``).

Sigma ``value_count`` counts the distinct values of one field. Some identities are not one WCS
field: a Windows account is its domain (or computer) *and* its name. A derived value is computed
per event by the backend from WCS fields, with the same logic in Python (reference, unit tests)
and Painless (the monitor). A derived value can only be used as ``condition.field`` of a
correlation, never in a base-rule selection.

``wcp.windows_target_account`` - the account that failed to log on, ``<realm>\<user>``, lower case.

Decoded mapping of Windows event 4625 by the stock Wazuh 5.0 decoders (decoder/windows-event/0,
decoder/windows-security/0; observed on 5.0.0-rc1 and 5.0.0-rc2), which this derivation relies on:

* ``user.target.name`` = TargetUserName (always).
* ``user.target.domain`` = TargetDomainName, set **only** when the event has a reporting subject
  (SubjectDomainName present and not ``-``). This is the only indexed field whose value
  demonstrably comes from the failed target's domain.
* ``user.domain`` = SubjectDomainName when a reporting subject is present; when it is absent
  (``-``, typical for network logons) the decoders put TargetDomainName there instead. The indexed
  fields cannot always tell which of the two it holds: a subject *name* with the NULL SID and no
  TargetDomainName gives ``user.id`` == ``user.target.id`` and ``user.domain`` = the subject's
  domain, exactly like a subject-absent event (5.0.0-rc2 validation run, test P1). The raw event
  (``event.original``) is not readable by a monitor (not indexed, no doc values).

Derivation (failed-target provenance only; the reporting subject is never used):

1. user = ``user.target.name``; events without it (or ``-``) are not counted.
2. realm = ``user.target.domain`` if present and not empty or ``-``; ``user.domain`` is **never**
   used.
3. realm ``.`` (the local computer) is replaced by the first label of ``host.name`` (the reporting
   computer), so ``.\admin`` and ``HOST\admin`` on the same agent are one account.
4. otherwise the realm is unknown: ``?``. Accounts with an unknown realm form their own realm:
   ``?\bob`` and ``contoso\bob`` are two distinct values (the counting step below may merge them).
5. Lower case (Windows account and domain names are case-insensitive). NetBIOS and DNS forms of
   one domain (``CONTOSO`` / ``contoso.local``) are not unified.

Counting (the Windows spray monitor, ``wcp/alerting.py`` ``PAINLESS_REDUCE_UNKNOWN_REALM``): within a
window, every value with a known realm counts once, and an unknown-realm value ``?\name`` adds an
account only if no value with a known realm and the same user name is present. A failed target seen
through both decoded shapes (``contoso\bob`` and ``?\bob``) is therefore one account.

Consequences: the counting is conservative. Events without a reporting subject (network logons such
as SMB or RDP) are counted by user name (``?\name``), so the same user name in different domains
counts as **one** account. An unknown-realm event whose user name also appears with an explicit
domain is counted as that account, so the count can be lower than the number of real accounts.
Explicit target domains stay distinct, and distinct user names always count.

This counting fixes one demonstrated over-count: a failed target seen through both decoded shapes
(``contoso\bob`` and ``?\bob``) was counted as two accounts. It does not prevent other over-counts:
the NetBIOS and DNS forms of one domain are two values, and a log record collected twice is counted
twice.
"""

VIRTUAL_PREFIX = "wcp."


def _first(doc, path):
    """First value of a WCS field in a nested or flattened document, as str, or None."""
    if path in doc:
        v = doc[path]
    else:
        v = doc
        for part in path.split("."):
            if not isinstance(v, dict) or part not in v:
                return None
            v = v[part]
    if isinstance(v, list):
        v = v[0] if v else None
    if v is None or isinstance(v, dict):
        return None
    return str(v)


def _norm(s):
    if s is None:
        return None
    s = s.strip()
    if not s or s == "-":
        return None
    return s.lower()


def windows_target_account(doc):
    """Python reference of the Painless derivation; None means the event is not counted."""
    name = _norm(_first(doc, "user.target.name"))
    if name is None:
        return None
    realm = _norm(_first(doc, "user.target.domain"))   # the only field of demonstrable target provenance
    if realm == ".":
        host = _norm(_first(doc, "host.name"))
        realm = host.split(".", 1)[0] if host else None
    if not realm:
        realm = "?"
    return realm + "\\" + name


PAINLESS_FUNCTIONS = r"""
String wcpFirst(def d, String f) { if (!d.containsKey(f) || d[f].size() == 0) { return null; } return d[f].value.toString(); }
String wcpNorm(String s) { if (s == null) { return null; } String x = s.trim(); if (x.isEmpty() || x == '-') { return null; } return x.toLowerCase(); }
""".strip()

PAINLESS_WINDOWS_TARGET_ACCOUNT = r"""
String wcpName = wcpNorm(wcpFirst(doc, 'user.target.name'));
if (wcpName == null) { return; }
String wcpRealm = wcpNorm(wcpFirst(doc, 'user.target.domain'));
if (wcpRealm != null && wcpRealm == '.') {
  String wcpHost = wcpNorm(wcpFirst(doc, 'host.name'));
  if (wcpHost == null) { wcpRealm = null; } else { int k = wcpHost.indexOf('.'); wcpRealm = k > 0 ? wcpHost.substring(0, k) : wcpHost; }
}
if (wcpRealm == null) { wcpRealm = '?'; }
v = wcpRealm + '\\' + wcpName;
""".strip()


class Identity(object):
    def __init__(self, name, required, optional, functions, body, python, description, unknown_realm_merge=False):
        self.unknown_realm_merge = unknown_realm_merge
        self.name = name
        self.required = required
        self.optional = optional
        self.functions = functions
        self.body = body
        self.python = python
        self.description = description


IDENTITIES = {
    "wcp.windows_target_account": Identity(
        "wcp.windows_target_account",
        required=["user.target.name"],
        optional=["user.target.domain", "host.name"],
        functions=PAINLESS_FUNCTIONS,
        body=PAINLESS_WINDOWS_TARGET_ACCOUNT,
        python=windows_target_account,
        unknown_realm_merge=True,
        description="Windows account that failed to log on: <target domain or computer>\\<target user>",
    ),
}


def is_virtual(field):
    return bool(field) and field.startswith(VIRTUAL_PREFIX)


def get(field):
    return IDENTITIES.get(field)
