"""Windows lab endpoint helpers for P2 and P3 (real 4625 generation and ground truth).

Failed logons are generated only for test account names (``test_account_prefix``, default
``wcpt-``) that do not exist on the endpoint (SubStatus 0xc0000064), so no account can be locked
out; the access account is refused as a target (vlib.check_test_account). The dummy password is
``vlib.DUMMY_PASSWORD``, never a real credential.

* ``logon_user``: LogonUser() from PowerShell on the Windows endpoint itself. Windows records the
  calling account as the **reporting subject** (SubjectUserName/SubjectDomainName) and the
  requested account as the target - the P2 event shape. No IpAddress (local call), so these events
  have no ``source.ip`` and are not counted by the pack's correlations (documented in the base
  rule); P2 counts them with a dry-run probe grouped by agent only.
* ``smb_attempts`` / ``rdp_attempts``: network failures from the Linux source endpoint
  (``smbclient``, ``xfreerdp +auth-only``), which carry IpAddress - the P3 shape.
* ``security_4625``: the Security log records (``Get-WinEvent``, ``ToXml()``) for the test names
  since a start time: the ground truth the pipeline is compared with.
"""

import json
import shlex

import vlib as V

LOGON_TYPES = {"interactive": 2, "network": 3, "batch": 4, "service": 5, "network_cleartext": 8}

PS_LOGON = r"""
$sig = '[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool LogonUser(string u, string d, string p, int t, int prov, out IntPtr h);'
$api = Add-Type -MemberDefinition $sig -Name WcpLogon -Namespace WcpTest -PassThru
$attempts = '__ATTEMPTS__' | ConvertFrom-Json
$out = @()
foreach ($a in $attempts) {
  $h = [IntPtr]::Zero
  $ok = $api::LogonUser($a.user, $a.domain, '__PW__', [int]$a.type, 0, [ref]$h)
  $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  $out += [pscustomobject]@{ user = $a.user; domain = $a.domain; type = [int]$a.type; succeeded = $ok; win32_error = $err;
                             at = (Get-Date).ToUniversalTime().ToString('o') }
  Start-Sleep -Milliseconds 400
}
$out
"""

PS_EVENTS = r"""
$start = [datetime]::Parse('__START__').ToUniversalTime().ToLocalTime()
$ev = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $start } -ErrorAction SilentlyContinue
@($ev | Where-Object { $_.Properties.Count -gt 5 -and ([string]$_.Properties[5].Value) -like '__PREFIX__*' } |
  ForEach-Object { [pscustomobject]@{ record_id = [string]$_.RecordId; xml = $_.ToXml() } })
"""


def _ps_str(s):
    return str(s).replace("'", "''")


def logon_user(ep, cfg, attempts):
    """attempts: [{"user", "domain", "type"}]; returns the per-attempt results (none may succeed)."""
    for a in attempts:
        V.check_test_account(cfg, a["user"])
    script = PS_LOGON.replace("__ATTEMPTS__", _ps_str(json.dumps(attempts))).replace("__PW__", V.DUMMY_PASSWORD)
    res = ep.run_json(script, timeout=120)
    if any(r.get("succeeded") for r in res):
        raise RuntimeError("a test logon succeeded - the test account exists with the dummy password; stop")
    return res


def security_4625(ep, start, prefix):
    script = PS_EVENTS.replace("__START__", _ps_str(V.iso(start))).replace("__PREFIX__", _ps_str(prefix))
    return ep.run_json(script, timeout=300)


def audit_logon_failure_enabled(ep):
    out = ep.run("auditpol /get /subcategory:'Logon' /r | ConvertFrom-Csv | Select-Object -ExpandProperty "
                 "'Inclusion Setting'", timeout=60, check=False)
    return "failure" in out.lower(), out.strip()


def smb_attempts(src, cfg, target_host, users, domain=None, pause=1.0):
    """One failed SMB authentication per user from the Linux source endpoint (needs smbclient)."""
    parts = []
    for u in users:
        V.check_test_account(cfg, u)
        who = ("%s\\%s" % (domain, u)) if domain else u
        parts.append("smbclient -L %s -m SMB3 -U %s >/dev/null 2>&1; sleep %s" % (
            shlex.quote("//%s" % target_host), shlex.quote("%s%%%s" % (who, V.DUMMY_PASSWORD)), pause))
    start = V.utc()
    src.run("; ".join(parts) + "; true", timeout=60 + len(users) * (pause + 10), sudo=False)
    return start, V.utc()


def rdp_attempts(src, cfg, target_host, users, pause=2.0):
    """One failed RDP authentication per user (xfreerdp +auth-only); records the tool's exit codes.

    xfreerdp (FreeRDP 2.x, X11 client) opens an X display even for +auth-only; on a headless
    endpoint it is run under ``xvfb-run -a`` when available (the output records ``wrapper=``).
    """
    parts = []
    for u in users:
        V.check_test_account(cfg, u)
        parts.append("timeout 25 $W xfreerdp /v:%s /u:%s /p:%s /cert:ignore +auth-only >/dev/null 2>&1; echo $?; sleep %s"
                     % (shlex.quote(target_host), shlex.quote(u), shlex.quote(V.DUMMY_PASSWORD), pause))
    start = V.utc()
    out = src.run("command -v xfreerdp >/dev/null || { echo NO_XFREERDP; exit 0; }; W=''; "
                  "if [ -z \"$DISPLAY\" ] && command -v xvfb-run >/dev/null; then W='xvfb-run -a'; fi; "
                  "echo wrapper=${W:-none}; " + "; ".join(parts),
                  timeout=60 + len(users) * (pause + 25), sudo=False)
    return start, V.utc(), out.split()


def spec_account(parsed):
    """The specified account of a raw 4625 record (README 'Grouping'), from the raw failed-target fields:
    <TargetDomainName>\\<TargetUserName>, lower case, '.' = the computer's first label - when the event
    carries TargetDomainName as the target's domain, i.e. it has a reporting subject (the decoders then set
    user.target.domain); otherwise, or when it is missing, empty or '-', the realm is '?'."""
    d = parsed["data"]
    name = (d.get("TargetUserName") or "").strip()
    if not name or name == "-":
        return None
    subject = (d.get("SubjectDomainName") or "").strip()
    realm = (d.get("TargetDomainName") or "").strip() if subject not in ("", "-") else ""
    if realm == ".":
        realm = (parsed.get("computer") or "").split(".", 1)[0]
    if not realm or realm == "-":
        realm = "?"
    return (realm + "\\" + name).lower()
