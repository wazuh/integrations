"""Lab driver: generate controlled activity on the test endpoints.

The lab is reached through SSH to the LXD host, then ``lxc exec`` into the test
containers. Configure with environment variables:

    WCP_LAB_SSH   ssh command prefix, e.g.
                  "ssh -o BatchMode=yes -i ~/.ssh/id_ed25519_lab user@192.0.2.10"
    WCP_LAB_SUDO  "sudo" (default) or "" when the SSH user runs lxc directly

Two ways to create events:

* ``live_ssh``: real sshd authentication failures (sshpass with a fixed dummy
  password against locked ``wcpt-*`` test accounts). Exercises sshd, journald,
  the agent, the manager, the engine and the indexer.
* ``replay``: append lines to /var/log/wcp-replay/replay.log on an endpoint,
  which the agent collects with ``<log_format>syslog</log_format>``. Exercises
  the agent, manager, engine and indexer with controlled timestamps/sources,
  but not sshd or journald.
"""

import datetime
import os
import random
import shlex
import subprocess

DUMMY_PASSWORD = "wcp-not-a-password"  # never a real credential; target accounts are locked
REPLAY_FILE = "/var/log/wcp-replay/replay.log"
SSH_OPTS = ("-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no "
            "-o PreferredAuthentications=password -o ConnectTimeout=5 -o LogLevel=ERROR")


def _prefix():
    p = os.environ.get("WCP_LAB_SSH")
    if not p:
        raise RuntimeError("set WCP_LAB_SSH to the ssh command that reaches the LXD host")
    return shlex.split(os.path.expanduser(p))


def host(cmd, stdin=None, timeout=600, check=True):
    """Run a shell command on the LXD host.

    stdin is sent as UTF-8 bytes: text-mode pipes on Windows would turn "\\n" into "\\r\\n", and a
    trailing carriage return changes how the stock decoders parse replayed lines.
    """
    data = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
    r = subprocess.run(_prefix() + [cmd], input=data, capture_output=True, timeout=timeout)
    out, err = r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")
    if check and r.returncode != 0:
        raise RuntimeError("lab command failed (%d): %s\n%s" % (r.returncode, cmd[:200], err[-2000:]))
    return out


def lxc(container, cmd, stdin=None, timeout=600, check=True):
    sudo = os.environ.get("WCP_LAB_SUDO", "sudo")
    return host("%s lxc exec %s -- sh -c %s" % (sudo, container, shlex.quote(cmd)), stdin=stdin, timeout=timeout,
                check=check)


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def live_ssh(src, dst_ip, users, attempts_per_connection=1, pause=0.0):
    """One SSH connection per entry of ``users``, each making ``attempts_per_connection`` password attempts.

    The OpenSSH client answers every password prompt through SSH_ASKPASS (forced, OpenSSH >= 8.4),
    so one connection can carry several attempts (sshpass answers only the first prompt).
    /usr/local/bin/wcp-askpass on the source endpoint prints the fixed dummy password.
    Returns (start_utc, end_utc, expected_failed_attempts).
    """
    parts = []
    for u in users:
        parts.append("SSH_ASKPASS=/usr/local/bin/wcp-askpass SSH_ASKPASS_REQUIRE=force setsid ssh %s "
                     "-o NumberOfPasswordPrompts=%d %s@%s true </dev/null >/dev/null 2>&1; %s" % (
                         SSH_OPTS, attempts_per_connection, shlex.quote(u), dst_ip,
                         ("sleep %s" % pause) if pause else "true"))
    start = now_utc()
    lxc(src, "; ".join(parts) + "; true", timeout=60 + len(users) * (attempts_per_connection * 4 + pause + 2))
    end = now_utc()
    return start, end, len(users) * attempts_per_connection


def install_askpass(container):
    lxc(container, "printf '#!/bin/sh\necho %s\n' > /usr/local/bin/wcp-askpass && chmod 755 /usr/local/bin/wcp-askpass"
        % DUMMY_PASSWORD)


def syslog_ts(dt):
    """RFC 3164 timestamp as rsyslog writes it to auth.log on Ubuntu 22.04 (local time = UTC in the lab)."""
    return dt.strftime("%b ") + ("%2d" % dt.day) + dt.strftime(" %H:%M:%S")


def sshd_failed_line(dt, hostname, user, src_ip, invalid=False, pid=None, port=None):
    pid = pid or random.randint(2000, 60000)
    port = port or random.randint(32768, 60999)
    who = ("invalid user %s" % user) if invalid else user
    return "%s %s sshd[%d]: Failed password for %s from %s port %d ssh2" % (
        syslog_ts(dt), hostname, pid, who, src_ip, port)


def sshd_attempt_lines(dt, hostname, user, src_ip, invalid=False):
    """All lines OpenSSH 8.9 + pam_unix write for one failed password attempt on one connection
    (as captured live on the lab endpoint; see samples/linux/sshd_live_capture.log)."""
    pid = random.randint(2000, 60000)
    port = random.randint(32768, 60999)
    ts = syslog_ts(dt)
    lines = []
    if invalid:
        lines.append("%s %s sshd[%d]: Invalid user %s from %s port %d" % (ts, hostname, pid, user, src_ip, port))
        lines.append("%s %s sshd[%d]: pam_unix(sshd:auth): check pass; user unknown" % (ts, hostname, pid))
        lines.append("%s %s sshd[%d]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh "
                     "ruser= rhost=%s" % (ts, hostname, pid, src_ip))
    else:
        lines.append("%s %s sshd[%d]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh "
                     "ruser= rhost=%s  user=%s" % (ts, hostname, pid, src_ip, user))
    lines.append(sshd_failed_line(dt, hostname, user, src_ip, invalid, pid, port))
    lines.append("%s %s sshd[%d]: Connection closed by %s %s %s port %d [preauth]" % (
        ts, hostname, pid, "invalid user" if invalid else "authenticating user", user, src_ip, port))
    return lines


WIN_SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                          "samples", "windows", "4625_smb_bruteforce.sanitized.xml.log")


def win_template():
    """First event of the sanitized real 4625 capture (see samples/windows/README.md)."""
    with open(WIN_SAMPLE, "r", encoding="utf-8") as fh:
        return fh.readline().rstrip("\n")


_RECORD = [100000]


def win_4625_line(dt, target_user, src_ip, computer="WCP-WIN-LAB1", template=None):
    """A 4625 event derived from the real capture: only TimeCreated, EventRecordID, Computer,
    TargetUserName, IpAddress and IpPort are replaced. LogonType 3 / NTLM / SubStatus 0xc000006a are kept."""
    import re
    t = template or win_template()
    _RECORD[0] += 1
    st = dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%07dZ" % (dt.microsecond * 10)
    t = re.sub(r"<TimeCreated SystemTime='[^']*'/>", "<TimeCreated SystemTime='%s'/>" % st, t)
    t = re.sub(r"<EventRecordID>\d+</EventRecordID>", "<EventRecordID>%d</EventRecordID>" % _RECORD[0], t)
    t = re.sub(r"<Computer>[^<]*</Computer>", "<Computer>%s</Computer>" % computer, t)
    t = re.sub(r"<Data Name='TargetUserName'>[^<]*</Data>", "<Data Name='TargetUserName'>%s</Data>" % target_user, t)
    t = re.sub(r"<Data Name='IpAddress'>[^<]*</Data>", "<Data Name='IpAddress'>%s</Data>" % src_ip, t)
    t = re.sub(r"<Data Name='IpPort'>[^<]*</Data>", "<Data Name='IpPort'>%d</Data>" % random.randint(49152, 65535), t)
    return t


def replay(container, lines):
    """Append lines to the replay file collected by the agent."""
    data = "".join(l.rstrip("\n") + "\n" for l in lines)
    lxc(container, "cat >> %s" % REPLAY_FILE, stdin=data)
    return len(lines)
