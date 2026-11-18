#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Rashik Adhikari
# SPDX-License-Identifier: Apache-2.0
"""Run aertun.ini's cases through wazuh-logtest on this manager.

    python3 check_rules.py [aertun.ini] [/var/ossec/bin/wazuh-logtest]

Each case is its own logtest session, its logs given in order, and the last
log's rule, level and decoder are held to the case's. Exits non-zero naming
every case that does not hold. Run it after installing aertun_rules.xml and
restarting the manager.
"""

import re
import subprocess
import sys


def cases(path):
    out, cur = [], None
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("["):
                cur = {"name": line[1:-1], "logs": []}
                out.append(cur)
            elif cur is not None and line.startswith("log ") and " pass = " in line:
                cur["logs"].append(line.split(" pass = ", 1)[1])
            elif cur is not None and " = " in line and not line.startswith(";"):
                key, value = line.split(" = ", 1)
                cur[key.strip()] = value.strip()
    return out


def main(args):
    ini = args[1] if len(args) > 1 else "aertun.ini"
    logtest = args[2] if len(args) > 2 else "/var/ossec/bin/wazuh-logtest"
    failed = 0
    all_cases = cases(ini)
    for c in all_cases:
        run = subprocess.run([logtest], input="\n".join(c["logs"]) + "\n",
                             capture_output=True, text=True)
        # wazuh-logtest writes its phases to standard error.
        last = (run.stdout + run.stderr).split("**Phase 1: Completed pre-decoding.")[-1]
        got = []
        for pattern in (r"id: '(\d+)'", r"level: '(\d+)'", r"name: '([^']*)'"):
            m = re.search(pattern, last)
            got.append(m.group(1) if m else "-")
        want = [c.get("rule", "-"), c.get("alert", "-"), c.get("decoder", "-")]
        ok = got == want
        failed += not ok
        print("%s  %s%s" % ("pass" if ok else "FAIL", c["name"],
                            "" if ok else "  (got rule %s level %s decoder %s)" % tuple(got)))
    print("%d of %d cases hold" % (len(all_cases) - failed, len(all_cases)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
