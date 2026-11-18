#!/usr/bin/env python3
"""Replay synthetic inventory through a manager with the rule file installed."""

import argparse
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CASES = (
    ("affected runtime", "affected", "present", "absent", (112939, 8)),
    ("fixed runtime", "fixed", "present", "absent", None),
    ("unaffected vendor build", "unaffected", "present", "absent", None),
    ("CPU path absent", "affected", "absent", "absent", None),
    ("mitigation verified", "affected", "present", "present", None),
    ("vendor unknown", "unknown", "present", "absent", (112940, 5)),
    ("CPU unknown", "affected", "unknown", "absent", (112940, 5)),
    ("mitigation unknown", "affected", "present", "unknown", (112940, 5)),
    ("fixed runtime with unknown CPU", "fixed", "unknown", "unknown", None),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logtest", nargs=argparse.REMAINDER, help="Logtest command and arguments")
    args = parser.parse_args()
    command = args.logtest or ["/var/ossec/bin/wazuh-logtest"]
    failures = 0
    for name, vendor, cpu, mitigation, expected in CASES:
        event = subprocess.check_output([
            sys.executable, str(ROOT / "assess.py"),
            "--workload", "synthetic-api", "--runtime", "Fixture JVM",
            "--vendor-status", vendor, "--cpu-path", cpu, "--mitigation", mitigation,
        ], text=True)
        result = subprocess.run(
            command, input=event, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=60,
        )
        output = result.stdout
        match = re.search(r"id: '(\d+)'\s+level: '(\d+)'", output)
        actual = tuple(map(int, match.groups())) if match else None
        passed = (
            result.returncode == 0
            and "name: 'json'" in output
            and (actual == expected if expected else actual in (None, (112938, 0)))
            and ("Alert to be generated" in output) == bool(expected)
        )
        failures += not passed
        print(f"{'PASS' if passed else 'FAIL'} {name}: decoder=json, rule={actual}")
        if not passed:
            print(output)
    print(f"{len(CASES) - failures}/{len(CASES)} passed")
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
