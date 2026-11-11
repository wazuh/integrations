#!/usr/bin/env python3
"""Check agentmetry.ini against a Wazuh manager container with wazuh-logtest."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


def read_cases(ini: Path) -> list[dict[str, str]]:
    cases: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for raw in ini.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            current = {"title": line[1:-1]}
            cases.append(current)
        elif line.startswith("log 1 pass = "):
            current["log"] = line[len("log 1 pass = "):]
        elif " = " in line and current:
            key, value = line.split(" = ", 1)
            current[key] = value
    return cases


def logtest(container: str, log: str) -> dict[str, str]:
    done = subprocess.run(
        ["docker", "exec", "-i", container, "/var/ossec/bin/wazuh-logtest"],
        input=log + "\n",
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    output = done.stdout + done.stderr
    found = {"output": output}
    decoding = output.split("**Phase 2", 1)[-1]
    if match := re.search(r"name: '([^']+)'", decoding):
        found["decoder"] = match.group(1)
    if "**Phase 3" in output:
        rules = output.split("**Phase 3", 1)[1]
        if match := re.search(r"id: '(\d+)'", rules):
            found["rule"] = match.group(1)
        if match := re.search(r"level: '(\d+)'", rules):
            found["alert"] = match.group(1)
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", default="agentmetry-wazuh-test")
    parser.add_argument("--ini", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    failures = 0
    rows = ["| Case | Expected rule | Got rule | Expected level | Got level | Decoder | Result |", "|---|---|---|---|---|---|---|"]
    for case in read_cases(args.ini):
        got = logtest(args.container, case["log"])
        passed = all(got.get(k) == case[k] for k in ("rule", "alert", "decoder"))
        failures += not passed
        rows.append(
            f"| {case['title']} | {case['rule']} | {got.get('rule', 'none')} | {case['alert']} | "
            f"{got.get('alert', 'none')} | {got.get('decoder', 'none')} | {'pass' if passed else 'FAIL'} |"
        )
        if not passed:
            print(f"FAIL {case['title']}\n{got['output'][-1500:]}", file=sys.stderr)
    args.report.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print("\n".join(rows))
    print(f"{len(rows) - 2 - failures} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
