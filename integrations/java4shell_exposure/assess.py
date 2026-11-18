#!/usr/bin/env python3
"""Emit a JSON observation from verified runtime inventory."""

import argparse
import json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workload", required=True, help="Stable service or workload identifier")
    parser.add_argument("--runtime", required=True, help="Running JVM vendor and exact build")
    parser.add_argument(
        "--vendor-status", choices=("affected", "fixed", "unaffected", "unknown"),
        default="unknown", help="Vendor verdict for the exact running build",
    )
    parser.add_argument(
        "--cpu-path", choices=("present", "absent", "unknown"), default="unknown",
        help="Whether x86-64 and AVX-512 VBMI are visible to the workload",
    )
    parser.add_argument(
        "--mitigation", choices=("present", "absent", "unknown"), default="unknown",
        help="Whether an advisory-listed workaround is effective in the running JVM",
    )
    args = parser.parse_args()
    observation = vars(args)
    complete = all(observation[field] != "unknown" for field in (
        "vendor_status", "cpu_path", "mitigation",
    ))
    print(json.dumps({
        "event_type": "java4shell_runtime_assessment",
        "cve": "CVE-2026-114938",
        **observation,
        "assessment_complete": "yes" if complete else "no",
    }))


if __name__ == "__main__":
    main()
