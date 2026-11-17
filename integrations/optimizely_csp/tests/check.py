"""Run the offline checks or replay each normalized report on a Wazuh manager."""

import argparse
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
RULE = ROOT / "ruleset/rules/optimizely_csp_rules.xml"
CASES = [
    ("1688360.cc", "enforce", "script-src-elem", True),
    ("asset.5vobauua3ojpklx.icu", "report", "frame-src", True),
    ("cdn.optimizely.com", "enforce", "script-src-elem", False),
    ("1688360.cc.example.test", "enforce", "connect-src", False),
    ("fake1688360.cc", "enforce", "connect-src", False),
    ("example.test", "enforce", "connect-src", False),
    None,  # Ambiguous authority
    None,  # No destination hostname for eval
    None,  # Unknown policy disposition
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logtest", help="Path to wazuh-logtest on the lab manager")
    args = parser.parse_args()
    rule = ET.parse(RULE).getroot().find("rule")
    fixtures = (ROOT / "tests/csp.jsonl").read_text().splitlines()
    if len(fixtures) != len(CASES):
        raise SystemExit("Fixture count does not match expectations")

    for index, (fixture, expected) in enumerate(zip(fixtures, CASES), start=1):
        normalized = subprocess.check_output(
            ["jq", "-c", "-f", ROOT / "normalize-csp.jq"],
            input=fixture.replace("[.]", "."),
            text=True,
        )
        if expected is None:
            assert not normalized, (index, normalized)
        else:
            host, disposition, directive, should_alert = expected
            event = json.loads(normalized)
            assert event == {
                "integration": "optimizely_csp",
                "csp": {"destination": host, "disposition": disposition, "directive": directive},
            }, (index, event)
            if args.logtest:
                result = subprocess.check_output(
                    [args.logtest], input=normalized, text=True, stderr=subprocess.STDOUT
                )
                matched = f"id: '{rule.attrib['id']}'" in result
                if "name: 'json'" not in result or matched != should_alert:
                    raise SystemExit(f"Case {index} failed\n{result}")
                if matched and f"level: '{rule.attrib['level']}'" not in result:
                    raise SystemExit(f"Case {index} returned an unexpected level\n{result}")
            else:
                for field in rule.findall("field"):
                    value = event
                    for key in field.attrib["name"].split("."):
                        value = value[key]
                    result = subprocess.run(
                        ["rg", "--no-config", "-qP", "--", field.text],
                        text=True,
                        input=value + "\n",
                    )
                    if result.returncode not in (0, 1):
                        raise SystemExit(f"PCRE2 failed for {field.attrib['name']}")
                    if (result.returncode == 0) != should_alert and field.attrib["name"] == "csp.destination":
                        raise SystemExit(f"Case {index} returned an unexpected destination match")
                    if field.attrib["name"] != "csp.destination" and result.returncode != 0:
                        raise SystemExit(f"Case {index} failed an input field match")
        print(f"Case {index} passed")

    mode = "Wazuh logtest and normalization" if args.logtest else "offline PCRE2 and normalization"
    print(f"{len(CASES)}/{len(CASES)} passed ({mode})")


if __name__ == "__main__":
    main()
