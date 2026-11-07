#!/usr/bin/env python3
"""Replay Agentmetry's attack corpus through a scratch recorder and keep samples.

Run with the Python that has `agentmetry` installed, against a recorder started
only for this purpose. The sessions are the scripted attack cases that ship with
the package, posted to the real ingest route, so every line kept here was written
and hash-chained by the recorder. They are not a live agent session.
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import yaml
from agentmetry.core.audit.detection.benchmark import DEFAULT_CORPUS_DIR

_TOOL_KEYS = ("qualified", "server", "arguments", "input_hash", "command", "traits", "mitre", "classification")
_PASSTHROUGH = ("gated_action", "dlp", "tool_policy", "initiator", "skill_id")


def attack_sessions() -> list[tuple[str, Path]]:
    corpus = yaml.safe_load((DEFAULT_CORPUS_DIR / "corpus.yaml").read_text(encoding="utf-8"))
    return [(c["name"], DEFAULT_CORPUS_DIR / c["session"]) for c in corpus["cases"] if c.get("expect")]


def to_payload(event: dict[str, Any]) -> dict[str, Any]:
    """Turn a stored canonical event back into what a capture surface posts."""
    action = event.get("action") or {}
    source = event.get("source") or {}
    payload: dict[str, Any] = {
        "source_app": source.get("app", "cursor"),
        "event_type": action.get("type", "tool_called"),
        "outcome": action.get("outcome", ""),
        "reason": action.get("reason", ""),
        "adapter": source.get("adapter", ""),
        "correlation_id": event.get("correlation_id", ""),
        "session_id": event.get("session_id", ""),
        "timestamp_utc": event.get("timestamp_utc", ""),
    }
    tool = event.get("tool")
    if isinstance(tool, dict):
        payload["tool"] = {k: tool[k] for k in _TOOL_KEYS if tool.get(k) not in (None, "")}
    for key in _PASSTHROUGH:
        if event.get(key):
            payload[key] = event[key]
    return payload


def post(base_url: str, payload: dict[str, Any]) -> None:
    request = urllib.request.Request(
        f"{base_url}/api/v1/audit/ingest",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    for _attempt in range(30):
        try:
            with urllib.request.urlopen(request, timeout=30):
                return
        except urllib.error.HTTPError as exc:
            if exc.code != 429:
                raise
            time.sleep(float(exc.headers.get("Retry-After") or 1))
    raise RuntimeError("ingest kept answering 429")


def _parse_rules(rules_xml: Path) -> list[ET.Element]:
    root = ET.fromstring("<root>" + rules_xml.read_text(encoding="utf-8") + "</root>")
    return list(root.iter("rule"))


def expected_rules(
    rules: list[ET.Element],
) -> tuple[dict[tuple[str, str], tuple[str, str]], dict[str, tuple[str, str]]]:
    """Read the shipped rules, so the test cases cannot drift from them."""
    by_rule: dict[tuple[str, str], tuple[str, str]] = {}
    by_severity: dict[str, tuple[str, str]] = {}
    severity_of: dict[str, str] = {}
    for rule in rules:
        for field in rule.findall("field"):
            if field.get("name") == "event.action.outcome":
                severity = field.text.strip("^$")
                by_severity[severity] = (rule.get("id"), rule.get("level"))
                severity_of[rule.get("id")] = severity
    for rule in rules:
        for field in rule.findall("field"):
            if field.get("name") == "event.detection.rule_id":
                severity = severity_of[rule.findtext("if_sid").strip()]
                by_rule[(field.text.strip("^$"), severity)] = (rule.get("id"), rule.get("level"))
    return by_rule, by_severity


def write_samples(trail: Path, rules_xml: Path, out_dir: Path) -> list[str]:
    rules = _parse_rules(rules_xml)
    by_rule, by_severity = expected_rules(rules)
    seen: dict[tuple[str, str], str] = {}
    activity: str | None = None
    for line in trail.read_text(encoding="utf-8").splitlines():
        event = json.loads(line).get("event", {})
        action = event.get("action", {})
        if action.get("type") == "detection":
            seen.setdefault((event["detection"]["rule_id"], action["outcome"]), line)
        elif activity is None and action.get("type") == "tool_called":
            activity = line
    if activity is None or not seen:
        raise SystemExit("the trail holds no activity or no detections; nothing to sample")

    lines = [activity]
    ini = [
        ";  Tests for products:",
        ";    Agentmetry",
        ";",
        ";  Sample logs source:",
        ";    Written and hash-chained by a real Agentmetry recorder from its scripted attack corpus.",
        "",
        "[Agentmetry: tool call activity, no alert.]",
        f"log 1 pass = {activity}",
        f"rule = {rules[0].get('id')}",
        "alert = 0",
        "decoder = json",
        "",
    ]
    report = []
    for (rule_id, severity), line in sorted(seen.items()):
        specific = by_rule.get((rule_id, severity))
        expected = specific or by_severity[severity]
        report.append(f"{rule_id} {severity} -> {expected[0]}{'' if specific else ' (severity fallback)'}")
        lines.append(line)
        ini += [
            f"[Agentmetry: {severity} detection {rule_id}.]",
            f"log 1 pass = {line}",
            f"rule = {expected[0]}",
            f"alert = {expected[1]}",
            "decoder = json",
            "",
        ]
    for rule_id, severity in sorted(set(by_rule) - set(seen)):
        report.append(f"NOT CAPTURED: {rule_id} {severity}")
    (out_dir / "sample_logs.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out_dir / "agentmetry.ini").write_text("\n".join(ini), encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8123")
    parser.add_argument("--trail", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    for _name, path in attack_sessions():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                post(args.base_url, to_payload(json.loads(line)))
    time.sleep(2)
    print("\n".join(write_samples(args.trail, args.rules, args.out)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
