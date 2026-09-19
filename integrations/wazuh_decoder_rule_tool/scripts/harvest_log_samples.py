#!/usr/bin/env python3
"""Harvest real log samples from the Wazuh ruleset test suite and verify them
against wazuh-logtest, so the RAG store can be indexed with (log -> decoder ->
fields) triples that are known to actually hold on this Wazuh version.

Without a log_example, a RAG hit only teaches the LLM decoder *style* -- it
cannot teach the log -> regex mapping, which is the part that matters. The .ini
files under ruleset/testing/tests carry the samples the Wazuh project itself
uses as ground truth; this script pairs each one with what logtest really
reports, and drops any pair that does not verify.

Usage:
    python3 scripts/harvest_log_samples.py [--limit N] [--out PATH]
"""
from __future__ import annotations

import argparse
import collections
import configparser
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterator, List

REPO_ROOT = Path(__file__).resolve().parent.parent
REPO_CACHE = REPO_ROOT / "data" / "wazuh_repo"
TESTS_DIR = REPO_CACHE / "ruleset" / "testing" / "tests"
DEFAULT_OUT = REPO_ROOT / "data" / "verified_log_samples.jsonl"
LOGTEST_BIN = "/var/ossec/bin/wazuh-logtest"

# How many logs to push through a single logtest session. Batching amortises
# the ~1s process startup over many samples; keeping it bounded stops one
# malformed log from taking a huge chunk of work down with it.
CHUNK_SIZE = 200
CHUNK_TIMEOUT = 300


class MultiOrderedDict(collections.OrderedDict):
    """Same trick runtests.py uses: keep every duplicate key in a list."""

    def __setitem__(self, key, value):
        if isinstance(value, list) and key in self:
            self[key].extend(value)
        else:
            super().__setitem__(key, value)


def parse_ini(path: Path) -> Iterator[Dict[str, Any]]:
    parser = configparser.RawConfigParser(dict_type=MultiOrderedDict, strict=False)
    try:
        parser.read(str(path))
    except Exception as exc:  # a malformed file should not sink the whole run
        print(f"  ! skipping {path.name}: {exc}", file=sys.stderr)
        return

    for section in parser.sections():
        items = dict(parser.items(section))

        def scalar(name: str) -> str:
            raw = items.get(name, "")
            if isinstance(raw, list):
                raw = raw[-1] if raw else ""
            return str(raw).strip()

        decoder = scalar("decoder")
        rule = scalar("rule")
        alert = scalar("alert")

        for key, raw in items.items():
            if not key.startswith("log ") or not key.endswith("pass"):
                continue
            values = raw if isinstance(raw, list) else [raw]
            for value in values:
                # A repeated "log 1 pass" key inside one section gets collapsed
                # by MultiOrderedDict into a single newline-joined value. Each
                # line is an independent sample, and logtest reads one log per
                # line anyway, so split rather than skip -- treating these as
                # one blob silently dropped ~300 samples.
                for line in str(value).splitlines():
                    log = line.strip()
                    if not log:
                        continue
                    yield {
                        "log": log,
                        "expected_decoder": decoder,
                        "expected_rule": rule,
                        "expected_alert": alert,
                        "ini_file": path.name,
                        "section": section,
                    }


_PHASE1_EVENT = re.compile(r"^\tfull event: '(?P<event>.*)'$")
_FIELD = re.compile(r"^\t(?P<key>[\w.\-]+): '(?P<value>.*)'$")


def parse_logtest_output(text: str) -> List[Dict[str, Any]]:
    """Return one result block per input log, in input order.

    Alignment is positional: logtest emits exactly one "**Phase 1" block per
    line it reads. Keying on the echoed `full event` instead looks safer but
    silently loses every JSON log -- for those, Phase 1 prints no full-event
    line at all. `full_event` is still recorded so the caller can assert
    alignment on the (majority) syslog-shaped samples.
    """
    results: List[Dict[str, Any]] = []
    current: Dict[str, Any] | None = None
    phase = 0

    for line in text.splitlines():
        if line.startswith("**Phase 1"):
            current = {"full_event": None, "decoder": "", "parent": "",
                       "fields": {}, "rule": "", "level": ""}
            results.append(current)
            phase = 1
            continue
        if line.startswith("**Phase 2"):
            phase = 2
            continue
        if line.startswith("**Phase 3"):
            phase = 3
            continue

        if current is None:
            continue

        if phase == 1:
            match = _PHASE1_EVENT.match(line)
            if match:
                current["full_event"] = match.group("event")
            continue

        match = _FIELD.match(line)
        if not match:
            continue
        key, value = match.group("key"), match.group("value")

        if phase == 2:
            if key == "name":
                current["decoder"] = value
            elif key == "parent":
                current["parent"] = value
            else:
                current["fields"][key] = value
        elif phase == 3:
            if key == "id":
                current["rule"] = value
            elif key == "level":
                current["level"] = value

    return results


def run_logtest(logs: List[str]) -> List[Dict[str, Any]]:
    """Feed one chunk through logtest; returns blocks aligned to `logs`.

    Returns [] on any misalignment rather than guessing, so a bad chunk shows
    up in the stats instead of quietly attaching the wrong decoder to a log.
    """
    payload = "".join(log + "\n" for log in logs)
    try:
        proc = subprocess.run(
            [LOGTEST_BIN], input=payload, text=True,
            capture_output=True, timeout=CHUNK_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        print(f"  ! logtest timed out on a {len(logs)}-log chunk", file=sys.stderr)
        return []
    except FileNotFoundError:
        sys.exit(f"{LOGTEST_BIN} not found -- run this on the Wazuh manager.")

    blocks = parse_logtest_output((proc.stdout or "") + (proc.stderr or ""))
    if len(blocks) != len(logs):
        print(f"  ! logtest returned {len(blocks)} blocks for {len(logs)} logs "
              f"-- dropping chunk", file=sys.stderr)
        return []

    for log, block in zip(logs, blocks):
        echoed = block.get("full_event")
        if echoed is not None and echoed != log:
            print(f"  ! alignment check failed: expected {log[:60]!r} "
                  f"got {echoed[:60]!r} -- dropping chunk", file=sys.stderr)
            return []
    return blocks


def ensure_tests_checkout() -> None:
    """Add ruleset/testing to the cached repo's sparse checkout if it's absent.

    refresh_wazuh_repo() pins the sparse checkout to ruleset/decoders, and a
    forced refresh re-clones from scratch -- so the test samples vanish exactly
    when someone updates the ruleset. Re-adding the path here keeps this script
    runnable without changing what the ML refresh downloads for everyone.
    """
    if TESTS_DIR.is_dir():
        return
    if not (REPO_CACHE / ".git").exists():
        sys.exit(f"{REPO_CACHE} is not a git checkout -- run the ML repo refresh first.")

    print(f"{TESTS_DIR.relative_to(REPO_ROOT)} missing — adding it to the sparse checkout")
    proc = subprocess.run(
        ["git", "-C", str(REPO_CACHE), "sparse-checkout", "add", "ruleset/testing"],
        text=True, capture_output=True, timeout=120,
    )
    if proc.returncode != 0:
        sys.exit(f"sparse-checkout add failed: {proc.stderr.strip()}")
    if not TESTS_DIR.is_dir():
        sys.exit(f"{TESTS_DIR} still missing after sparse-checkout add")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="cap samples (0 = all)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()

    ensure_tests_checkout()

    samples: List[Dict[str, Any]] = []
    for ini in sorted(TESTS_DIR.glob("*.ini")):
        samples.extend(parse_ini(ini))
    if args.limit:
        samples = samples[: args.limit]
    print(f"parsed {len(samples)} pass-samples from {len(list(TESTS_DIR.glob('*.ini')))} ini files")

    verified: List[Dict[str, Any]] = []
    stats = collections.Counter()

    for start in range(0, len(samples), CHUNK_SIZE):
        chunk = samples[start : start + CHUNK_SIZE]
        reported = run_logtest([s["log"] for s in chunk])
        print(f"  logtest {start + len(chunk)}/{len(samples)}", flush=True)

        if not reported:
            stats["chunk_dropped"] += len(chunk)
            continue

        for sample, got in zip(chunk, reported):

            actual = got["decoder"]
            if not actual:
                stats["undecoded"] += 1
                continue

            # The .ini names the decoder whose <name> should win Phase 2. A
            # child decoder reports its own name, so accept a parent match too.
            expected = sample["expected_decoder"]
            if expected and actual != expected and got["parent"] != expected:
                stats["decoder_mismatch"] += 1
                continue

            stats["verified"] += 1
            if got["fields"]:
                stats["verified_with_fields"] += 1

            verified.append({
                "log": sample["log"],
                "decoder": actual,
                "parent": got["parent"],
                "fields": got["fields"],
                "field_names": sorted(got["fields"]),
                "rule": got["rule"],
                "level": got["level"],
                "expected_decoder": expected,
                "expected_rule": sample["expected_rule"],
                "rule_matches_expected": bool(
                    sample["expected_rule"] and got["rule"] == sample["expected_rule"]
                ),
                "ini_file": sample["ini_file"],
                "section": sample["section"],
            })

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        for row in verified:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"\nwrote {len(verified)} verified samples -> {args.out}")
    for key, count in stats.most_common():
        print(f"  {key}: {count}")
    decoders = {row["decoder"] for row in verified}
    parents = {row["parent"] for row in verified if row["parent"]}
    print(f"  distinct decoders covered: {len(decoders | parents)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
