#!/usr/bin/env python3
"""Measure what retrieval-proposed <order> fields actually recover.

Ground truth is wazuh-logtest's own Phase 2 output for each verified sample
(data/verified_log_samples.jsonl), so "recovered" means a field real Wazuh
extracts that the local heuristics alone did not produce -- not a field the
model merely claimed.

Reports both directions, because only one of them is good news:
  recovered      - truth fields the proposal path added
  false addition - fields it added that logtest never extracted

Usage:
    python3 scripts/eval_ml_order_proposals.py [--limit N]
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.main import (  # noqa: E402
    canonicalize_field_name,
    choose_log_driven_fields,
    ml_suggestions_for_logs,
    parse_phase1_predecode,
    select_ml_decoder_template,
)

CORPUS = BASE_DIR / "data" / "verified_log_samples.jsonl"

# Wazuh resolves <order>user</order> onto dstuser, so the two spellings name the
# same captured value and must not count as a miss against each other.
_EQUIVALENT = {"dstuser": "user"}


def norm(name: str) -> str:
    canonical = canonicalize_field_name(name)
    return _EQUIVALENT.get(canonical, canonical)


def norm_set(names) -> Set[str]:
    return {norm(n) for n in names if str(n).strip()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    if not CORPUS.exists():
        sys.exit(f"{CORPUS} missing -- run scripts/harvest_log_samples.py first.")

    rows: List[Dict[str, Any]] = []
    with CORPUS.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    # Only samples where logtest extracted something can show a difference.
    rows = [r for r in rows if r.get("field_names")]
    if args.limit:
        rows = rows[: args.limit]
    print(f"scoring {len(rows)} verified samples with extracted fields\n")

    stats = collections.Counter()
    recovered_names = collections.Counter()
    false_names = collections.Counter()
    base_hits = new_hits = truth_total = 0

    for i, row in enumerate(rows, 1):
        log = row["log"]
        truth = norm_set(row["field_names"])

        try:
            predecoded = parse_phase1_predecode(log)
            suggestions = ml_suggestions_for_logs(
                [log], predecoded.get("program_name"), predecoded.get("body") or log
            )
            selected = select_ml_decoder_template([log], [], suggestions)
            ml_order = (selected or {}).get("order") or []

            base_order = norm_set(choose_log_driven_fields([log], [], ml_order=None)[1])
            new_order = norm_set(choose_log_driven_fields([log], [], ml_order=ml_order)[1])
        except Exception as exc:
            stats["errored"] += 1
            if stats["errored"] <= 3:
                print(f"  ! {type(exc).__name__} on sample {i}: {exc}")
            continue

        truth_total += len(truth)
        base_hits += len(base_order & truth)
        new_hits += len(new_order & truth)

        added = new_order - base_order
        for name in added & truth:
            stats["recovered"] += 1
            recovered_names[name] += 1
        for name in added - truth:
            stats["false_addition"] += 1
            false_names[name] += 1
        if added & truth:
            stats["samples_improved"] += 1
        if added - truth:
            stats["samples_with_false_addition"] += 1
        stats["scored"] += 1

        if i % 200 == 0:
            print(f"  {i}/{len(rows)}", flush=True)

    scored = stats["scored"] or 1
    print(f"\nsamples scored: {stats['scored']}  (errored: {stats['errored']})")
    print(f"truth field recall  baseline: {base_hits}/{truth_total} "
          f"({base_hits / max(1, truth_total):.1%})")
    print(f"truth field recall  proposals: {new_hits}/{truth_total} "
          f"({new_hits / max(1, truth_total):.1%})")
    print(f"\nsamples improved: {stats['samples_improved']} ({stats['samples_improved']/scored:.1%})")
    print(f"samples with a false addition: {stats['samples_with_false_addition']} "
          f"({stats['samples_with_false_addition']/scored:.1%})")
    print(f"fields recovered: {stats['recovered']}   false additions: {stats['false_addition']}")

    if recovered_names:
        print("\nmost recovered fields:")
        for name, count in recovered_names.most_common(10):
            print(f"  {count:5d}  {name}")
    if false_names:
        print("\nmost common false additions:")
        for name, count in false_names.most_common(10):
            print(f"  {count:5d}  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
