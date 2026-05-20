"""
Build a decoder training dataset using real log samples from Wazuh rules-testing suites
plus optional local correction examples.

Primary source: data/wazuh_ruleset_repo/tools/rules-testing/tests/*.ini
Optional source: data/datasets/feedback.jsonl

Output records include the decoder pattern text used during inference so the embedding
model learns to retrieve regex/order/prematch-rich candidates instead of decoder names
alone.
"""

from __future__ import annotations

import json
import os
import random
import sys
from pathlib import Path
from typing import Dict, List, Tuple

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))  # allow `app` imports when running as a script

from app.decoder_ml import DecoderPattern, load_patterns_from_repo

OUT_DIR = BASE_DIR / "data" / "datasets"
TESTS_DIR = BASE_DIR / "data" / "wazuh_ruleset_repo" / "tools" / "rules-testing" / "tests"
REPO_DIR = BASE_DIR / "data" / "wazuh_ruleset_repo"
DECODER_SUBPATH = os.getenv("WAZUH_REPO_DECODER_SUBPATH", "decoders")
FEEDBACK_PATH = BASE_DIR / "data" / "datasets" / "feedback.jsonl"


def build_pattern_lookup(patterns: List[DecoderPattern]) -> Dict[str, List[DecoderPattern]]:
    lookup: Dict[str, List[DecoderPattern]] = {}
    for pattern in patterns:
        lookup.setdefault(pattern.name, []).append(pattern)
    return lookup


def serialize_pattern(pattern: DecoderPattern) -> Dict:
    return {
        "name": pattern.name,
        "parent": pattern.parent,
        "program_name": pattern.program_name,
        "prematch": pattern.prematch,
        "regex": pattern.regex,
        "order": pattern.order,
        "source_file": pattern.source_file,
        "feature_text": pattern.feature_text,
    }


def parse_rules_testing_tests(tests_dir: Path, pattern_lookup: Dict[str, List[DecoderPattern]]) -> List[Dict]:
    """
    Parse Wazuh rules-testing .ini scenarios into log/decoder pairs.
    """
    records: List[Dict] = []

    for ini_path in sorted(tests_dir.glob("*.ini")):
        section_name = None
        logs: List[str] = []
        decoder_name: str | None = None
        rule_id: str | None = None

        def resolve_pattern() -> DecoderPattern | None:
            if not decoder_name:
                return None
            candidates = pattern_lookup.get(decoder_name, [])
            if not candidates:
                return None
            source_hint = ini_path.stem.replace("_rules", "")
            for candidate in candidates:
                if source_hint in candidate.source_file:
                    return candidate
            return candidates[0]

        def flush():
            pattern = resolve_pattern()
            if decoder_name and logs:
                for log in logs:
                    record = {
                        "log": log.strip(),
                        "decoder": {"name": decoder_name, "source": ini_path.name},
                        "rule": {"id": rule_id, "description": section_name},
                    }
                    if pattern:
                        record["decoder_pattern"] = serialize_pattern(pattern)
                        record["target_text"] = pattern.feature_text
                    else:
                        record["target_text"] = decoder_name
                    records.append(record)

        for raw_line in ini_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line:
                # blank line marks end of a scenario
                flush()
                logs, decoder_name, rule_id, section_name = [], None, None, section_name
                continue
            if line.startswith("[") and line.endswith("]"):
                flush()
                section_name = line.strip("[]")
                logs, decoder_name, rule_id = [], None, None
                continue
            if line.lower().startswith("log"):
                # Format: log 1 pass = <logtext>
                if "=" in line:
                    logs.append(line.split("=", 1)[1].strip())
                continue
            if line.lower().startswith("decoder"):
                decoder_name = line.split("=", 1)[1].strip()
                continue
            if line.lower().startswith("rule"):
                rule_id = line.split("=", 1)[1].strip()
                continue

        # flush last block
        flush()

    return records


def load_feedback_records(path: Path) -> List[Dict]:
    if not path.exists():
        return []
    records: List[Dict] = []
    with path.open(encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            rec = json.loads(line)
            log = (rec.get("log") or "").strip()
            decoder = rec.get("decoder") or {}
            target_text = (rec.get("target_text") or "").strip()
            if not target_text and isinstance(decoder, dict):
                parts = [
                    decoder.get("name") or "",
                    decoder.get("parent") or "",
                    decoder.get("program_name") or "",
                    decoder.get("prematch") or "",
                    decoder.get("regex") or "",
                    " ".join(decoder.get("order") or []),
                    decoder.get("source_file") or "feedback",
                ]
                target_text = " ".join(part for part in parts if part).lower()
                rec["decoder_pattern"] = decoder
            if not log or not target_text:
                continue
            rec["log"] = log
            rec["target_text"] = target_text
            records.append(rec)
    return records


def train_val_split(records: List[Dict], val_ratio: float = 0.1) -> Tuple[List[Dict], List[Dict]]:
    random.shuffle(records)
    n_val = max(1, int(len(records) * val_ratio))
    return records[n_val:], records[:n_val]


def main() -> None:
    tests_dir = Path(os.getenv("WAZUH_RULES_TESTS_DIR", TESTS_DIR))
    if not tests_dir.exists():
        raise SystemExit(f"Rules-testing path not found: {tests_dir}")

    repo_dir = Path(os.getenv("WAZUH_REPO_CACHE_DIR", REPO_DIR))
    patterns = load_patterns_from_repo(repo_dir, DECODER_SUBPATH)
    pattern_lookup = build_pattern_lookup(patterns)

    records = parse_rules_testing_tests(tests_dir, pattern_lookup)
    records.extend(load_feedback_records(FEEDBACK_PATH))
    if not records:
        raise SystemExit(f"No records parsed from {tests_dir}")

    train, val = train_val_split(records)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "train.jsonl").write_text("\n".join(json.dumps(r) for r in train), encoding="utf-8")
    (OUT_DIR / "val.jsonl").write_text("\n".join(json.dumps(r) for r in val), encoding="utf-8")
    print(f"wrote {len(train)} train and {len(val)} val samples to {OUT_DIR}")


if __name__ == "__main__":
    main()
