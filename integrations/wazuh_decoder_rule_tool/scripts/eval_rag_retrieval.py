#!/usr/bin/env python3
"""Measure RAG retrieval precision, with and without verified log examples.

Every verified sample whose exact text was indexed as a doc's log_example is
excluded: querying with a string that is verbatim in the store measures
memorisation, not retrieval. Only held-out samples are scored, so the two
configurations are compared on logs neither of them has seen.

A hit means the retrieved doc's <decoder name=...> (or its <parent>) is the
decoder wazuh-logtest actually assigned to that log.

Usage:
    python3 scripts/eval_rag_retrieval.py [--top-k 3]
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import rag_engine as R  # noqa: E402

_NAME_RE = re.compile(r'<decoder name="([^"]+)"')
BASELINE_COLLECTION = "wazuh_decoders_nolog_eval"


def doc_decoder_names(meta: Dict[str, Any]) -> Set[str]:
    return set(_NAME_RE.findall(meta.get("decoder_xml") or ""))


def load_samples() -> List[Dict[str, Any]]:
    rows = []
    with R._VERIFIED_SAMPLES.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def build_baseline_collection(client, ef):
    """Re-index the same decoders with the pre-change embedding text."""
    # Emptying the cache makes _parse_decoder_xml_file emit docs with no
    # log_example, which reproduces the old metadata-only embed text exactly.
    saved = R._verified_samples_cache
    R._verified_samples_cache = {}
    try:
        docs = []
        for xml_file in sorted(R._DECODER_DIR.glob("*.xml")):
            docs.extend(R._parse_decoder_xml_file(xml_file))
    finally:
        R._verified_samples_cache = saved

    try:
        client.delete_collection(BASELINE_COLLECTION)
    except Exception:
        pass
    coll = client.get_or_create_collection(
        name=BASELINE_COLLECTION, embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )
    seen, unique = set(), []
    for doc in docs:
        if doc["id"] not in seen:
            seen.add(doc["id"])
            unique.append(doc)
    for i in range(0, len(unique), 200):
        batch = unique[i : i + 200]
        coll.upsert(
            ids=[d["id"] for d in batch],
            documents=[d["text"] for d in batch],
            metadatas=[{"decoder_xml": d["decoder_xml"][:2000],
                        "source": d.get("source", "")[:100]} for d in batch],
        )
    return coll, len(unique)


def score(coll, samples: List[Dict[str, Any]], top_k: int) -> Dict[str, Any]:
    hits1 = hitsk = 0
    per_file = collections.Counter()
    per_file_total = collections.Counter()

    # Query in batches; chroma accepts many query_texts at once.
    for start in range(0, len(samples), 100):
        batch = samples[start : start + 100]
        res = coll.query(query_texts=[s["log"] for s in batch],
                         n_results=top_k, include=["metadatas"])
        for sample, metas in zip(batch, res["metadatas"]):
            truth = {sample["decoder"]}
            if sample.get("parent"):
                truth.add(sample["parent"])
            ranked = [doc_decoder_names(m) for m in metas]
            top1 = bool(ranked and (ranked[0] & truth))
            topk = any(names & truth for names in ranked)
            hits1 += top1
            hitsk += topk
            per_file_total[sample["ini_file"]] += 1
            if topk:
                per_file[sample["ini_file"]] += 1

    n = len(samples) or 1
    return {"n": len(samples),
            "p@1": hits1 / n,
            f"recall@{top_k}": hitsk / n,
            "per_file": per_file, "per_file_total": per_file_total}


def score_production(samples: List[Dict[str, Any]], top_k: int) -> Dict[str, Any]:
    """Score the real retrieve() path, dedup and all.

    score() queries chroma directly, so it can't see whether dedup pushes a
    correct sibling out of the top_k window — which is exactly the risk that
    dedup introduces.
    """
    hits1 = hitsk = 0
    for sample in samples:
        got = R.retrieve(sample["log"], top_k=top_k)
        truth = {sample["decoder"]}
        if sample.get("parent"):
            truth.add(sample["parent"])
        ranked = [doc_decoder_names(e) for e in got]
        hits1 += bool(ranked and (ranked[0] & truth))
        hitsk += any(names & truth for names in ranked)
    n = len(samples) or 1
    return {"p@1": hits1 / n, f"recall@{top_k}": hitsk / n}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--top-k", type=int, default=3)
    args = ap.parse_args()

    status = R.build_store(force=False)
    if status.get("status") != "ok":
        sys.exit(f"RAG store unavailable: {status}")
    current = R._collection

    indexed_examples = {
        (m.get("log_example") or "").strip()
        for m in current.get(include=["metadatas"])["metadatas"]
    }
    indexed_examples.discard("")

    samples = load_samples()
    heldout = [s for s in samples if s["log"].strip() not in indexed_examples]
    print(f"verified samples: {len(samples)}")
    print(f"held out (not indexed as any log_example): {len(heldout)}")

    # Logs that Wazuh handles with its builtin `json` decoder need no custom
    # decoder at all, so "which XML decoder should we retrieve" has no correct
    # answer for them. Scoring them would just move the headline number around
    # without telling us anything about the case the tool exists to serve.
    text_only = [s for s in heldout if s["decoder"] != "json"]
    builtin_json = len(heldout) - len(text_only)
    print(f"  of which builtin-json (excluded from the headline): {builtin_json}")
    print(f"  scored (logs needing a real text decoder): {len(text_only)}")
    if not text_only:
        sys.exit("nothing held out -- cannot evaluate honestly")

    ef = R._get_embedding_function()
    baseline, n_docs = build_baseline_collection(R._chroma_client, ef)
    print(f"baseline collection re-indexed with metadata-only text: {n_docs} docs\n")

    k = f"recall@{args.top_k}"
    for label, subset in (("logs needing a text decoder", text_only),
                          ("all held-out logs", heldout)):
        before = score(baseline, subset, args.top_k)
        after = score(current, subset, args.top_k)
        print(f"\n== {label} (n={len(subset)})")
        print(f"{'config':<28}{'p@1':>9}{k:>12}")
        print("-" * 49)
        print(f"{'metadata only (before)':<28}{before['p@1']:>8.1%}{before[k]:>12.1%}")
        print(f"{'+ verified log example':<28}{after['p@1']:>8.1%}{after[k]:>12.1%}")
        print(f"{'delta':<28}{after['p@1']-before['p@1']:>+8.1%}{after[k]-before[k]:>+12.1%}")
        if subset is text_only:
            after_text = after
            prod = score_production(subset, args.top_k)
            print(f"{'+ dedup (production path)':<28}{prod['p@1']:>8.1%}{prod[k]:>12.1%}")

    print(f"\nworst text-decoder log sources after the change (recall@{args.top_k}, n>=10):")
    rows = []
    for f, total in after_text["per_file_total"].items():
        if total >= 10:
            rows.append((after_text["per_file"][f] / total, f, after_text["per_file"][f], total))
    for rate, f, hit, total in sorted(rows)[:10]:
        print(f"  {rate:6.1%}  {f:<34} {hit}/{total}")

    try:
        R._chroma_client.delete_collection(BASELINE_COLLECTION)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
