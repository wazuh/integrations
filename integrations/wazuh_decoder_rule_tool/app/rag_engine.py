"""
RAG Engine for Wazuh Decoder Rule Tool.

Builds a ChromaDB vector store from:
  1. Official Wazuh decoder XML files (data/wazuh_repo/ruleset/decoders/)
  2. Approved feedback pairs (data/datasets/feedback.jsonl)
  3. Training pairs (data/datasets/train.jsonl)

Exposes retrieve(log_line, fields, top_k) which returns real decoder
examples to inject into the LLM prompt as grounding context.
"""

from __future__ import annotations

import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from xml.sax.saxutils import escape as _xml_escape

logger = logging.getLogger("rag_engine")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_BASE = Path(__file__).resolve().parent.parent
_DECODER_DIR = _BASE / "data" / "wazuh_repo" / "ruleset" / "decoders"
_FEEDBACK_JSONL = _BASE / "data" / "datasets" / "feedback.jsonl"
_TRAIN_JSONL = _BASE / "data" / "datasets" / "train.jsonl"
_RAG_STORE_DIR = _BASE / "data" / "rag_store"
_SBERT_MODEL_DIR = _BASE / "data" / "models" / "decoder-sbert" / "final"
# Real log samples harvested from the Wazuh ruleset test suite and confirmed
# against wazuh-logtest. Produced by scripts/harvest_log_samples.py.
_VERIFIED_SAMPLES = _BASE / "data" / "verified_log_samples.jsonl"

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
_chroma_client = None
_collection = None
_store_built = False


def _get_chroma():
    """Lazy-import chromadb so the app doesn't break if it's not installed."""
    try:
        import chromadb
        return chromadb
    except ImportError:
        logger.warning("chromadb not installed — RAG disabled. Run: pip install chromadb")
        return None


def _get_embedding_function():
    """Return a ChromaDB-compatible embedding function using the local SBERT model."""
    chromadb = _get_chroma()
    if chromadb is None:
        return None
    try:
        from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
        # Use local fine-tuned model if available, else fall back to a small public model
        if _SBERT_MODEL_DIR.exists():
            model_name = str(_SBERT_MODEL_DIR)
        else:
            model_name = "all-MiniLM-L6-v2"
        logger.info(f"RAG: Using embedding model: {model_name}")
        return SentenceTransformerEmbeddingFunction(model_name=model_name)
    except Exception as e:
        logger.warning(f"RAG: Could not load embedding function: {e}")
        return None


# ---------------------------------------------------------------------------
# Document builders
# ---------------------------------------------------------------------------

def _build_decoder_text(name: str, parent: str, prematch: str,
                        program_name: str, regex: str, order: str,
                        log_example: str = "") -> str:
    """Produce a flat text representation for embedding.

    The log sample leads, because retrieval queries with a raw log line —
    embedding only decoder metadata (regex/order/prematch) meant comparing a
    log against OS_Regex syntax, which is why official decoders scored barely
    above unrelated feedback rows.
    """
    parts = []
    if log_example:
        parts.append(log_example)
    if name:
        parts.append(f"decoder:{name}")
    if parent:
        parts.append(f"parent:{parent}")
    if program_name:
        parts.append(f"program:{program_name}")
    if prematch:
        parts.append(f"prematch:{prematch}")
    if regex:
        parts.append(f"regex:{regex}")
    if order:
        parts.append(f"fields:{order}")
    return " ".join(parts)


_verified_samples_cache: Optional[Dict[str, List[Dict[str, Any]]]] = None


def _load_verified_samples() -> Dict[str, List[Dict[str, Any]]]:
    """Index verified log samples by the decoder name that claimed them.

    A sample is filed under both its own decoder and its parent, because an
    official doc is keyed on the child decoder in some files and the parent in
    others. Returns {} when the corpus hasn't been harvested yet, which just
    means docs keep their previous (empty) log_example.
    """
    global _verified_samples_cache
    if _verified_samples_cache is not None:
        return _verified_samples_cache

    index: Dict[str, List[Dict[str, Any]]] = {}
    if not _VERIFIED_SAMPLES.exists():
        logger.info(
            "RAG: %s absent — indexing decoders without log examples. "
            "Run scripts/harvest_log_samples.py to generate it.",
            _VERIFIED_SAMPLES.name,
        )
        _verified_samples_cache = index
        return index

    count = 0
    with _VERIFIED_SAMPLES.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            log = (row.get("log") or "").strip()
            if not log:
                continue
            entry = {"log": log, "field_names": set(row.get("field_names") or [])}
            for key in {row.get("decoder"), row.get("parent")}:
                if key:
                    index.setdefault(key, []).append(entry)
            count += 1

    logger.info(f"RAG: loaded {count} verified log samples covering {len(index)} decoder names")
    _verified_samples_cache = index
    return index


def _pick_log_example(child_name: str, parent_name: str, fields: List[str]) -> str:
    """Best verified sample for one parent+child decoder pair.

    Sibling decoders share a name, so a name-only match would attach the same
    log to every variant in a file. logtest told us which fields each sample
    actually produced, so prefer the sample whose extracted fields overlap this
    decoder's <order> — that picks the variant the log really exercises.
    """
    index = _load_verified_samples()
    candidates: List[Dict[str, Any]] = []
    for key in (child_name, parent_name):
        if key:
            candidates.extend(index.get(key, []))
    if not candidates:
        return ""

    wanted = {f.strip() for f in fields if f.strip()}
    if not wanted:
        # No <order> to discriminate on (e.g. a prematch-only decoder); any
        # sample that reached this decoder is a fair illustration.
        return candidates[0]["log"]

    def overlap(entry: Dict[str, Any]) -> Tuple[int, int]:
        common = wanted & entry["field_names"]
        # Tie-break toward the sample with the fewest extra fields, so the
        # example stays close to what this decoder alone is responsible for.
        return len(common), -len(entry["field_names"] - wanted)

    best = max(candidates, key=overlap)
    return best["log"] if (wanted & best["field_names"]) else candidates[0]["log"]


def _parse_decoder_xml_file(xml_path: Path) -> List[Dict[str, Any]]:
    """Parse one XML file and return a list of decoder document dicts."""
    docs: List[Dict[str, Any]] = []
    try:
        content = xml_path.read_text(encoding="utf-8", errors="replace")
        # Strip XML comments before parsing
        content_clean = re.sub(r"<!--.*?-->", "", content, flags=re.DOTALL)
        root = ET.fromstring(f"<root>{content_clean}</root>")
    except Exception:
        return docs

    # Group decoders by name to build parent→children pairs
    parent_map: Dict[str, Dict] = {}
    children: List[Dict] = []

    for elem in root.findall("decoder"):
        name = elem.get("name", "")
        parent_el = elem.find("parent")
        parent_name = parent_el.text.strip() if parent_el is not None and parent_el.text else ""
        pn_el = elem.find("program_name")
        program_name = pn_el.text.strip() if pn_el is not None and pn_el.text else ""
        pm_el = elem.find("prematch")
        prematch = pm_el.text.strip() if pm_el is not None and pm_el.text else ""
        rx_el = elem.find("regex")
        regex = rx_el.text.strip() if rx_el is not None and rx_el.text else ""
        ord_el = elem.find("order")
        order = ord_el.text.strip() if ord_el is not None and ord_el.text else ""

        if not parent_name:
            parent_map[name] = {
                "name": name,
                "program_name": program_name,
                "prematch": prematch,
                "source_file": xml_path.name,
            }
        else:
            children.append({
                "name": name,
                "parent": parent_name,
                "regex": regex,
                "order": order,
                "source_file": xml_path.name,
            })

    # Emit one document per child decoder, enriched with its parent info
    seen_ids: set = set()
    for child in children:
        pinfo = parent_map.get(child["parent"], {})
        doc_id = f"{xml_path.stem}::{child['parent']}::{child['name']}::{child['regex'][:40]}"
        if doc_id in seen_ids:
            continue
        seen_ids.add(doc_id)

        # Build the XML string for this parent+child pair
        parent_xml = f'<decoder name="{_xml_escape(child["parent"], {chr(34): "&quot;"})}">\n'
        if pinfo.get("program_name"):
            parent_xml += f'  <program_name>{_xml_escape(pinfo["program_name"])}</program_name>\n'
        elif pinfo.get("prematch"):
            parent_xml += f'  <prematch>{_xml_escape(pinfo["prematch"])}</prematch>\n'
        parent_xml += "</decoder>"

        child_xml = f'<decoder name="{_xml_escape(child["name"], {chr(34): "&quot;"})}">\n'
        child_xml += f'  <parent>{_xml_escape(child["parent"])}</parent>\n'
        if child.get("regex"):
            child_xml += f'  <regex>{_xml_escape(child["regex"])}</regex>\n'
        if child.get("order"):
            child_xml += f'  <order>{_xml_escape(child["order"])}</order>\n'
        child_xml += "</decoder>"

        full_xml = parent_xml + "\n\n" + child_xml
        fields = [f.strip() for f in child["order"].split(",") if f.strip()]
        log_example = _pick_log_example(child["name"], child["parent"], fields)
        embed_text = _build_decoder_text(
            name=child["name"],
            parent=child["parent"],
            prematch=pinfo.get("prematch", ""),
            program_name=pinfo.get("program_name", ""),
            regex=child["regex"],
            order=child["order"],
            log_example=log_example,
        )
        docs.append({
            "id": doc_id,
            "text": embed_text,
            "decoder_xml": full_xml,
            "fields": fields,
            "log_example": log_example,
            "source": f"official:{xml_path.name}",
        })
    return docs


def _encode_fields(fields: List[str], limit: int = 500) -> str:
    """JSON-encode a field list so it still parses after the size cap.

    Slicing the encoded string (the previous approach) could cut mid-element and
    leave `["a", "bc` behind, which made json.loads raise inside retrieve() and
    took the whole request down. Drop whole elements instead.
    """
    kept = list(fields)
    while kept:
        encoded = json.dumps(kept)
        if len(encoded) <= limit:
            return encoded
        kept.pop()
    return "[]"


def _parse_feedback_jsonl(jsonl_path: Path) -> List[Dict[str, Any]]:
    """Parse feedback.jsonl / train.jsonl and return document dicts."""
    docs: List[Dict[str, Any]] = []
    if not jsonl_path.exists():
        return docs
    for line in jsonl_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue

        # Skip rejected entries
        if obj.get("approved") is False:
            continue

        # Skip synthetic records mined from rejection notes (build_dataset.py
        # load_rejection_records): these are free-text human corrections, not
        # verified real decoders, and must never be surfaced to the LLM
        # prompt as a "Retrieved Real Wazuh Decoder Example".
        if obj.get("source") == "rejection_corrected":
            continue

        log_line = obj.get("log", "")
        decoder = obj.get("decoder", {})
        if not decoder:
            continue

        name = decoder.get("name", "custom")
        parent = decoder.get("parent", "")
        prematch = decoder.get("prematch", "")
        program_name = decoder.get("program_name", "")
        regex = decoder.get("regex", "")
        order = decoder.get("order", [])
        if isinstance(order, list):
            order_str = ", ".join(order)
        else:
            order_str = str(order)

        # Build XML — these values come from user-submitted feedback, so every
        # interpolated field must be escaped to avoid corrupting the document
        # structure (or injecting content into the LLM's grounding context).
        parent_xml = ""
        if parent:
            parent_xml = f'<decoder name="{_xml_escape(parent, {chr(34): "&quot;"})}">\n'
            if program_name:
                parent_xml += f"  <program_name>{_xml_escape(program_name)}</program_name>\n"
            elif prematch:
                parent_xml += f"  <prematch>{_xml_escape(prematch)}</prematch>\n"
            parent_xml += "</decoder>\n\n"

        child_xml = f'<decoder name="{_xml_escape(name, {chr(34): "&quot;"})}">\n'
        if parent:
            child_xml += f"  <parent>{_xml_escape(parent)}</parent>\n"
        if prematch and not parent:
            child_xml += f"  <prematch>{_xml_escape(prematch)}</prematch>\n"
        if regex:
            child_xml += f"  <regex>{_xml_escape(regex)}</regex>\n"
        if order_str:
            child_xml += f"  <order>{_xml_escape(order_str)}</order>\n"
        child_xml += "</decoder>"

        full_xml = parent_xml + child_xml

        embed_text = _build_decoder_text(
            name=name, parent=parent, prematch=prematch,
            program_name=program_name, regex=regex, order=order_str,
        )
        if log_line:
            embed_text = log_line + " " + embed_text

        fields = order if isinstance(order, list) else [f.strip() for f in order_str.split(",") if f.strip()]
        doc_id = f"feedback::{jsonl_path.stem}::{len(docs)}"
        docs.append({
            "id": doc_id,
            "text": embed_text,
            "decoder_xml": full_xml,
            "log_example": log_line,
            "fields": fields,
            "source": f"feedback:{jsonl_path.name}",
        })
    return docs


# ---------------------------------------------------------------------------
# Store management
# ---------------------------------------------------------------------------

def build_store(force: bool = False) -> Dict[str, Any]:
    """
    Build (or rebuild) the ChromaDB vector store.
    Returns a status dict.
    """
    global _chroma_client, _collection, _store_built

    chromadb = _get_chroma()
    if chromadb is None:
        return {"status": "error", "message": "chromadb not installed"}

    ef = _get_embedding_function()
    if ef is None:
        return {"status": "error", "message": "embedding function unavailable"}

    _RAG_STORE_DIR.mkdir(parents=True, exist_ok=True)
    _chroma_client = chromadb.PersistentClient(path=str(_RAG_STORE_DIR))

    # Delete existing collection if force rebuild
    if force:
        try:
            _chroma_client.delete_collection("wazuh_decoders")
        except Exception:
            pass

    _collection = _chroma_client.get_or_create_collection(
        name="wazuh_decoders",
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )

    existing_count = _collection.count()
    if existing_count > 0 and not force:
        logger.info(f"RAG: Store already has {existing_count} docs, skipping rebuild.")
        _store_built = True
        return {"status": "ok", "count": existing_count, "built": False}

    # Gather all documents
    all_docs: List[Dict[str, Any]] = []

    # 1. Official Wazuh decoders
    if _DECODER_DIR.exists():
        for xml_file in sorted(_DECODER_DIR.glob("*.xml")):
            all_docs.extend(_parse_decoder_xml_file(xml_file))
        logger.info(f"RAG: Loaded {len(all_docs)} docs from official decoder XMLs")

    # 2. Feedback / training JSONL
    for jsonl_path in [_FEEDBACK_JSONL, _TRAIN_JSONL]:
        fb_docs = _parse_feedback_jsonl(jsonl_path)
        all_docs.extend(fb_docs)
        logger.info(f"RAG: Loaded {len(fb_docs)} docs from {jsonl_path.name}")

    if not all_docs:
        return {"status": "error", "message": "No documents found to index"}

    # Deduplicate by id
    seen: set = set()
    unique_docs: List[Dict[str, Any]] = []
    for doc in all_docs:
        if doc["id"] not in seen:
            seen.add(doc["id"])
            unique_docs.append(doc)

    # Batch upsert into ChromaDB
    # ChromaDB metadata values have a ~41KB per-field limit; truncate decoder_xml to be safe
    MAX_XML_CHARS = 2000
    BATCH = 200
    total = 0
    for i in range(0, len(unique_docs), BATCH):
        batch = unique_docs[i : i + BATCH]
        try:
            _collection.upsert(
                ids=[d["id"] for d in batch],
                documents=[d["text"] for d in batch],
                metadatas=[
                    {
                        "decoder_xml": d["decoder_xml"][:MAX_XML_CHARS],
                        "fields": _encode_fields(d.get("fields", [])),
                        "log_example": d.get("log_example", "")[:300],
                        "source": d.get("source", "")[:100],
                    }
                    for d in batch
                ],
            )
            total += len(batch)
            logger.info(f"RAG: Upserted {total}/{len(unique_docs)} documents")
        except Exception as e:
            logger.warning(f"RAG: Batch {i}-{i+BATCH} failed: {e}")
            continue

    _store_built = True
    logger.info(f"RAG: Store built with {total} documents")
    return {"status": "ok", "count": total, "built": True}


def get_status() -> Dict[str, Any]:
    """Return the current status of the RAG store.

    Lazily attaches to the store, the same way retrieve() does. Without this,
    the endpoint reported ready=False/count=0 in any worker that hadn't served a
    retrieval yet, and kept reporting it after an out-of-process rebuild
    invalidated the cached handle -- so status disagreed with what retrieval
    would actually return.
    """
    global _collection

    def _describe(count: int) -> Dict[str, Any]:
        return {
            "ready": count > 0,
            "count": count,
            "store_dir": str(_RAG_STORE_DIR),
            "model": str(_SBERT_MODEL_DIR) if _SBERT_MODEL_DIR.exists() else "all-MiniLM-L6-v2",
        }

    try:
        if _collection is not None:
            return _describe(_collection.count())
    except Exception as exc:
        # A rebuild elsewhere can leave this handle pointing at a dropped
        # collection; fall through and re-attach rather than reporting empty.
        logger.info(f"RAG: cached collection handle stale ({exc}); re-attaching")
        _collection = None

    result = build_store(force=False)
    if result.get("status") != "ok" or _collection is None:
        return {"ready": False, "count": 0, "store_dir": str(_RAG_STORE_DIR),
                "error": result.get("message", "store unavailable")}
    try:
        return _describe(_collection.count())
    except Exception as e:
        return {"ready": False, "count": 0, "error": str(e)}


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------

def retrieve(
    log_line: str,
    fields: Optional[List[str]] = None,
    top_k: int = 3,
) -> List[Dict[str, Any]]:
    """
    Retrieve the top_k most similar decoder examples for the given log line.

    Returns a list of dicts with keys:
      - decoder_xml: str
      - log_example: str (may be empty)
      - fields: list[str]
      - source: str
      - score: float (lower cosine distance = more similar)
    """
    global _chroma_client, _collection, _store_built

    if _collection is None:
        # Try lazy init
        result = build_store(force=False)
        if result.get("status") != "ok":
            return []

    if _collection is None or _collection.count() == 0:
        return []

    # Build query: log line + requested fields
    query_parts = [log_line]
    if fields:
        query_parts.append("fields:" + " ".join(fields))
    query = " ".join(query_parts)

    # Sibling decoders in one file share a log sample, so a raw top_k often
    # comes back as the same log three times with fragmentary <order> lists —
    # the prompt pays for three examples and teaches one. Over-fetch, then keep
    # the best-scoring doc per distinct log sample.
    fetch_k = min(max(top_k * 6, top_k), _collection.count())

    try:
        results = _collection.query(
            query_texts=[query],
            n_results=fetch_k,
            include=["metadatas", "distances"],
        )
    except Exception as e:
        logger.warning(f"RAG: retrieval failed: {e}")
        return []

    docs = []
    metadatas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0]

    seen_examples: set = set()
    for meta, dist in zip(metadatas, distances):
        decoder_xml = meta.get("decoder_xml", "")
        if not decoder_xml:
            continue

        log_example = meta.get("log_example", "")
        # Only dedupe when there IS a sample to dedupe on; several docs with no
        # example are still distinct decoders and shouldn't collapse into one.
        if log_example:
            if log_example in seen_examples:
                continue
            seen_examples.add(log_example)

        # A store written before _encode_fields existed can still hold a
        # truncated array; a malformed field list is not worth failing the
        # whole retrieval over.
        try:
            doc_fields = json.loads(meta.get("fields", "[]"))
        except (json.JSONDecodeError, TypeError):
            doc_fields = []

        docs.append({
            "decoder_xml": decoder_xml,
            "log_example": log_example,
            "fields": doc_fields,
            "source": meta.get("source", ""),
            "score": round(1.0 - float(dist), 3),  # convert distance to similarity
        })
        if len(docs) >= top_k:
            break

    return docs


def format_rag_context(examples: List[Dict[str, Any]]) -> str:
    """Format retrieved examples into a prompt-ready string."""
    if not examples:
        return ""
    lines = ["## Retrieved Real Wazuh Decoder Examples (use as guide, adapt for this log):"]
    for i, ex in enumerate(examples, 1):
        lines.append(f"\n### Example {i} (similarity: {ex['score']})")
        if ex.get("log_example"):
            lines.append(f"Log: {ex['log_example']}")
        if ex.get("fields"):
            lines.append(f"Fields: {', '.join(ex['fields'])}")
        lines.append("Decoder XML:")
        lines.append(ex["decoder_xml"])
    return "\n".join(lines)
