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
                        program_name: str, regex: str, order: str) -> str:
    """Produce a flat text representation for embedding."""
    parts = []
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
        parent_xml = f'<decoder name="{child["parent"]}">\n'
        if pinfo.get("program_name"):
            parent_xml += f'  <program_name>{pinfo["program_name"]}</program_name>\n'
        elif pinfo.get("prematch"):
            parent_xml += f'  <prematch>{pinfo["prematch"]}</prematch>\n'
        parent_xml += "</decoder>"

        child_xml = f'<decoder name="{child["name"]}">\n'
        child_xml += f'  <parent>{child["parent"]}</parent>\n'
        if child.get("regex"):
            child_xml += f'  <regex>{child["regex"]}</regex>\n'
        if child.get("order"):
            child_xml += f'  <order>{child["order"]}</order>\n'
        child_xml += "</decoder>"

        full_xml = parent_xml + "\n\n" + child_xml
        embed_text = _build_decoder_text(
            name=child["name"],
            parent=child["parent"],
            prematch=pinfo.get("prematch", ""),
            program_name=pinfo.get("program_name", ""),
            regex=child["regex"],
            order=child["order"],
        )
        docs.append({
            "id": doc_id,
            "text": embed_text,
            "decoder_xml": full_xml,
            "fields": [f.strip() for f in child["order"].split(",") if f.strip()],
            "source": f"official:{xml_path.name}",
        })
    return docs


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

        # Build XML
        parent_xml = ""
        if parent:
            parent_xml = f'<decoder name="{parent}">\n'
            if program_name:
                parent_xml += f"  <program_name>{program_name}</program_name>\n"
            elif prematch:
                parent_xml += f"  <prematch>{prematch}</prematch>\n"
            parent_xml += "</decoder>\n\n"

        child_xml = f'<decoder name="{name}">\n'
        if parent:
            child_xml += f"  <parent>{parent}</parent>\n"
        if prematch and not parent:
            child_xml += f"  <prematch>{prematch}</prematch>\n"
        if regex:
            child_xml += f"  <regex>{regex}</regex>\n"
        if order_str:
            child_xml += f"  <order>{order_str}</order>\n"
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
                        "fields": json.dumps(d.get("fields", []))[:500],
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
    """Return the current status of the RAG store."""
    if _collection is None:
        return {"ready": False, "count": 0, "store_dir": str(_RAG_STORE_DIR)}
    try:
        count = _collection.count()
        return {
            "ready": count > 0,
            "count": count,
            "store_dir": str(_RAG_STORE_DIR),
            "model": str(_SBERT_MODEL_DIR) if _SBERT_MODEL_DIR.exists() else "all-MiniLM-L6-v2",
        }
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

    try:
        results = _collection.query(
            query_texts=[query],
            n_results=min(top_k, _collection.count()),
            include=["metadatas", "distances"],
        )
    except Exception as e:
        logger.warning(f"RAG: retrieval failed: {e}")
        return []

    docs = []
    metadatas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0]

    for meta, dist in zip(metadatas, distances):
        decoder_xml = meta.get("decoder_xml", "")
        if not decoder_xml:
            continue
        docs.append({
            "decoder_xml": decoder_xml,
            "log_example": meta.get("log_example", ""),
            "fields": json.loads(meta.get("fields", "[]")),
            "source": meta.get("source", ""),
            "score": round(1.0 - float(dist), 3),  # convert distance to similarity
        })

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
