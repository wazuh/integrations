from flask import Flask, request, jsonify
import os, requests, textwrap
from datetime import datetime

# ----- Config (env) -----
OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "https://localhost:9200").rstrip("/")
OS_USER = os.getenv("OS_USER", "admin")
OS_PASS = os.getenv("OS_PASS", "admin")
OS_VERIFY_SSL = os.getenv("OS_VERIFY_SSL", "false").lower() == "true"

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
GEMINI_KEY = os.getenv("GEMINI_API_KEY")  # required
GEMINI_ENDPOINT = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

TIMEOUT = 30  # seconds for HTTP calls

app = Flask(__name__)

# ----- Helpers -----
def iso_now():
    return datetime.utcnow().isoformat() + "Z"

def derive_risk(level):
    """Optional: crude risk mapping from Wazuh rule.level (1..?)"""
    try:
        lvl = int(level)
    except Exception:
        return "unknown"
    if lvl >= 10: return "critical"
    if lvl >= 7:  return "high"
    if lvl >= 4:  return "medium"
    return "low"

def build_prompt(src: dict) -> str:
    # Build a tight prompt from the alert's _source only
    rule = src.get("rule", {}) or {}
    desc = rule.get("description") or "Security alert"
    level = rule.get("level")
    groups = ", ".join(rule.get("groups", [])[:6]) if rule.get("groups") else ""
    mitre = rule.get("mitre", {}) or {}
    mitre_ids = ", ".join(mitre.get("id", [])[:6]) if isinstance(mitre.get("id"), list) else ""
    mitre_tech = ", ".join(mitre.get("technique", [])[:6]) if isinstance(mitre.get("technique"), list) else ""
    location = src.get("location") or ""
    path = (src.get("syscheck", {}) or {}).get("path", "")
    full_log = (src.get("full_log") or "")[:800]

    bits = [f"Rule description: {desc}"]
    if level:      bits.append(f"Level: {level}")
    if groups:     bits.append(f"Groups: {groups}")
    if mitre_ids or mitre_tech:
        bits.append(f"MITRE: IDs[{mitre_ids}] Techniques[{mitre_tech}]")
    if location:   bits.append(f"Location: {location}")
    if path:       bits.append(f"Path: {path}")
    if full_log:   bits.append(f"Log excerpt: {full_log}")
    context = "\n".join(bits)

    return textwrap.dedent(f"""\
        You are a security assistant. Based ONLY on the data below, write 4–5 sentences that:
        1) Summarize what the alert means,
        2) Suggest likely cause(s),
        3) Recommend concrete, immediate remediation steps,
        4) Note risk/impact if ignored.

        {context}

        Keep it concise and practical. Do not invent details not present.
    """)

def call_gemini(prompt: str) -> str:
    if not GEMINI_KEY:
        raise RuntimeError("GEMINI_API_KEY is not set in environment")
    headers = {"Content-Type": "application/json", "x-goog-api-key": GEMINI_KEY}
    body = {"contents": [{"parts": [{"text": prompt}]}]}
    r = requests.post(GEMINI_ENDPOINT, headers=headers, json=body, timeout=TIMEOUT)
    if r.status_code != 200:
        raise RuntimeError(f"Gemini error {r.status_code}: {r.text[:500]}")
    j = r.json()
    txt = ""
    if "candidates" in j and j["candidates"]:
        content = j["candidates"][0].get("content", {})
        parts = content.get("parts", [])
        if parts and isinstance(parts, list):
            txt = parts[0].get("text", "") or ""
    return txt.strip()

def update_doc(index_name: str, doc_id: str, src: dict, summary: str):
    # Optional risk scoring
    rule_level = (src.get("rule") or {}).get("level")
    risk = derive_risk(rule_level)

    payload = {
        "doc": {
            "ai_enrichment": {
                "model": GEMINI_MODEL,
                "summary": summary,
                "risk_score": risk,        # optional field
                "timestamp": iso_now()
            }
        }
    }

    url = f"{OPENSEARCH_URL}/{index_name}/_update/{doc_id}"
    r = requests.post(url, json=payload, auth=(OS_USER, OS_PASS),
                      verify=OS_VERIFY_SSL, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()

# ----- Webhook -----
@app.post("/enrich")
def enrich():
    data = request.get_json(force=True, silent=True) or {}
    # Alerting sends ctx.docs (doc-level) or ctx.results[0].hits.hits (query-level)
    docs = data.get("docs") or data.get("hits") or []
    updated, errors = [], []

    for d in docs:
        idx = d.get("_index")
        _id = d.get("_id")
        src = d.get("_source", {}) or {}
        if not idx or not _id:
            errors.append({"error": "missing_index_or_id", "doc": {k: d.get(k) for k in ["_index","_id"]}})
            continue
        try:
            prompt = build_prompt(src)
            summary = call_gemini(prompt)
            # Fallback if model returns empty
            if not summary:
                base = (src.get("rule", {}) or {}).get("description", "Security alert")
                summary = f"AI summary unavailable. Context: {base}"
            res = update_doc(idx, _id, src, summary)
            updated.append({"_index": idx, "_id": _id, "result": res.get("result")})
        except Exception as e:
            errors.append({"_index": idx, "_id": _id, "error": str(e)})

    return jsonify({"received": len(docs), "updated": updated, "errors": errors})

if __name__ == "__main__":
    # Listen on all interfaces; use 127.0.0.1 if Alerting calls locally only
    app.run(host="0.0.0.0", port=5000)