#!/var/ossec/framework/python/bin/python3

import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# ---------- Config ----------
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = f'{pwd}/logs/integrations.log'
socket_addr = f'{pwd}/queue/sockets/queue'
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

# Gemini API config
GEMINI_MODEL = "gemini-2.0-flash"
GEMINI_ENDPOINT = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

# ---------- Helpers ----------
def debug(msg):
    if debug_enabled:
        msg = f"{now}: {msg}\n"
    print(msg)
    try:
        with open(log_file, "a") as f:
            f.write(str(msg))
    except Exception:
        pass  # avoid breaking on logging errors

def send_event(msg, agent=None):
    if not agent or agent.get("id") == "000":
        string = '1:gemini:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->gemini:{3}'.format(
            agent.get("id"),
            agent.get("name"),
            agent.get("ip") if "ip" in agent else "any",
            json.dumps(msg),
        )
    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

def first(items, default=""):
    if isinstance(items, list) and items:
        return items[0]
    return default

# ---------- Prompting ----------
def build_prompt(alert):
    """
    Builds a minimal, safe prompt centered on rule.description.
    Adds small context to help accuracy while avoiding sensitive data leakage.
    Target style: 4–5 sentences; summary + likely cause + remediation/risk.
    """
    rule = alert.get("rule", {}) or {}
    desc = rule.get("description") or "Security alert detected"
    level = rule.get("level")
    groups = ", ".join(rule.get("groups", [])[:6]) if rule.get("groups") else ""
    mitre_ids = ", ".join(rule.get("mitre", {}).get("id", [])[:6]) if rule.get("mitre") else ""
    mitre_techniques = ", ".join(rule.get("mitre", {}).get("technique", [])[:6]) if rule.get("mitre") else ""

    # Optional context (kept generic)
    path = alert.get("syscheck", {}).get("path") or ""
    location = alert.get("location") or ""
    full_log = alert.get("full_log") or ""
    # Keep full_log short to avoid huge prompts
    short_log = full_log[:800]

    bits = []
    bits.append(f"Rule description: {desc}")
    if level: bits.append(f"Level: {level}")
    if groups: bits.append(f"Groups: {groups}")
    if mitre_ids or mitre_techniques:
        bits.append(f"MITRE: IDs[{mitre_ids}] Techniques[{mitre_techniques}]")
    if location: bits.append(f"Location: {location}")
    if path: bits.append(f"Path: {path}")
    if short_log: bits.append(f"Log excerpt: {short_log}")

    context = "\n".join(bits)

    prompt = (
        "You are a security assistant. Based ONLY on the information provided, write 4–5 sentences that:\n"
        "1) Summarize what this alert means,\n"
        "2) Suggest the most likely cause(s),\n"
        "3) Recommend concrete remediation steps or immediate actions,\n"
        "4) Note key risk factors or impact if ignored.\n\n"
        f"{context}\n\n"
        "Keep it concise and practical. Do not invent file paths, hosts, or data not present."
    )
    return prompt

# ---------- Gemini ----------
def call_gemini(prompt, api_key):
    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": api_key,
    }
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ]
    }
    try:
        resp = requests.post(GEMINI_ENDPOINT, headers=headers, json=payload, timeout=30)
    except requests.RequestException as e:
        return {"error": "transport_error", "description": str(e)}

    if resp.status_code != 200:
        try:
            j = resp.json()
            desc = json.dumps(j)[:2048]
        except Exception:
            desc = resp.text[:2048]
        return {"error": str(resp.status_code), "description": desc}

    try:
        j = resp.json()
        text = ""
        resp_id = j.get("responseId")
        model_ver = j.get("modelVersion")
        if "candidates" in j and j["candidates"]:
            content = j["candidates"][0].get("content", {})
            parts = content.get("parts", [])
            if parts and isinstance(parts, list):
                text = parts[0].get("text", "") or ""
        return {
            "text": text.strip(),
            "response_id": resp_id,
            "model_version": model_ver,
            "raw": j,  # keep for debug; you can remove in production
        }
    except Exception as e:
        return {"error": "parse_error", "description": str(e)}

# ---------- Core ----------
def build_output(alert, prompt_used, gemini_result):
    rule = alert.get("rule", {}) or {}
    out = {
        "integration": "custom-gemini",
        "gemini": {
            "found": 0,
            "source": {
                "alert_id": alert.get("id"),
                "rule": rule.get("id"),
                "description": rule.get("description"),
                "level": rule.get("level"),
                "groups": rule.get("groups"),
                "mitre": rule.get("mitre"),
                "location": alert.get("location"),
                "path": alert.get("syscheck", {}).get("path"),
                "full_log": alert.get("full_log"),
                "timestamp": alert.get("timestamp"),
            },
            "prompt_used": prompt_used[:2000]
        }
    }

    if gemini_result.get("error"):
        out["gemini"]["error"] = gemini_result["error"]
        out["gemini"]["error_description"] = gemini_result.get("description")
        return out

    text = gemini_result.get("text", "")
    if text:
        out["gemini"]["found"] = 1
        out["gemini"]["summary"] = text
        meta = {}
        if gemini_result.get("response_id"): meta["response_id"] = gemini_result["response_id"]
        if gemini_result.get("model_version"): meta["model_version"] = gemini_result["model_version"]
        if meta: out["gemini"]["model_meta"] = meta
    else:
        out["gemini"]["note"] = "Empty or blocked response from model."

    return out

def process_alert(alert, api_key):
    prompt = build_prompt(alert)
    result = call_gemini(prompt, api_key)
    return build_output(alert, prompt, result)

# ---------- Entrypoint ----------
def main(args):
    debug("# Starting custom-gemini (rule.description) integration")
    if len(args) < 3:
        debug("# Exiting: Bad arguments.")
        sys.exit(1)

    alert_file = args[1]
    api_key = args[2]
    debug("# API key (masked)")
    debug((api_key[:5] + "...") if api_key else "MISSING")
    debug("# Alert file")
    debug(alert_file)

    with open(alert_file, "r") as f:
        alert = json.load(f)

    msg = process_alert(alert, api_key)
    if msg:
        send_event(msg, alert.get("agent"))

if __name__ == "__main__":
    try:
        if len(sys.argv) >= 4:
            # argv: [1]=alert.json, [2]=API_KEY, [3]=extra?, [4]=debug
            _msg = '{0} {1} {2} {3} {4}'.format(
                now,
                sys.argv[1],
                sys.argv[2],
                sys.argv[3] if len(sys.argv) > 3 else "",
                sys.argv[4] if len(sys.argv) > 4 else ""
            )
            debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == 'debug')
        else:
            _msg = f'{now} Wrong arguments'
        with open(log_file, 'a') as f:
            f.write(str(_msg) + '\n')

        if len(sys.argv) < 3:
            sys.exit(1)

        main(sys.argv)
    except Exception as e:
        debug(str(e))
        # Avoid crashing analysisd on unexpected exceptions.