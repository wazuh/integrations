import os

# Config path is located in the root directory (parent of the backend directory)
CONFIG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config"))

def parse_simple_yaml(filepath):
    config = {}
    current_key = None
    if not os.path.exists(filepath):
        return config
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.endswith(':'):
                current_key = line[:-1].strip()
                config[current_key] = {}
            elif ':' in line:
                parts = line.split(':', 1)
                k = parts[0].strip()
                v = parts[1].strip().strip('"').strip("'")
                if v.lower() == 'true':
                    v = True
                elif v.lower() == 'false':
                    v = False
                if current_key:
                    config[current_key][k] = v
                else:
                    config[k] = v
    return config

_cfg = parse_simple_yaml(CONFIG_PATH)

WAZUH_API_URL = _cfg.get("wazuh_api", {}).get("host")
API_USERNAME = _cfg.get("wazuh_api", {}).get("username")
API_PASSWORD = _cfg.get("wazuh_api", {}).get("password")

INDEXER_USERNAME = _cfg.get("indexer", {}).get("username")
INDEXER_PASSWORD = _cfg.get("indexer", {}).get("password")
INDEXER_URL = _cfg.get("indexer", {}).get("url")

KIBANA_USERNAME = _cfg.get("kibana", {}).get("username")
KIBANA_PASSWORD = _cfg.get("kibana", {}).get("password")

# ── Ollama (Wazuh Copilot) ────────────────────────────────────────────────────
OLLAMA_URL   = _cfg.get("ollama", {}).get("url",   "http://localhost:11434")
OLLAMA_MODEL = _cfg.get("ollama", {}).get("model", "qwen3:1.7b")

if not API_PASSWORD or not INDEXER_PASSWORD or not KIBANA_PASSWORD:
    import sys
    print(f"CRITICAL ERROR: Required credentials missing in configuration file at {CONFIG_PATH}", file=sys.stderr)
    sys.exit(1)
