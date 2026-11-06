# Wazuh Troubleshooting & Operations Portal

A dedicated, unified web portal to assess, diagnostic-report, and troubleshoot Wazuh deployments. The system provides real-time health checks, interactive diagnostic guides, an AI troubleshooting agent, and native vector reporting.

## Key Features

1. **Operations Reporting Center**: Natively generated interactive diagnostic report modules (Agent Fleet Health, Indexer Pipeline, Cluster health, Environmental assessments, and Security Events) with offline simulation support and print-formatted PDF/HTML export capabilities.
2. **Interactive Diagnostic Wizards**: Step-by-step troubleshooting wizards for common Wazuh issues like alerts not showing, indexing pipeline errors, and database cluster yellow/red states.
3. **Wazuh Agent AI**: A tool-calling troubleshooting agent that can run read-only checks on its own and always pauses for your approval before any change to the system.
4. **AI Assistant (chat)**: Context-aware AI chat guidance for platform operators, backed by a local knowledge base synced from Wazuh community issues/discussions.
5. **Secure by default**: No credentials or connection URLs are hardcoded anywhere in source code, everything sensitive lives in one gitignored `config` file.

## Directory Structure

```text
wazuh-troubleshooting-tool/
├── config                       # Placeholder credentials template (tracked, see step 4)
├── .gitignore
├── README.md
├── start.sh                     # Dev environment launcher (backend + frontend)
├── backend/                     # Python FastAPI backend server
│   ├── config.py                # Loads config into importable constants
│   ├── main.py                  # HTTP routes: health checks, reports, assistant, agent
│   ├── wazuh_api.py              # Wazuh Manager API auth/token helper
│   ├── copilot_engine.py         # Ollama-backed "Copilot" quick-answer engine
│   ├── assistant_engine.py       # Routes chat input into use_cases/ wizards
│   ├── agent_engine.py           # The Wazuh Agent's plan/tool/observe loop
│   ├── agent_brain.py             # Dual-brain abstraction: Ollama vs Claude
│   ├── agent_tools.py             # Tool registry the agent can call
│   ├── use_cases/                # One module per diagnostic wizard (see below)
│   ├── flows/                     # Shared multi-step state machines reused across wizards
│   ├── utils/                     # Service/cluster/index/log helpers, the actual diagnostic logic
│   ├── knowledge/                 # Scripts + shipped data for the local community-issue
│   │                               # knowledge base (backend/knowledge/lgtm.db, lgtm_issues.json)
│   ├── sessions/                  # Agent chat session state, created automatically at runtime
│   └── wizard_history/            # Completed Troubleshooting Library run transcripts, created
│                                   # automatically at runtime, see /assistant/history
└── frontend/                     # HTML5/CSS/JS frontend views
    ├── index.html                 # App shell, all panel layouts
    ├── app.js                      # Routing, health-check polling, report triggers
    ├── assistant.js                # Chat UI for the wizard-driven Assistant
    ├── agent.js                     # Chat UI for the Wazuh Agent (brain picker, approvals)
    ├── manual.js                    # Manual diagnostics panel
    ├── reports.js                    # SVG charts & report export engine
    └── styles.css
```

## Setup & Configuration

### 1. Prerequisites

- **Python 3.10+** and `pip`
- **[Ollama](https://ollama.com)** installed and running locally (used for the chat Assistant, the Copilot, the Ollama agent brain, and the local knowledge-base embeddings)
- A standard Linux host with `curl`, `systemctl`, and `sed` available. The diagnostic/fix tools shell out to these to inspect and manage `wazuh-indexer`, `wazuh-manager`, `wazuh-dashboard`, and `filebeat`
- Network access to your Wazuh Manager API, Wazuh Indexer, and Kibana/Dashboard
- `sudo` privileges for the user running the backend, if you want the fix tools (service restarts, cert/config edits) to actually work rather than just report what they'd do

### 2. Install backend dependencies

Run this from the project root (no need to `cd` into `backend/` first):

```bash
pip install -r backend/requirements.txt
```

This installs every third-party package the backend needs:

| Package | Used for |
|---|---|
| `fastapi` | The backend's HTTP API framework |
| `uvicorn` | ASGI server that actually runs the FastAPI app |
| `requests` | All HTTP calls to the Wazuh API, Indexer, Kibana, GitHub, and Ollama |
| `rapidfuzz` | Fuzzy phrase matching that routes chat input to the right diagnostic wizard |
| `pyyaml` | Parses the `config` file's YAML in `start.sh` |
| `anthropic` | Optional Claude brain for the Wazuh Agent (see step 5) |
| `numpy` | Vector similarity search over the local knowledge base (`backend/knowledge/lgtm.db`) |

Everything else imported (`sqlite3`, `subprocess`, `uuid`, `gzip`, etc.) is Python's standard library, no separate install needed.

### 3. Pull the required Ollama models

```bash
ollama pull qwen3:1.7b          # chat model: Copilot, Assistant, and the Ollama agent brain
ollama pull nomic-embed-text    # embedding model: powers the local knowledge-base search
```

### 4. Create your `config` file

A `config` file already exists in the project root (next to `start.sh`) as a placeholder template. Edit it in place with your real values:

```yaml
wazuh_api:
  host: "https://localhost:55000"
  username: "wazuh"
  password: "YOUR_WAZUH_PASSWORD"
  verify_ssl: false

indexer:
  url: "https://localhost:9200"
  username: "admin"
  password: "YOUR_INDEXER_PASSWORD"

kibana:
  username: "kibanaserver"
  password: "YOUR_KIBANA_PASSWORD"

ollama:
  url: "http://localhost:11434"
  model: "qwen3:1.7b"

anthropic:
  api_key: ""                    # optional, see step 5
  model: "claude-sonnet-5"

server:
  host: "localhost"              # replace with your server/lab IP if you're
                                  # browsing to this box from another machine
  backend_port: "8000"
  frontend_port: "3000"
```

`wazuh_api.password`, `indexer.password`, and `kibana.password` are required. The backend refuses to start without them (see `backend/config.py`). Everything else has a working default. `server.host` only needs to change from `localhost` if you'll access the UI from a different machine than the one running it, set it to that machine's real IP/hostname.

You need to replace the placeholder credentials according to your own environment in the following file:

- `config` (`wazuh_api.password`, `indexer.password`, `kibana.password`, and optionally `anthropic.api_key`, `server.host`)

### 5. (Optional) Enable the Claude brain for the Wazuh Agent

The Agent works out of the box on Ollama alone. To also offer Claude as a brain option (recommended, far more reliable at multi-step tool use than a small local CPU model):

1. Create an API key at [console.anthropic.com](https://console.anthropic.com)
2. Set `anthropic.api_key` in your `config` file
3. Restart the backend. `GET /agent/brains` will now report `claude.available: true`

Never commit a real key. If one is ever pasted somewhere it shouldn't be (chat, a public PR, a log), revoke it immediately from the Anthropic Console and generate a new one.

### 6. Start the app

```bash
./start.sh
```

This starts the backend (`backend_port`, default `8000`) and frontend (`frontend_port`, default `3000`). Navigate to `http://<server.host>:<frontend_port>` to access the portal.

---

## Adding Your Own Diagnostic Wizard (Use Case)

Each wizard is a self-contained module in `backend/use_cases/` that walks the operator through checking and fixing one specific problem, reusing the shared step-machines in `flows/` and helpers in `utils/` rather than re-implementing diagnostic logic.

1. **Write the flow.** Create `backend/use_cases/my_issue.py` exposing a function with this contract:

   ```python
   def my_issue_flow(user_choice=None, context=None):
       context = context or {}
       # ... inspect context.get("stage") to know where you are in a
       # multi-step conversation, call your utils/flows helpers, and
       # return the next step:
       return {
           "display": "What you show the user this turn",
           "context": {"stage": "next_stage_name", **context},
       }
   ```

   Look at `use_cases/mapping_issue.py` for a short, self-contained example, or `use_cases/dashboard_error.py` for one that chains through several `flows/` state machines.

2. **Register it** in `backend/use_cases/__init__.py`:
   - Add an entry to the `USE_CASES` list with a `name`, a list of trigger `phrases` (matched with fuzzy string matching, threshold 65), and a `handler` key.
   - Add your `handler` to both `elif` chains inside `run_use_cases()`: one for starting a fresh match, one for continuing an in-progress flow (`context["stage"]` already set).

That's it. The Assistant chat and `/assistant` endpoint pick it up automatically; no frontend changes needed.

---

## How the Wazuh Agent AI Works

The Agent (`agent_engine.py`) runs a **plan, call tool, observe, repeat** loop, capped at 8 iterations per turn, with one hard rule: **read-only tools chain automatically, but the moment the agent wants to call a tool marked `mutating` in `agent_tools.py`, the loop stops and waits for your explicit approval** via `/agent/approve` before anything on the system actually changes.

**Two interchangeable brains** (`agent_brain.py`), picked per-session from the UI's brain dropdown:

- **Ollama** (local, offline): the small model here is too slow to drive a real tool-calling loop, so instead of letting it choose tools, the backend fetches all relevant data itself (service status, cluster health, matching knowledge-base issues) and hands Ollama one single prompt for one single answer. Fast, but can't execute fixes.
- **Claude** (API): runs the full tool-calling agentic loop and can actually execute approved fixes. Requires `anthropic.api_key` in `config` (see Setup step 5); if it's blank, the Agent silently falls back to Ollama-only.

**The tool registry** (`agent_tools.py`) is what the agent can see and call. Each entry wraps an existing, already-tested function from `utils/*.py`, described by a name, a JSON schema for its arguments, and a `mutating` flag. To give the agent a new capability, add an entry to the `TOOLS` list there; don't re-implement diagnostic logic inline, call into `utils/` the same way every other tool does.

---

## Knowledge Base Data

`backend/knowledge/lgtm.db` and `backend/knowledge/lgtm_issues.json` are shipped with the repo so the Assistant/Copilot/Agent RAG features work immediately after cloning, with no separate build step. Both are an indexed snapshot sourced entirely from public Wazuh GitHub issues and discussions.

That snapshot goes stale over time. To refresh it with more recent or more relevant community issues, manually re-run the sync scripts and replace the shipped file:

```bash
cd backend/knowledge
python3 sync_lgtm_issues.py            # rebuilds lgtm_issues.json from source
python3 migrate_json_to_sqlite.py      # rebuilds lgtm.db from lgtm_issues.json
```

Commit the regenerated `lgtm.db`/`lgtm_issues.json` in place of the old ones when you want the shipped knowledge base updated.

---

## Security Notes

- `config` is tracked as a placeholder-only template (`YOUR_*_PASSWORD` values, `host: "localhost"`). Never commit it with real credentials filled in.
- `backend/sessions/` and `backend/wizard_history/` (runtime-generated session/history files, created automatically on first use) are gitignored. Don't force-add real session data into git.
- `.env`, if you use one, is gitignored the same way.
- If any real credential ever ends up pasted in a chat log, commit, or public PR, treat it as compromised and rotate it immediately, even if you're not sure it was actually exposed.
