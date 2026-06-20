# Wazuh Decoder & Rule Creator

A FastAPI web application that intelligently generates custom Wazuh decoder and rule XML for any log format. It combines `wazuh-logtest` verification, machine learning similarity search, RAG (Retrieval-Augmented Generation), and a local LLM to produce accurate, ready-to-use Wazuh XML — without manual regex writing.

---

## How It Works

```
Raw Log
   │
   ▼
wazuh-logtest
   ├── Already Matched → Skip Custom Generation (use built-in decoder)
   └── Not Matched
          │
          ▼
   Python Heuristics (calculate regex skeleton)
          │
          ▼
   ML Similarity Engine (SBERT 70% + TF-IDF 30%)
          │
          ▼
   RAG Engine (retrieve 3 verified XMLs from ChromaDB)
          │
          ▼
   Local LLM (Ollama / Qwen)
          │
          ▼
   Post-Processor (sanitize OS_Regex syntax)
          │
          ▼
   Clean Wazuh Decoder & Rule XML
```

### Key Intelligence Rules
- If `wazuh-logtest` **pre-decodes a `program_name`** → parent decoder uses `<program_name>^value</program_name>`
- If **no program name** is pre-decoded → parent decoder uses `<prematch>` based on the log's actual prefix
- The LLM never guesses structure — it always copies from verified real examples injected via RAG

---

## Using the UI — Step-by-Step Guide

The web UI has five panels accessible from the left sidebar: **AI Generate**, **Test**, **Feedback**, **ML Status**, and **History**.

### UI Overview

```
┌──────────────────────────────────────────────────────────────┐
│  🔷 Wazuh Decoder Studio            ● Wazuh Local  ML 1500   │
├─────────────────────┬────────────────────────────────────────┤
│  Workspace          │                                        │
│  ⚡ AI Generate      │                                         │
│    (active)         │        Main Content Area               │
│  ✓ Test             │   (forms, XML output, results)         │
│  👍 Feedback        │                                        │
│  ─────────────────  │                                        │
│  Model              │                                        │
│  ✳ ML Status        │                                        │
│  🔘 History         │                                        │
└─────────────────────┴────────────────────────────────────────┘
```

The **top-right status pills** show live connectivity:
- `● Wazuh Local` — green dot, `wazuh-logtest` is reachable on the local machine
- `● Wazuh Remote` — green dot, `wazuh-logtest` is reachable over SSH
- `● Wazuh Local (unavailable)` — red dot, logtest binary not found; generation still works but validation is skipped
- `ML 1500` — number of decoder patterns currently loaded in the ML model

---

### Panel 1 — AI Generate (Main Workflow)

This is the default panel and the primary way to generate decoders and rules.

#### Step 1: Fill in the basic settings

| Field | What to enter |
|---|---|
| **App Name** | Short identifier for your app, e.g. `nginx`, `myapp`, `paloalto` |
| **Log Source Name** | Optional. Human-readable source name (auto-detected from log if left blank) |
| **Generation Mode** | `Auto` (default) — generates both decoder + rule. Choose `Decoder Only` or `Rule Only` if needed |
| **Install Mode** | `stdin only` — tests without writing files. `Write XML files` — writes to `/var/ossec/etc/` |

#### Step 2: Choose options

- ☑ **Split Child Decoders** — generates one child decoder per extracted field (useful for complex multi-field logs)
- ☑ **Validate with logtest** — after generation, immediately tests the decoder against `wazuh-logtest` (recommended)

#### Step 3: Paste your log samples

In the **Log Source Samples** box, paste one or more raw log lines **from the same source**:

```
Dec 25 20:45:02 MyHost myapp[12345]: User 'admin' failed login from '192.168.1.100'
Dec 25 20:50:11 MyHost myapp[12345]: User 'root' failed login from '10.0.0.5'
```

> **Tip:** Paste 2–5 varied log lines from the same app for best pattern learning.

#### Step 4: Specify fields to extract (optional but recommended)

In the **Fields to Extract** box, list the fields you want captured:

```
timestamp, user, srcip
```

In **Field Value Mapping Hints**, optionally map values to fields to guide the engine:

```
user: admin
srcip: 192.168.1.100
```

#### Step 5: Add AI context (optional)

| Field | Purpose |
|---|---|
| **Temperature** | Controls AI creativity. `0.1–0.2` = deterministic (recommended). Higher = more creative. |
| **Decoder Extra Context** | Free-text hint, e.g. `"This is a Palo Alto firewall log. Extract action from the deny-smb field."` |
| **Rule Requirements** | Describe the rule in plain English, e.g. `"Create a level 7 rule for failed login events."` |

#### Step 6: Generate

Click one of two buttons:

| Button | What it does |
|---|---|
| **⚡ Generate with AI** | Calls AI (RAG + LLM) to generate XML. Fast, no logtest validation. |
| **✓ Generate & Validate** | Generates XML, then installs temporarily and runs `wazuh-logtest` to verify it matches. **Best option.** |

> If your log already matches a built-in Wazuh decoder, a confirmation dialog appears before proceeding.

#### Step 7: Review the generated XML

After generation, two syntax-highlighted XML blocks appear:

- **AI-Generated Decoder XML** — the `<decoder>` block(s) to add to Wazuh
- **AI-Generated Rule XML** — the `<group><rule>` block(s) for alerting

Both have a **Copy** button. If you used **Generate & Validate**, a badge shows the result:
- ✅ **Passed** — decoder matched your log lines in `wazuh-logtest`
- ❌ **Failed** — decoder was generated but didn't match; try adjusting fields or adding extra context and re-generate

---

### Panel 2 — Test (Install & Raw Logtest)

Use this panel to install a generated decoder into Wazuh and run live tests.

#### Step 1: Install the decoder

After generating in the AI panel, switch to **Test** and click **Install Current AI Decoder**. This writes the XML files to:
- `/var/ossec/etc/decoders/local_<appname>_decoder_<timestamp>.xml`
- `/var/ossec/etc/rules/local_<appname>_rule_<timestamp>.xml`

The badge changes to 🟢 **Installed** and shows the written file paths.

#### Step 2: Run wazuh-logtest

Paste log lines into the **Test Logs** box and click **▶ Run wazuh-logtest**. The raw `wazuh-logtest` output appears, showing:
- Which decoder matched
- Which rule fired
- All extracted field values in a parsed fields table below the output

#### Step 3: Uninstall (when done)

Click **🗑 Uninstall** to remove the written XML files from Wazuh cleanly.

---

### Panel 3 — Feedback (Improve the ML Model)

After reviewing a generated decoder, provide feedback to improve future generations.

1. Switch to the **Feedback** panel (the log and app name are already pre-filled from your last generation)
2. *(Optional)* Correct the **Prematch**, **Regex**, and **Order** fields if the generated decoder is wrong
3. Add **Notes** describing what you corrected (e.g. `"Fixed timestamp capture group"`)
4. Click one of:
   - **👍 Approve & Retrain** — saves the log→decoder pair to `data/datasets/feedback.jsonl` and adds it to the RAG store for future generations
   - **👎 Reject** — records the rejection so the pattern is avoided in future training

---

### Panel 4 — ML Status

Check and refresh the ML similarity model.

- Click **Refresh Status** to see how many patterns are loaded, the ensemble type, and where the cache is located
- Click **Pull & Rebuild Model** to:
  1. Fetch the latest Wazuh decoder XMLs from the official GitHub repo
  2. Rebuild the ML similarity model (TF-IDF + SBERT)
  3. Rebuild the ChromaDB RAG vector store

> This process takes a few minutes on first run. Subsequent runs are faster as the repo is cached.

---

### Panel 5 — History

The **History** sidebar view shows your last 30 sessions, stored in browser `localStorage`. Click any entry to reload those log samples and app name back into the AI Generate panel.

---

## What Is Included

| File / Directory | Purpose |
|---|---|
| `app/main.py` | FastAPI backend — all API endpoints and generation logic |
| `app/rag_engine.py` | RAG engine — ChromaDB vector store for real decoder retrieval |
| `app/decoder_ml.py` | ML similarity model (TF-IDF baseline) |
| `app/decoder_ml_enhanced.py` | Enhanced ensemble ML model (TF-IDF 30% + SBERT 70%) |
| `app/wazuh_logtest.py` | `wazuh-logtest` runner (local and SSH remote) |
| `app/templates/index.html` | Single-page frontend UI |
| `app/static/` | JavaScript (`app.js`) and CSS (`styles.css`) |
| `Modelfile` | Custom Ollama model config (`wazuh-decoder` built on `qwen2.5:7b`) |
| `Modelfile.finetune` | Extended Modelfile with fine-tuning examples |
| `scripts/build_dataset.py` | Build SBERT training dataset from Wazuh decoder repo |
| `scripts/train_similarity.py` | Fine-tune SBERT on Wazuh decoder patterns |
| `scripts/train_osregex.py` | Train OS_Regex pattern model |
| `scripts/generate_finetuning_data.py` | Generate LLM fine-tuning data |
| `data/wazuh_repo/` | Cached clone of official Wazuh decoder XMLs |
| `data/rag_store/` | ChromaDB vector store (auto-built on first startup) |
| `data/models/decoder-sbert/` | Fine-tuned SBERT similarity model |
| `data/datasets/` | Feedback and training datasets |
| `requirements.txt` | Python dependencies |

---

## Quick Start

### 1. Set Up Python Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Generate SSL Certificates

The app runs over HTTPS. Generate a self-signed certificate for local use:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/localhost.key \
  -out certs/localhost.crt \
  -days 365 -nodes -subj "/CN=localhost"
```

> **Note:** `certs/` is in `.gitignore` — your private keys will never be committed.

### 3. (Optional) Set Up the Ollama AI Model

The app uses a custom Ollama model called `wazuh-decoder` built on top of `qwen2.5:7b`. It has Wazuh OS_Regex rules baked into its system prompt.

```bash
# Install Ollama: https://ollama.com
ollama create wazuh-decoder -f Modelfile
```

Then set environment variables before starting:

```bash
export OLLAMA_BASE_URL=http://localhost:11434
export OLLAMA_MODEL=wazuh-decoder
```

### 4. Start the Application

```bash
.venv/bin/uvicorn app.main:app \
  --host 0.0.0.0 --port 8443 \
  --ssl-certfile certs/localhost.crt \
  --ssl-keyfile certs/localhost.key
```

Open **`https://localhost:8443`** in your browser.

> On first startup, the RAG vector store is built automatically in the background (~1–2 min). The app is fully usable while it builds.

---

## AI Provider Configuration

The app supports three AI providers. Set **one** of the following before starting:

### Ollama (Recommended — Local, No Rate Limits)

```bash
export OLLAMA_BASE_URL=http://localhost:11434
export OLLAMA_MODEL=wazuh-decoder        # custom model from Modelfile
# or use a generic model:
# export OLLAMA_MODEL=qwen2.5:7b
```

### DashScope (Alibaba Cloud — Qwen)

```bash
export DASHSCOPE_API_KEY=your_key_here
```

### OpenRouter

```bash
export OPENROUTER_API_KEY=your_key_here
# Optional: override default model
export AI_DEFAULT_MODEL=meta-llama/llama-3.3-70b-instruct:free
```

**Priority:** Ollama → DashScope → OpenRouter. Ollama is always preferred when configured.

---

## Wazuh Integration

### Local `wazuh-logtest`

By default the app looks for the Wazuh logtest binary at:

```
/var/ossec/bin/wazuh-logtest
```

Override with:

```bash
export WAZUH_LOGTEST_PATH=/custom/path/to/wazuh-logtest
```

### Local sudo mode

If the app runs on the Wazuh server but not as root:

```bash
export WAZUH_USE_SUDO=true
export WAZUH_SUDO_PASSWORD=your_sudo_password
```

### Remote Wazuh VM (SSH Mode)

If your Wazuh instance runs in a VM or remote server, configure SSH access:

```bash
export WAZUH_SSH_HOST=192.168.56.10
export WAZUH_SSH_PORT=22
export WAZUH_SSH_USER=your_ssh_user
export WAZUH_SSH_PASSWORD=your_ssh_password
# optional — use key-based auth instead of password:
export WAZUH_SSH_KEY=/path/to/private_key
```

When SSH is configured, the app will:
- Run `wazuh-logtest` over SSH to validate logs against your live Wazuh instance
- Write generated decoder/rule XML directly to `/var/ossec/etc/decoders/` and `/var/ossec/etc/rules/` on the remote VM

---

## ML Similarity Model

The app uses an ensemble of **TF-IDF (30%) + SBERT (70%)** to find the closest official Wazuh decoder patterns for any new log.

### Configuration

```bash
export WAZUH_REPO_URL=https://github.com/wazuh/wazuh.git
export WAZUH_REPO_CACHE_DIR=/path/to/cache/wazuh_repo    # default: data/wazuh_repo
export WAZUH_REPO_DECODER_SUBPATH=ruleset/decoders
```

### API

| Endpoint | Description |
|---|---|
| `GET /api/ml/status` | Show model status, pattern count, cache location |
| `POST /api/ml/refresh` | Pull latest Wazuh decoders, rebuild ML model **and** RAG store |

### Training a Fine-Tuned SBERT Model

For best accuracy, train the SBERT model on official Wazuh decoders:

```bash
# 1. Make sure the Wazuh repo cache exists
#    (run the app once or POST /api/ml/refresh)

# 2. Build training dataset
python scripts/build_dataset.py
# Outputs: data/datasets/train.jsonl, val.jsonl

# 3. Train SBERT
python scripts/train_similarity.py
# Outputs: data/models/decoder-sbert/final/
```

The app automatically uses the fine-tuned model if `data/models/decoder-sbert/final/` exists, otherwise falls back to TF-IDF.

---

## Rule ML Model

In addition to the decoder similarity model, the app also includes a **Rule ML model** trained from the official Wazuh ruleset repository. This helps suggest appropriate rule structures (level, group, fields) for generated rules.

```bash
export WAZUH_RULESET_REPO_DIR=data/wazuh_ruleset_repo   # default path
```

---

## RAG (Retrieval-Augmented Generation)

The RAG engine indexes **1,700+ real Wazuh decoder XMLs** into a local ChromaDB vector store. Before the LLM generates anything, the 3 most similar real decoder examples are retrieved and injected into the prompt.

This prevents the LLM from hallucinating incorrect OS_Regex syntax — it copies from proven, verified patterns instead.

### RAG Data Sources

| Source | Content |
|---|---|
| `data/wazuh_repo/ruleset/decoders/*.xml` | Official Wazuh decoder XMLs (~120 files, 1,500+ decoders) |
| `data/datasets/feedback.jsonl` | Your approved log→decoder pairs |
| `data/datasets/train.jsonl` | Generated training pairs |

### API

| Endpoint | Description |
|---|---|
| `GET /api/rag/status` | Show RAG store status and document count |
| `POST /api/ml/refresh` | Rebuilds both the ML model **and** the RAG store |

### RAG Store Location

The vector store is saved to `data/rag_store/` and persists across restarts. It is rebuilt automatically when you call `POST /api/ml/refresh`.

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Web UI |
| `/api/analyze` | POST | Analyze a log — run logtest, extract fields, ML suggestions |
| `/api/generate` | POST | Generate decoder + rule XML (programmatic only) |
| `/api/ai/generate` | POST | Generate decoder + rule XML with AI (RAG + LLM) |
| `/api/ai/generate-validated` | POST | Generate + auto-validate with wazuh-logtest (retry loop) |
| `/api/test` | POST | Generate + install + test via `wazuh-logtest` |
| `/api/install` | POST | Install generated XML to Wazuh (local or remote) |
| `/api/uninstall` | POST | Remove installed XML files |
| `/api/ml/status` | GET | ML model status |
| `/api/ml/refresh` | POST | Rebuild ML model and RAG store |
| `/api/rag/status` | GET | RAG vector store status |
| `/api/logtest/raw` | POST | Run raw `wazuh-logtest` on a log line |
| `/api/feedback` | POST | Save an approved log→decoder pair to feedback dataset |
| `/health` | GET | Health check and connectivity status |

---

## Optional File Output

The `/api/test` endpoint supports `install_mode="write_files"` which writes generated XML to:

- `/var/ossec/etc/decoders/local_<appname>_decoder_<stamp>.xml`
- `/var/ossec/etc/rules/local_<appname>_rule_<stamp>.xml`

Override the output directories:

```bash
export WAZUH_DECODERS_DIR=/custom/decoders
export WAZUH_RULES_DIR=/custom/rules
```

---

## Environment Variable Reference

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API base URL |
| `OLLAMA_MODEL` | `llama3.1:latest` | Ollama model name |
| `DASHSCOPE_API_KEY` | *(none)* | DashScope API key |
| `DASHSCOPE_BASE_URL` | `https://dashscope-intl.aliyuncs.com/compatible-mode/v1` | DashScope endpoint |
| `OPENROUTER_API_KEY` | *(none)* | OpenRouter API key |
| `OPENROUTER_BASE_URL` | `https://openrouter.ai/api/v1` | OpenRouter endpoint |
| `AI_DEFAULT_MODEL` | `meta-llama/llama-3.3-70b-instruct:free` | Default OpenRouter model |
| `WAZUH_LOGTEST_PATH` | `/var/ossec/bin/wazuh-logtest` | Path to wazuh-logtest binary |
| `WAZUH_USE_SUDO` | `false` | Run wazuh-logtest with sudo |
| `WAZUH_SUDO_PASSWORD` | *(none)* | sudo password for local mode |
| `WAZUH_SSH_HOST` | *(none)* | SSH host for remote Wazuh VM |
| `WAZUH_SSH_PORT` | `22` | SSH port |
| `WAZUH_SSH_USER` | *(none)* | SSH username |
| `WAZUH_SSH_PASSWORD` | *(none)* | SSH password |
| `WAZUH_SSH_KEY` | *(none)* | Path to SSH private key |
| `WAZUH_REMOTE_ENABLED` | *(auto)* | Force-enable remote mode (auto-detected from SSH vars) |
| `WAZUH_REPO_URL` | `https://github.com/wazuh/wazuh.git` | Wazuh repo for ML training data |
| `WAZUH_REPO_CACHE_DIR` | `data/wazuh_repo` | Local cache for Wazuh repo |
| `WAZUH_REPO_DECODER_SUBPATH` | `ruleset/decoders` | Subpath inside repo for decoder XMLs |
| `WAZUH_REPO_BRANCH` | `v4.14.5` | Branch/tag to use from Wazuh repo |
| `WAZUH_RULESET_REPO_DIR` | `data/wazuh_ruleset_repo` | Local cache for Wazuh ruleset repo |
| `ML_MODEL_DIR` | `data/models/decoder-sbert` | Directory for fine-tuned SBERT model |
| `WAZUH_DECODERS_DIR` | `/var/ossec/etc/decoders` | Output directory for decoder XML |
| `WAZUH_RULES_DIR` | `/var/ossec/etc/rules` | Output directory for rule XML |
