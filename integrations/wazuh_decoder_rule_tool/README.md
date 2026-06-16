# Wazuh Decoder & Rule Creator

A FastAPI web application that intelligently generates custom Wazuh decoder and rule XML for any log format. It combines `wazuh-logtest` verification, machine learning similarity search, RAG (Retrieval-Augmented Generation), and a local LLM to produce accurate, ready-to-use Wazuh XML — without manual regex writing.

---

## How It Works

```mermaid
flowchart TD
    A[Raw Log] --> B{wazuh-logtest}
    B -- "Already Matched" --> C[Skip Custom Generation<br/>Use Built-in Decoder]
    B -- "Not Matched" --> D[Python Heuristics<br/>Calculate Regex Skeleton]
    D --> E[ML Similarity Engine<br/>SBERT + TF-IDF]
    E --> F[RAG Engine<br/>Retrieve 3 Verified XMLs from ChromaDB]
    F --> G[Local LLM<br/>Ollama]
    G --> H[Post-Processor<br/>Sanitize OS_Regex Syntax]
    H --> I((Clean Wazuh<br/>Decoder & Rule XML))
    
    style A fill:#f9f,stroke:#333,stroke-width:2px
    style I fill:#bbf,stroke:#333,stroke-width:2px
    style B fill:#dfd,stroke:#333
    style D fill:#eee,stroke:#333
    style E fill:#eee,stroke:#333
    style F fill:#eee,stroke:#333
    style G fill:#ffd,stroke:#333
    style H fill:#eee,stroke:#333
```

### Key Intelligence Rules
- If `wazuh-logtest` **pre-decodes a `program_name`** → parent decoder uses `<program_name>^value</program_name>`
- If **no program name** is pre-decoded → parent decoder uses `<prematch>` based on the log's actual prefix
- The LLM never guesses structure — it always copies from verified real examples injected via RAG

---

## What Is Included

| File / Directory | Purpose |
|---|---|
| `app/main.py` | FastAPI backend — all API endpoints and generation logic |
| `app/rag_engine.py` | RAG engine — ChromaDB vector store for real decoder retrieval |
| `app/decoder_ml.py` | ML similarity model (TF-IDF baseline) |
| `app/decoder_ml_enhanced.py` | Enhanced ensemble ML model (TF-IDF 30% + SBERT 70%) |
| `app/templates/index.html` | Single-page frontend UI |
| `app/static/` | JavaScript and CSS |
| `Modelfile` | Custom Ollama model config (`wazuh-decoder` built on `qwen2.5:7b`) |
| `data/wazuh_repo/` | Cached clone of official Wazuh decoder XMLs |
| `data/rag_store/` | ChromaDB vector store (auto-built on first startup) |
| `data/models/decoder-sbert/` | Fine-tuned SBERT similarity model |
| `data/datasets/` | Feedback and training datasets |
| `requirements.txt` | Python dependencies |

---

## Deployment Modes

The app supports two deployment modes. **Mode A (on-server) is recommended** — it gives you a fully local setup with no SSH overhead.

### Mode A — Run Directly on the Wazuh Server (Recommended)

Install and run the app directly on the machine where Wazuh is installed. `wazuh-logtest` is called locally and files are written directly to `/var/ossec/`.

**When to use:** The app and Wazuh are on the same machine.

### Mode B — Run Remotely via SSH

Run the app on a separate machine (e.g. your laptop or a dev VM) and connect to the Wazuh server over SSH. `wazuh-logtest` is executed via SSH and files are written remotely.

**When to use:** You are developing on a separate machine from where Wazuh runs.

---

## Quick Start

### 1. Clone and Set Up Python Environment

```bash
cd integrations/wazuh_decoder_rule_tool
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Environment

Copy the `.env` file and choose your deployment mode:

```bash
# The .env file is pre-configured for Mode A (on-server).
# Edit it if you need Mode B (remote SSH) instead.
nano .env
```

**Mode A — On-server (default `.env`):**

```ini
WAZUH_REMOTE_ENABLED=false

# Enable sudo if the app does not run as root:
WAZUH_USE_SUDO=true
# WAZUH_SUDO_PASSWORD=yourpassword   # only if passwordless sudo is not configured

OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1:latest
```

**Mode B — Remote SSH:**

```ini
WAZUH_REMOTE_ENABLED=true
WAZUH_SSH_HOST=192.168.8.171
WAZUH_SSH_USER=vagrant
WAZUH_SSH_PASSWORD=vagrant
WAZUH_SSH_PORT=22

OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1:latest
```

### 3. Generate SSL Certificates

The app runs over HTTPS. Generate a self-signed certificate for local use:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/localhost.key \
  -out certs/localhost.crt \
  -days 365 -nodes -subj "/CN=localhost"
```

> **Note:** `certs/` is in `.gitignore` — your private keys will never be committed.

### 4. (Optional) Set Up a Custom Ollama Model

The app works with any Ollama model. A custom `wazuh-decoder` model built on `qwen2.5:7b` is provided via `Modelfile` for best results:

```bash
# Install Ollama: https://ollama.com
ollama pull llama3.1        # general-purpose default
# or build the custom wazuh-tuned model:
ollama create wazuh-decoder -f Modelfile
# then set in .env: OLLAMA_MODEL=wazuh-decoder
```

### 5. Start the Application

```bash
uvicorn app.main:app \
  --host 0.0.0.0 --port 8443 \
  --ssl-certfile certs/localhost.crt \
  --ssl-keyfile certs/localhost.key
```

Open **`https://localhost:8443`** in your browser (or `https://<server-ip>:8443` when running on the Wazuh server).

> On first startup, the RAG vector store is built automatically in the background (~1–2 min). The app is fully usable while it builds.

---

## AI Provider Configuration

The app supports three AI providers. Configure **one** in `.env` or via environment variables:

### Ollama (Recommended — Local, No Rate Limits)

```bash
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1:latest   # or wazuh-decoder, qwen2.5:7b, etc.
```

Accepts both `http://localhost:11434` and `http://localhost:11434/v1` — the `/v1` suffix is normalised automatically.

### DashScope (Alibaba Cloud — Qwen)

```bash
DASHSCOPE_API_KEY=your_key_here
```

### OpenRouter

```bash
OPENROUTER_API_KEY=your_key_here
```

**Priority:** Ollama → DashScope → OpenRouter. Ollama is always preferred when `OLLAMA_BASE_URL` is set.

---

## Wazuh Integration

### Mode A — Local (On-server)

When `WAZUH_REMOTE_ENABLED=false`, the app calls `wazuh-logtest` and writes files directly on the local machine.

If the app runs as a non-root user, enable sudo:

```bash
WAZUH_USE_SUDO=true
# WAZUH_SUDO_PASSWORD=yourpassword   # omit if passwordless sudo is configured
```

Override the logtest binary path if needed:

```bash
WAZUH_LOGTEST_PATH=/var/ossec/bin/wazuh-logtest   # default
```

### Mode B — Remote Wazuh Server (SSH)

Set `WAZUH_REMOTE_ENABLED=true` and provide SSH credentials:

```bash
WAZUH_REMOTE_ENABLED=true
WAZUH_SSH_HOST=192.168.56.10
WAZUH_SSH_PORT=22
WAZUH_SSH_USER=vagrant
WAZUH_SSH_PASSWORD=vagrant
# optional — key-based auth instead of password:
# WAZUH_SSH_KEY=/path/to/private_key
```

When SSH is configured, the app will:
- Run `wazuh-logtest` over SSH to validate logs against your live Wazuh instance
- Write generated decoder/rule XML directly to `/var/ossec/etc/decoders/` and `/var/ossec/etc/rules/` on the remote server

---

## ML Similarity Model

The app uses an ensemble of **TF-IDF (30%) + SBERT (70%)** to find the closest official Wazuh decoder patterns for any new log.

### Configuration

```bash
WAZUH_REPO_URL=https://github.com/wazuh/wazuh.git
WAZUH_REPO_CACHE_DIR=/path/to/cache/wazuh_repo    # default: data/wazuh_repo
WAZUH_REPO_DECODER_SUBPATH=ruleset/decoders
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

The vector store is saved to `data/rag_store/` and persists across restarts.

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Web UI |
| `/api/analyze` | POST | Analyze a log — run logtest, extract fields, ML suggestions |
| `/api/generate` | POST | Generate decoder + rule XML (programmatic only) |
| `/api/ai/generate` | POST | Generate decoder + rule XML with AI (RAG + LLM) |
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
WAZUH_DECODERS_DIR=/custom/decoders
WAZUH_RULES_DIR=/custom/rules
```

---

## Environment Variable Reference

| Variable | Default | Description |
|---|---|---|
| `WAZUH_REMOTE_ENABLED` | `false` | `true` = SSH mode, `false` = local/on-server mode |
| `WAZUH_USE_SUDO` | `false` | Use `sudo` for local logtest and file writes (when not running as root) |
| `WAZUH_SUDO_PASSWORD` | *(none)* | Sudo password — omit if passwordless sudo is configured |
| `WAZUH_LOGTEST_PATH` | `/var/ossec/bin/wazuh-logtest` | Path to wazuh-logtest binary |
| `WAZUH_SSH_HOST` | *(none)* | SSH host for remote Wazuh server (Mode B only) |
| `WAZUH_SSH_PORT` | `22` | SSH port (Mode B only) |
| `WAZUH_SSH_USER` | *(none)* | SSH username (Mode B only) |
| `WAZUH_SSH_PASSWORD` | *(none)* | SSH password (Mode B only) |
| `WAZUH_SSH_KEY` | *(none)* | Path to SSH private key (Mode B only) |
| `WAZUH_DECODERS_DIR` | `/var/ossec/etc/decoders` | Output directory for decoder XML |
| `WAZUH_RULES_DIR` | `/var/ossec/etc/rules` | Output directory for rule XML |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API base URL |
| `OLLAMA_MODEL` | `llama3.1:latest` | Ollama model name |
| `DASHSCOPE_API_KEY` | *(none)* | DashScope API key |
| `OPENROUTER_API_KEY` | *(none)* | OpenRouter API key |
| `WAZUH_REPO_URL` | `https://github.com/wazuh/wazuh.git` | Wazuh repo for ML training data |
| `WAZUH_REPO_CACHE_DIR` | `data/wazuh_repo` | Local cache for Wazuh repo |
