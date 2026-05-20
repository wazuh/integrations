# Wazuh Decoder Rule Creator MVP

A small FastAPI app that:
- analyzes pasted logs with heuristics,
- checks logs against `wazuh-logtest` first and reuses built-ins when they exist,
- learns decoder patterns from official Wazuh decoders in the Wazuh GitHub repo (ML similarity model),
- generates custom decoder XML only when no decoder matches,
- generates custom rule XML from natural-language requirement when provided,
- tests each sample against `/var/ossec/bin/wazuh-logtest` when available.

## What is included

- `app/main.py` – backend API and HTML UI
- `app/templates/index.html` – single-page frontend
- `app/static/*` – JS and CSS
- `requirements.txt`

## Run locally

To run the application over HTTPS on port 8443 (ideal for secure access from other machines):

1. **Set up the virtual environment and install dependencies:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. **Generate SSL Certificates:**
Create a `certs` directory and generate a self-signed certificate:
```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/localhost.key -out certs/localhost.crt -days 365 -nodes -subj "/CN=localhost"
```

3. **Start the Application:**
Run `uvicorn` with the generated certificates:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8443 --ssl-certfile certs/localhost.crt --ssl-keyfile certs/localhost.key --reload
```

Open `https://localhost:8443` (or use your machine's IP address). Note: You may need to bypass your browser's self-signed certificate warning.

## Wazuh integration

By default the app looks for:

```bash
/var/ossec/bin/wazuh-logtest
```

You can override that path:

```bash
export WAZUH_LOGTEST_PATH=/custom/path/to/wazuh-logtest
```

### Remote VM mode (SSH)

If Wazuh runs in a VM, configure:

```bash
export WAZUH_SSH_HOST=127.0.0.1
export WAZUH_SSH_PORT=2222
export WAZUH_SSH_USER=vagrant
export WAZUH_SSH_PASSWORD=vagrant
# optional:
export WAZUH_SSH_KEY=/path/to/private_key
```

For this workspace, the app now defaults to:

```bash
WAZUH_SSH_HOST=192.168.56.10
WAZUH_SSH_PORT=22
WAZUH_SSH_USER=vagrant
WAZUH_SSH_PASSWORD=vagrant
```

Environment variables still override these defaults.

When `WAZUH_SSH_HOST` and `WAZUH_SSH_USER` are set, the app will:
- run `wazuh-logtest` over SSH with sudo
- write `local_*.xml` directly to `/var/ossec/etc/decoders` and `/var/ossec/etc/rules` on the VM

## ML decoder learning

The app can build a similarity model from official Wazuh decoders in a cached clone of:

```bash
https://github.com/wazuh/wazuh.git
```

Config:

```bash
export WAZUH_REPO_URL=https://github.com/wazuh/wazuh.git
export WAZUH_REPO_CACHE_DIR=/path/to/cache/wazuh_repo
export WAZUH_REPO_DECODER_SUBPATH=ruleset/decoders
```

API:

- `GET /api/ml/status` shows model and cache status.
- `POST /api/ml/refresh` refreshes the repo cache and rebuilds the model.

### Training a better similarity model (SentenceTransformer)

1. Ensure the Wazuh repo cache exists (run the app once or `POST /api/ml/refresh`).
2. Build a dataset:
   ```bash
   python scripts/build_dataset.py
   ```
   Outputs `data/datasets/train.jsonl` and `val.jsonl`.
3. Train a small SBERT model:
   ```bash
   python scripts/train_similarity.py
   ```
   Outputs `data/models/decoder-sbert/`.
4. Set `ML_MODEL_DIR=data/models/decoder-sbert` (or leave default) and restart the app. If `sentence-transformers` is installed (see `requirements.txt`), ML suggestions will use the trained model; otherwise the TF‑IDF fallback is used.

If you are following your VM-based workflow, run `/api/ml/refresh` once, then test logs through `/api/test` with remote mode enabled.

## ML integration plan

The current analyzer is heuristic-first. Replace `analyze_logs_impl()` and/or add a new service that:

1. retrieves similar approved decoders/rules,
2. asks an LLM to emit structured JSON,
3. renders XML from JSON,
4. validates every candidate with `wazuh-logtest`.

A safe production loop is:

- ML proposes
- XML renderer normalizes
- `wazuh-logtest` validates
- regression suite accepts or rejects

## Optional file output

The `/api/test` endpoint supports `install_mode="write_files"` and writes generated files to:

- `/var/ossec/etc/decoders/`
- `/var/ossec/etc/rules/`

Override these with:

```bash
export WAZUH_DECODERS_DIR=/custom/decoders
export WAZUH_RULES_DIR=/custom/rules
```
