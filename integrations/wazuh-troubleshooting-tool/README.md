# Wazuh Troubleshooting & Operations Portal

A dedicated, unified web portal designed to assess, diagnostic-report, and troubleshoot Wazuh deployments. The system provides real-time health checks, interactive diagnostic guides, and native vector reporting.

## Key Features

1. **Operations Reporting Center**: Natively generated interactive diagnostic report modules (Agent Fleet Health, Indexer Pipeline, Cluster health, Environmental assessments, and Security Events) with offline simulation support and print-formatted PDF/HTML export capabilities.
2. **Interactive Diagnostic Wizards**: Step-by-step troubleshooting wizards for common Wazuh issues like alerts not showing, indexing pipeline errors, and database cluster yellow/red states.
3. **AI troubleshooting Assistant**: Context-aware AI chat guidance for platform operators.
4. **Secure Architecture**: Strictly parameterized execution sinks (no direct credential mentions or hardcoded connection URLs in any source code file).

## Directory Structure

```text
wazuh-ai-tool/
├── config                     # Consolidated API, Indexer, and Kibana credentials
├── README.md
├── start.sh                   # Dev environment daemon launcher
├── backend/                   # Python FastAPI backend server
│   ├── config.py              # Dynamically loads credentials from ../config
│   ├── main.py                # Operations API & status routes
│   ├── use_cases/             # Parameterized troubleshooting scripts
│   └── utils/                 # OS logging and correction modules
└── frontend/                  # HTML5/CSS/JS frontend views
    ├── index.html             # Operations UI layout
    ├── reports.js             # SVG charts & report export engine
    └── app.js                 # App routing & status checkers
```

## Centralized Configuration

All credentials and API endpoint URLs are defined in a single file in the project's root folder: `/home/vagrant/wazuh-ai-tool/config`.

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
```

## Getting Started

To launch the portal backend (port `8000`) and the web interface (port `3000`), run the startup script from the root directory:

```bash
./start.sh
```

Navigate to `http://<your-server-ip>:3000` to access the portal.
