import os

GATEWAY_API_KEY = os.getenv("GATEWAY_API_KEY", "secret")
PORT = int(os.getenv("PORT", "9912"))
VERBOSE = os.getenv("VERBOSE", "false").lower() == "true"
DEBUG_ACTION_OUTPUT = os.getenv("DEBUG_ACTION_OUTPUT", "false").lower() == "true"

MCP_SSE_URL = os.getenv("MCP_SSE_URL", "")

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai").lower()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.2")

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-pro")

ALERTS_INDEX = os.getenv("ALERTS_INDEX", "wazuh-alerts-*")
VULN_INDEX = os.getenv("VULN_INDEX", "wazuh-states-vulnerabilities-*")
INVENTORY_INDEX = os.getenv("INVENTORY_INDEX", "wazuh-states-inventory-*")
DEFAULT_TIME_WINDOW = os.getenv("DEFAULT_TIME_WINDOW", "now-30m")

SOC_PROMPT_PATH = os.getenv("SOC_PROMPT_PATH", "/etc/mcp-llm-gateway/mcp-llm-gateway.prompt")

DQL_PROMPT_PATH = os.getenv("DQL_PROMPT_PATH", "/etc/mcp-llm-gateway/dql-builder.prompt")
INVENTORY_PROMPT_PATH = os.getenv("INVENTORY_PROMPT_PATH", "/etc/mcp-llm-gateway/inventory-builder.prompt")
REPORT_PROMPT_PATH = os.getenv("REPORT_PROMPT_PATH", "/etc/mcp-llm-gateway/report-generator.prompt")

STAGING_WAZUH_API_URL = os.getenv("STAGING_WAZUH_API_URL", "").rstrip("/")
STAGING_WAZUH_API_USER = os.getenv("STAGING_WAZUH_API_USER", "")
STAGING_WAZUH_API_PASS = os.getenv("STAGING_WAZUH_API_PASS", "")
STAGING_WAZUH_API_VERIFY_TLS = os.getenv("STAGING_WAZUH_API_VERIFY_TLS", "true").lower() == "true"

WAZUH_API_URL = os.getenv("WAZUH_API_URL", "").rstrip("/")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "")
WAZUH_API_PASS = os.getenv("WAZUH_API_PASS", "")
WAZUH_API_VERIFY_TLS = os.getenv("WAZUH_API_VERIFY_TLS", "true").lower() == "true"



ACTION_CONFIRM_TTL = int(os.getenv("ACTION_CONFIRM_TTL", "300"))
AGENTS_CACHE_TTL = int(os.getenv("AGENTS_CACHE_TTL", "0"))

OPENSEARCH_DASHBOARD_URL = os.getenv("OPENSEARCH_DASHBOARD_URL", "").rstrip("/")
OPENSEARCH_DASHBOARD_USER = os.getenv("OPENSEARCH_DASHBOARD_USER", "")
OPENSEARCH_DASHBOARD_PASS = os.getenv("OPENSEARCH_DASHBOARD_PASS", "")
OPENSEARCH_DASHBOARD_VERIFY_TLS = os.getenv("OPENSEARCH_DASHBOARD_VERIFY_TLS", "true").lower() == "true"
OPENSEARCH_DASHBOARD_CA_FILE = os.getenv("OPENSEARCH_DASHBOARD_CA_FILE", "").strip()
OPENSEARCH_DASHBOARD_BASEPATH = os.getenv("OPENSEARCH_DASHBOARD_BASEPATH", "").strip()
OPENSEARCH_DASHBOARD_SPACE = os.getenv("OPENSEARCH_DASHBOARD_SPACE", "").strip()

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", os.getenv("OPENSEARCH_URL", "")).rstrip("/")
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", os.getenv("OPENSEARCH_USER", ""))
WAZUH_INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASS", os.getenv("OPENSEARCH_PASS", ""))
WAZUH_INDEXER_VERIFY_TLS = os.getenv("WAZUH_INDEXER_VERIFY_TLS", os.getenv("OPENSEARCH_VERIFY_TLS", "true")).lower() == "true"
WAZUH_INDEXER_CA_FILE = os.getenv("WAZUH_INDEXER_CA_FILE", os.getenv("OPENSEARCH_CA_FILE", "")).strip()

WIZARD_TTL = int(os.getenv("WIZARD_TTL", "900"))
AUTO_CREATE_INDEX_PATTERN = os.getenv("AUTO_CREATE_INDEX_PATTERN", "true").lower() == "true"

SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", "25"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", "wazuh-ai@localhost")

# For generating external links (e.g., PDF downloads) when behind NAT/Proxy
PUBLIC_GATEWAY_URL = os.getenv("PUBLIC_GATEWAY_URL", "")
