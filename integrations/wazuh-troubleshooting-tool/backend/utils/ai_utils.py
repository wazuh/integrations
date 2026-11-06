from copilot_engine import run_copilot
from config import OLLAMA_URL, OLLAMA_MODEL


def ai_explain(system_prompt, user_content):
    """Send `user_content` (e.g. raw log text) to the local model under a
    focused `system_prompt` and return its plain-text reply. Never raises -
    returns a readable message instead if Ollama is unreachable."""
    try:
        return run_copilot(
            messages=[{"role": "user", "content": user_content}],
            ollama_url=OLLAMA_URL,
            ollama_model=OLLAMA_MODEL,
            include_env=False,
            wazuh_api_url="", api_username="", api_password="",
            indexer_url="", indexer_username="", indexer_password="",
            system_prompt=system_prompt,
        )
    except Exception as e:
        return f"(AI explanation unavailable: {e})"
