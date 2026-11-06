from use_cases import run_use_cases
from copilot_engine import run_copilot
from config import (
    WAZUH_API_URL,
    API_USERNAME,
    API_PASSWORD,
    INDEXER_USERNAME,
    INDEXER_PASSWORD,
    INDEXER_URL,
    OLLAMA_URL,
    OLLAMA_MODEL,
)

def process_assistant(user_input, context=None):
    if context is None:
        context = {}

    # 1. Try to run guided diagnostic use cases
    try:
        result = run_use_cases(user_input, context)
    except Exception as e:
        print(f"Error in guided use case: {e}")
        result = None

    if result:
        # Predefined use cases take precedence
        return {
            "type": "use_case",
            "display": result.get("display", ""),
            "ask": result.get("ask", []),
            "done": result.get("done", False),
            "context": result.get("context", {})
        }

    # 2. Fall back to Ollama conversational AI
    history = context.get("ollama_history", [])
    history.append({"role": "user", "content": user_input})

    try:
        reply = run_copilot(
            messages=history,
            ollama_url=OLLAMA_URL,
            ollama_model=OLLAMA_MODEL,
            include_env=True,
            wazuh_api_url=WAZUH_API_URL,
            api_username=API_USERNAME,
            api_password=API_PASSWORD,
            indexer_url=INDEXER_URL,
            indexer_username=INDEXER_USERNAME,
            indexer_password=INDEXER_PASSWORD,
        )
        history.append({"role": "assistant", "content": reply})
        context["ollama_history"] = history

        return {
            "type": "use_case",
            "display": reply,
            "ask": [],
            "done": False,
            "context": context
        }
    except Exception as e:
        return {
            "type": "info",
            "message": f"Error from Ollama: {str(e)}"
        }
