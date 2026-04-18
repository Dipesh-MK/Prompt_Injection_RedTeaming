"""
rtf_core/ollama_detect.py
--------------------------
Auto-detection of locally available Ollama models.
Used to populate the attacker/judge model pickers in the sidebar.
Falls back gracefully if Ollama is not running.
"""

import requests
from rtf_core import settings


def get_available_models(base_url: str = None, timeout: int = 4) -> list[str]:
    """
    Query Ollama's /api/tags endpoint and return a list of installed model names.
    Returns an empty list if Ollama is unreachable (no crash).
    """
    # Derive the tags URL from the generate URL (strip /api/generate → root)
    url = base_url or settings.OLLAMA_URL
    # Normalise: handle both http://host/api/generate and http://host/
    root = url.split("/api/")[0].rstrip("/")
    tags_url = f"{root}/api/tags"

    try:
        r = requests.get(tags_url, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        models = [m["name"] for m in data.get("models", [])]
        return sorted(models)
    except Exception:
        return []


def pick_best_model(models: list[str], role: str) -> str | None:
    """
    Heuristically pick the best available model for a given role.
    'role' is one of: 'attacker', 'judge', 'mutator'

    Priority logic:
    - Judge needs a reasoning-capable model → prefer mistral, llama3, qwen, gemma
    - Attacker/Mutator are generative → any good model works
    Falls back to the first available model, then to the hardcoded default.
    """
    if not models:
        return None

    # Ordered preference lists (checked as substrings in model name)
    JUDGE_PREFS    = ["mistral", "llama3", "qwen", "gemma3", "gemma", "phi3", "phi"]
    ATTACKER_PREFS = ["mistral", "llama3", "gemma3", "qwen", "gemma", "phi3", "phi"]

    prefs = JUDGE_PREFS if role == "judge" else ATTACKER_PREFS

    for pref in prefs:
        for m in models:
            if pref in m.lower():
                return m

    # No preference matched — return the first available
    return models[0]


def suggest_models(models: list[str]) -> dict[str, str]:
    """
    Return a suggested config dict:
    { 'attacker': '...', 'judge': '...', 'mutator': '...' }
    """
    return {
        "attacker": pick_best_model(models, "attacker") or settings.ATTACKER_MODEL,
        "judge":    pick_best_model(models, "judge")    or settings.JUDGE_MODEL,
        "mutator":  pick_best_model(models, "mutator")  or settings.MUTATOR_MODEL,
    }
