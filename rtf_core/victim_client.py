"""
rtf_core/victim_client.py
--------------------------
Generic webhook client that talks to ANY LLM endpoint.

Supports two payload formats automatically:
  1. OpenAI-compatible  → POST /v1/chat/completions
  2. Ollama generate    → POST /api/generate

The 'test_connection' method sends a harmless ping and returns
latency + a detail message so the UI can display a clear status.
"""

import time
import requests
import json
from typing import Optional


# ─── Payload builders ────────────────────────────────────────────────────────

def _build_openai_payload(message: str, model: Optional[str]) -> dict:
    payload = {
        "messages": [{"role": "user", "content": message}],
        "stream": False,
    }
    if model:
        payload["model"] = model
    return payload


def _build_ollama_payload(message: str, model: Optional[str]) -> dict:
    return {
        "model": model or "llama2",
        "prompt": message,
        "stream": False,
    }


def _extract_response_text(data: dict) -> str:
    """Normalise response from both OpenAI and Ollama formats."""
    # OpenAI format
    if "choices" in data:
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError):
            pass
    # Ollama format
    if "response" in data:
        return data["response"]
    # Raw text fallback
    if "content" in data:
        return data["content"]
    # Last resort — dump everything
    return json.dumps(data)[:500]


# ─── Main client class ───────────────────────────────────────────────────────

class VictimClient:
    """
    Stateless HTTP client for sending probes to a configured victim LLM.
    Instantiate with the user's saved victim configuration from session state.
    """

    def __init__(
        self,
        webhook_url: str,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = 30,
    ):
        self.webhook_url = webhook_url.rstrip("/")
        self.model_name  = model_name
        self.api_key     = api_key
        self.timeout     = timeout

        self._headers = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"

    # ── Detection ─────────────────────────────────────────────────────────────

    def _is_openai_compat(self) -> bool:
        """Guess format from URL path."""
        return (
            "chat/completions" in self.webhook_url
            or "openai" in self.webhook_url.lower()
            or "v1" in self.webhook_url
        )

    # ── Core send ─────────────────────────────────────────────────────────────

    def send(self, message: str) -> tuple[bool, str]:
        """
        Send a message to the victim webhook.
        Returns (success: bool, response_text: str).
        """
        # Try preferred format first, then fallback
        formats = (
            [_build_openai_payload, _build_ollama_payload]
            if self._is_openai_compat()
            else [_build_ollama_payload, _build_openai_payload]
        )

        last_error = ""
        for build_fn in formats:
            payload = build_fn(message, self.model_name)
            try:
                r = requests.post(
                    self.webhook_url,
                    json=payload,
                    headers=self._headers,
                    timeout=self.timeout,
                )
                if r.status_code < 300:
                    try:
                        data = r.json()
                        return True, _extract_response_text(data)
                    except Exception:
                        return True, r.text[:2000]
                else:
                    last_error = f"HTTP {r.status_code}: {r.text[:200]}"
            except requests.exceptions.ConnectionError:
                last_error = f"Cannot connect to {self.webhook_url}"
                break
            except requests.exceptions.Timeout:
                last_error = f"Request timed out after {self.timeout}s"
                break
            except Exception as e:
                last_error = str(e)

        return False, last_error

    # ── Connection test ───────────────────────────────────────────────────────

    def test_connection(self) -> tuple[bool, float, str]:
        """
        Send a harmless test message.
        Returns (ok: bool, latency_ms: float, detail: str).
        """
        test_msg = "Say 'OK' in one word."
        t0 = time.time()
        ok, response = self.send(test_msg)
        latency_ms = (time.time() - t0) * 1000

        if ok:
            detail = f"Response received in {latency_ms:.0f}ms — \"{response[:80]}\""
        else:
            detail = response

        return ok, latency_ms, detail
