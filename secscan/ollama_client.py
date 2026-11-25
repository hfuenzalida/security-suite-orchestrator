"""Local Ollama HTTP client."""

from __future__ import annotations

import json
import urllib.error
import urllib.request


def ollama_generate(
    prompt: str,
    model: str,
    *,
    num_predict: int = 512,
    temperature: float = 0.2,
    timeout: int = 120,
) -> tuple[str | None, str | None]:
    """POST to local Ollama /api/generate. Returns (response_text, error_message)."""
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature, "num_predict": num_predict},
    }).encode()
    try:
        req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw_body = resp.read()
            data = json.loads(raw_body)
            if not isinstance(data, dict):
                return (None, f"Ollama: expected JSON object, got {type(data).__name__}")
            err_o = data.get("error")
            if err_o:
                return (None, f"Ollama: {err_o}")
            resp_text = data.get("response")
            if resp_text is None:
                return (None, "Ollama: missing response field (is the model pulled and running?)")
            return (str(resp_text).strip(), None)
    except urllib.error.URLError as e:
        return (None, f"Ollama unreachable: {e.reason}")
    except Exception as e:
        return (None, str(e))
