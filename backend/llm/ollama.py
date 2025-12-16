import json
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "phi3"

def generate_response(prompt: str) -> str:
    try:
        payload = {
            "model": MODEL_NAME,
            "prompt": prompt,
            "stream": False
        }
        resp = requests.post(OLLAMA_URL, json=payload, timeout=60)
        if resp.status_code != 200:
            return ""
        data = resp.json()
        text = data.get("response") or ""
        return text
    except Exception:
        return ""
