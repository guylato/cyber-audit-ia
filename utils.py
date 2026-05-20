import json
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
from fastapi import HTTPException

import state as _state
from config import CANARY_SECRETS, OLLAMA_URL, SENSITIVE_PATTERNS, TIMEOUT_SECONDS


def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4()}"


def next_patch_id() -> str:
    _state.state["last_patch_id"] += 1
    return f"SEC-2026-{_state.state['last_patch_id']:03d}"


def get_agent(agent_id: str) -> Dict[str, Any]:
    agent = _state.state["agents"].get(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent introuvable: {agent_id}")
    return agent


def history_event(event_type: str, agent_id: str, payload: Dict[str, Any]) -> None:
    _state.state["global_history"].append({
        "timestamp": now_iso(),
        "event_type": event_type,
        "agent_id": agent_id,
        "payload": payload,
    })


def llm(prompt: str, model: str, temperature: float = 0.2) -> str:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature},
    }
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.json().get("response", "").strip()
    except requests.exceptions.ConnectionError:
        raise HTTPException(status_code=503, detail="Impossible de joindre Ollama. Lance 'ollama serve'.")
    except requests.exceptions.Timeout:
        raise HTTPException(status_code=504, detail=f"Timeout Ollama après {TIMEOUT_SECONDS}s.")
    except requests.exceptions.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Erreur HTTP Ollama: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur Ollama inattendue: {exc}")


def llm_safe(prompt: str, model: str, temperature: float = 0.2, default: str = "") -> str:
    try:
        return llm(prompt, model, temperature)
    except Exception as e:
        print(f"[WARN] llm_safe error: {e}")
        return default


def safe_json_parse(raw: str) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        pass
    try:
        start = raw.index("{")
        end = raw.rindex("}") + 1
        return json.loads(raw[start:end])
    except Exception:
        return None


def redact_sensitive_text(text: str) -> str:
    if not text:
        return text
    redacted = text
    patterns = [
        "API_KEY", "SECRET", "PASSWORD", "TOKEN", "sk-", "Bearer ",
        CANARY_SECRETS["api_key"],
        CANARY_SECRETS["db_password"],
        CANARY_SECRETS["access_token"],
        CANARY_SECRETS["internal_secret"],
    ]
    for p in patterns:
        redacted = redacted.replace(p, "[REDACTED]")
    return redacted


def create_alert(agent_id: str, severity: str, title: str, details: str) -> Dict[str, Any]:
    alert = {
        "alert_id": new_id("alert"),
        "timestamp": now_iso(),
        "severity": severity,
        "title": title,
        "details": details,
    }
    get_agent(agent_id)["alerts"].append(alert)
    history_event("alert", agent_id, alert)
    return alert


def contains_sensitive_pattern(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    return any(re.search(pattern, lowered) for pattern in SENSITIVE_PATTERNS)


def contains_canary_secret(text: str) -> List[str]:
    if not text:
        return []
    leaked = []
    lowered = text.lower()
    for key, value in CANARY_SECRETS.items():
        if value.lower() in lowered:
            leaked.append(key)
    return leaked
