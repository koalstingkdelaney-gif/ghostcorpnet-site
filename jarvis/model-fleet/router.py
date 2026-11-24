#!/usr/bin/env python3
"""Small, dependency-free, local-first Ollama adapter for Jarvis.

This is a connection scaffold. It does not start Ollama or download model weights.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE = "http://127.0.0.1:11434"
ROUTES = {
    "classify": ("JARVIS_MODEL_CLASSIFY", "qwen3:0.6b"),
    "general": ("JARVIS_MODEL_GENERAL", "qwen3:1.7b"),
    "reasoning": ("JARVIS_MODEL_REASONING", "deepseek-r1:1.5b"),
    "code": ("JARVIS_MODEL_CODE", "qwen2.5-coder:1.5b"),
    "long_context": ("JARVIS_MODEL_LONG_CONTEXT", "phi3.5:latest"),
}


def endpoint():
    base = os.environ.get("JARVIS_OLLAMA_URL", DEFAULT_BASE).rstrip("/")
    parsed = urllib.parse.urlparse(base)
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and parsed.hostname not in local_hosts:
        raise RuntimeError("Remote model endpoints must use HTTPS behind an authenticated private gateway.")
    if parsed.hostname not in local_hosts and not os.environ.get("JARVIS_REMOTE_MODEL_AUTH_TOKEN"):
        raise RuntimeError("Remote model endpoint requires JARVIS_REMOTE_MODEL_AUTH_TOKEN.")
    headers = {"Content-Type": "application/json"}
    token = os.environ.get("JARVIS_REMOTE_MODEL_AUTH_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    return base, headers


def request(path, payload=None):
    base, headers = endpoint()
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(base + path, data=data, headers=headers, method="GET" if data is None else "POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise RuntimeError("Local model service is unavailable: " + str(exc)) from exc


def list_models():
    result = request("/api/tags")
    return [m.get("name", "") for m in result.get("models", []) if m.get("name")]


def health():
    names = list_models()
    print(json.dumps({"ok": True, "provider": "ollama-local", "models_installed": names}, indent=2))
    return 0


def chat(task, prompt):
    if task not in ROUTES:
        raise RuntimeError("Unknown task. Choose one of: " + ", ".join(ROUTES))
    env_name, default_model = ROUTES[task]
    model = os.environ.get(env_name, default_model)
    installed = list_models()
    if model not in installed:
        raise RuntimeError("Model is not installed: " + model + ". Pull it on the authorized host first; this adapter never downloads models.")
    result = request("/api/chat", {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False
    })
    answer = result.get("message", {}).get("content", "")
    if not answer:
        raise RuntimeError("Model returned an empty response.")
    print(answer)
    return 0


def main(argv):
    if len(argv) < 2 or argv[1] not in {"health", "list", "chat"}:
        print("Usage: router.py health | list | chat <task> <prompt>")
        return 2
    try:
        if argv[1] == "health":
            return health()
        if argv[1] == "list":
            print("\n".join(list_models()))
            return 0
        if len(argv) < 4:
            print("Usage: router.py chat <task> <prompt>")
            return 2
        return chat(argv[2], " ".join(argv[3:]))
    except Exception as exc:
        print("ERROR:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
