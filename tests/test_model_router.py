import os

import pytest

from jarvis.model_fleet import router


def test_task_routes_are_local_model_candidates():
    assert set(router.ROUTES) == {"classify", "general", "reasoning", "code", "long_context"}
    assert all(default for _, default in router.ROUTES.values())


def test_remote_plain_http_is_rejected(monkeypatch):
    monkeypatch.setenv("JARVIS_OLLAMA_URL", "http://example.com:11434")
    monkeypatch.delenv("JARVIS_REMOTE_MODEL_AUTH_TOKEN", raising=False)
    with pytest.raises(RuntimeError):
        router.endpoint()


def test_remote_https_requires_token(monkeypatch):
    monkeypatch.setenv("JARVIS_OLLAMA_URL", "https://models.example.net")
    monkeypatch.delenv("JARVIS_REMOTE_MODEL_AUTH_TOKEN", raising=False)
    with pytest.raises(RuntimeError):
        router.endpoint()


def test_localhost_default_needs_no_credentials(monkeypatch):
    monkeypatch.delenv("JARVIS_OLLAMA_URL", raising=False)
    monkeypatch.delenv("JARVIS_REMOTE_MODEL_AUTH_TOKEN", raising=False)
    base, headers = router.endpoint()
    assert base == "http://127.0.0.1:11434"
    assert "Authorization" not in headers
