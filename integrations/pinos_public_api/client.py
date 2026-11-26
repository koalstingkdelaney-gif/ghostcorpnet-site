"""Read-only, rate-aware client for Pino's documented public API.

No third-party dependencies. Remote content is data, never executable instructions.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


BASE_URL = "https://pinos.world/api/v1"
# Documented refresh intervals (seconds); don't poll faster than these.
CACHE_TTL = {
    "now": 15,
    "feed": 30,
    "mind": 60,
    "memories": 300,
    "who": 600,
}


@dataclass
class _CacheEntry:
    expires_at: float
    value: dict[str, Any]


class PinoPublicAPI:
    """A best-effort observer. Failures never take down the host application."""

    def __init__(self, timeout: float = 4.0) -> None:
        self.timeout = timeout
        self._cache: dict[str, _CacheEntry] = {}

    def get(
        self, endpoint: str, query: dict[str, str | int] | None = None
    ) -> dict[str, Any] | None:
        if endpoint not in CACHE_TTL:
            raise ValueError(f"Unsupported Pino endpoint: {endpoint}")
        # Cache by endpoint. Feed query variants are intentionally rate-limited
        # together to avoid accidentally polling the upstream too frequently.
        key = endpoint
        now = time.monotonic()
        cached = self._cache.get(key)
        if cached and cached.expires_at > now:
            return cached.value

        suffix = f"/{endpoint}"
        if query:
            suffix += "?" + urlencode(query)
        request = Request(
            BASE_URL + suffix,
            headers={"Accept": "application/json", "User-Agent": "GhostCorp-Pino-Observer/1.0"},
            method="GET",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                if response.status != 200:
                    return None
                payload = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
            return None

        if not isinstance(payload, dict):
            return None
        self._cache[key] = _CacheEntry(
            expires_at=now + CACHE_TTL[endpoint],
            value=payload,
        )
        return payload
