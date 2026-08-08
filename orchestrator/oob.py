"""OOB-адаптеры: реализация `OOBProvider` из types.py.

InteractshClient — тонкая обёртка над своим interactsh-сервером (URL + токен).
StubOOB — детерминированный in-memory для тестов и dry-run.
"""

from __future__ import annotations

import secrets
import threading
import time
from typing import Any

import httpx

from orchestrator.types import OOBProvider


class StubOOB:
    """Не делает сетевых вызовов. Возвращает пустой список hits."""

    def __init__(self) -> None:
        self._tokens: dict[str, str] = {}
        self._lock = threading.Lock()

    def new_token(self, probe_id: str) -> tuple[str, str]:
        token = f"stub{secrets.token_hex(6)}"
        oob_url = f"http://oob.invalid/{token}"
        with self._lock:
            self._tokens[token] = probe_id
        return token, oob_url

    def poll(self, token: str, wait_s: float) -> list[dict[str, Any]]:
        _ = token, wait_s
        return []


class InteractshClient:
    """Взаимодействие со своим instance interactsh-server.

    Проверяется `OOBProvider`-протоколом. Тонкая обёртка: конкретный протокол
    interactsh (JSON-poll с ChaCha20-ключом) реализуется в M8 — здесь seam.
    """

    def __init__(self, base_url: str, token: str, timeout: float = 10.0) -> None:
        if not base_url:
            raise ValueError("interactsh base_url required")
        self.base = base_url.rstrip("/")
        self.token = token
        self._client = httpx.Client(timeout=timeout, verify=True)

    def new_token(self, probe_id: str) -> tuple[str, str]:
        # TODO(M8): реальный register endpoint + ChaCha ключ
        token = f"{probe_id}-{secrets.token_hex(4)}"
        oob_url = f"https://{token}.{self._domain()}"
        return token, oob_url

    def poll(self, token: str, wait_s: float) -> list[dict[str, Any]]:
        # TODO(M8): poll `/poll?id=…&secret=…`, decrypt, вернуть hits
        time.sleep(min(wait_s, 0.5))
        return []

    def _domain(self) -> str:
        return self.base.split("://", 1)[-1]

    def close(self) -> None:
        self._client.close()


assert isinstance(StubOOB(), OOBProvider)  # noqa: S101
