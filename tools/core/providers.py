"""Контракты внешних поставщиков (auth, OOB) — только Protocol, без реализаций.

Реализации живут в `orchestrator/oob.py` и (позже) `orchestrator/auth.py`. Здесь —
типовые границы, чтобы `ValidatorContext` держал их как Protocol-поля.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class AuthProvider(Protocol):
    """HTTP-opener для роли — для authz-классов (idor/bola/bfla)."""

    def opener(self, role: str) -> Any: ...
    def unauth_opener(self) -> Any: ...


@runtime_checkable
class OOBProvider(Protocol):
    """OAST-инстанс (свой interactsh) для ssrf/xxe/blind-классов."""

    def new_token(self, probe_id: str) -> tuple[str, str]: ...
    def poll(self, token: str, wait_s: float) -> list[dict[str, Any]]: ...
