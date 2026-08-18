"""DEPRECATED — используйте `tools.validators.registry` + `tools.validators.normalize`.

Файл оставлен как **тонкий deprecation shim** после M1 п.3: старый registry с
13 строковыми алиасами удалён, единственный источник алиасов теперь —
`tools.validators.normalize.normalize_vuln_class` (входная граница), а реестр
валидаторов ключевируется каноническим `VulnerabilityClass` enum.
"""

from __future__ import annotations

import warnings
from collections.abc import Callable
from typing import Any

from tools.validators import registry as _new_registry
from tools.validators.base import BaseValidator
from tools.validators.normalize import normalize_vuln_class

warnings.warn(
    "orchestrator.registry is deprecated; use tools.validators.registry "
    "and tools.validators.normalize.normalize_vuln_class instead",
    DeprecationWarning,
    stacklevel=2,
)

ALIASES: dict[str, str] = {}


def norm_class(raw: str) -> str:
    vc = normalize_vuln_class(raw)
    return vc.value if vc else raw.strip().lower().replace("-", "_")


def register(*classes: str) -> Callable[[type[Any]], type[Any]]:
    def _wrap(cls: type[Any]) -> type[Any]:
        if not issubclass(cls, BaseValidator):
            for c in classes:
                vc = normalize_vuln_class(c)
                if vc is not None:
                    _new_registry._REGISTRY[vc] = cls()  # type: ignore[assignment]
            return cls
        for c in classes:
            vc = normalize_vuln_class(c)
            if vc is None:
                raise ValueError(f"unknown class in legacy register(): {c!r}")
            _new_registry.register(vc)(cls)
        return cls

    return _wrap


def get(raw: str) -> Any | None:
    vc = normalize_vuln_class(raw)
    return _new_registry.get(vc) if vc is not None else None


def known_classes() -> list[str]:
    return [v.value for v in _new_registry.known_classes()]


def clear() -> None:
    _new_registry.clear()
