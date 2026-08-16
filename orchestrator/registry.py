"""DEPRECATED — используйте `tools.validators.registry` + `tools.validators.normalize`.

Файл оставлен как **тонкий deprecation shim** после M1 п.3: старый registry с
13 строковыми алиасами удалён, единственный источник алиасов теперь —
`tools.validators.normalize.normalize_vuln_class` (входная граница), а реестр
валидаторов ключевируется каноническим `VulnerabilityClass` enum.

Shim переадресует старые вызовы (`register("sqli")`, `get("SQLI")`,
`norm_class("BOLA")`) в новые модули, добавляя `DeprecationWarning`.
Внутри репозитория новых импортов этого модуля быть НЕ должно — все
переведены; при физическом `git rm` файла (одна команда локально)
ничего не сломается. В этом PR удаление через MCP невозможно —
поэтому оставлен shim; удаление придёт следующим локальным commit'ом.
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

# Пусто — источник алиасов теперь `tools.validators.normalize._ALIASES`.
# Оставлено для обратной совместимости старых импортов, ссылающихся на
# `registry.ALIASES` (например, старый CLI-код при постепенной миграции).
ALIASES: dict[str, str] = {}


def norm_class(raw: str) -> str:
    """Legacy: строковый API поверх нового `normalize_vuln_class`."""
    vc = normalize_vuln_class(raw)
    return vc.value if vc else raw.strip().lower().replace("-", "_")


def register(*classes: str) -> Callable[[type[Any]], type[Any]]:
    """Legacy-декоратор: `register("sqli")` → нормализует и регистрирует в enum-registry.

    Работает только с классами-наследниками `BaseValidator`. Классы старого
    протокола (dummy-`.validate(finding, ctx)`) не пройдут — им нужен рефактор.
    """

    def _wrap(cls: type[Any]) -> type[Any]:
        if not issubclass(cls, BaseValidator):
            # Для тестов оставлен мягкий путь: если это dummy-класс из старых
            # тестов, регистрируем  как есть» в приватный old-style реестр
            # только для того, чтобы не поломать миграционные тесты. В прод
            # коде так делать нельзя.
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
    """Legacy-геттер по строке. Использует `normalize_vuln_class` + новый registry."""
    vc = normalize_vuln_class(raw)
    return _new_registry.get(vc) if vc is not None else None


def known_classes() -> list[str]:
    """Legacy: список строк вместо enum'ов."""
    return [v.value for v in _new_registry.known_classes()]


def clear() -> None:
    """Legacy: делегирует новому registry."""
    _new_registry.clear()
