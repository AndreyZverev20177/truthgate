"""Реестр валидаторов по каноническому enum'у.

Единственная точка регистрации — `VulnerabilityClass` (15 значений).
Никаких строковых алиасов на этом слое: LLM/scanner прислали `bug_class`
строкой → нормализация в `tools.validators.normalize.normalize_vuln_class`
(входная граница) → enum → `registry.get(vc)`.

Именно так исправляется ошибка disform'а: реестр `bug_class(str) → Validator`
с 13 строковыми алиасами превращался в непредсказуемый источник несоответствий
(«BOLA»/«bola»/«broken_object_level_authz»/`idor` — четыре разных ключа для
одной сущности). Здесь ключ — только enum, поэтому промах невозможен.
"""

from __future__ import annotations

from collections.abc import Callable

from tools.core.vulnerability_class import VulnerabilityClass
from tools.validators.base import BaseValidator

_REGISTRY: dict[VulnerabilityClass, BaseValidator] = {}


def register(
    vc: VulnerabilityClass,
) -> Callable[[type[BaseValidator]], type[BaseValidator]]:
    """Декоратор для регистрации валидатора по каноническому enum'у."""

    def _wrap(cls: type[BaseValidator]) -> type[BaseValidator]:
        inst = cls()
        if not isinstance(inst, BaseValidator):
            raise TypeError(
                f"{cls.__name__} должен наследоваться от BaseValidator "
                f"(получено: {type(inst).__mro__})"
            )
        if inst.vulnerability_class is not vc:
            raise ValueError(
                f"{cls.__name__}.vulnerability_class = {inst.vulnerability_class!r} "
                f"не совпадает с ключом реестра {vc!r}"
            )
        _REGISTRY[vc] = inst
        return cls

    return _wrap


def get(vc: VulnerabilityClass) -> BaseValidator | None:
    """Вернуть зарегистрированный валидатор для класса или None."""
    return _REGISTRY.get(vc)


def known_classes() -> list[VulnerabilityClass]:
    """Список классов, у которых есть зарегистрированный валидатор."""
    return sorted(_REGISTRY.keys(), key=lambda v: v.value)


def clear() -> None:
    """Только для тестов — сбросить реестр между прогонами."""
    _REGISTRY.clear()
