"""Реестр валидаторов bug_class → Validator.

Класс-алиасы нормализуются в один канонический (напр. `idor` и `bola` → `idor`).
Валидаторы регистрируются декоратором `@register("idor", "bola")` при импорте.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from orchestrator.types import ValidatorContext, Verdict

ALIASES: dict[str, str] = {
    "bola": "idor",
    "broken_object_level_authz": "idor",
    "path_traversal": "lfi",
    "cmd_injection": "command_injection",
    "os_command_injection": "command_injection",
    "template_injection": "ssti",
    "server_side_template_injection": "ssti",
    "server_side_request_forgery": "ssrf",
    "cross_site_scripting": "xss",
    "xml_external_entity": "xxe",
    "prompt_inject": "prompt_injection",
    "rag_inject": "prompt_injection",
    "mem_poison": "prompt_injection",
}


@runtime_checkable
class Validator(Protocol):
    bug_class: str

    def validate(self, finding: dict[str, Any], ctx: ValidatorContext) -> Verdict: ...


_REGISTRY: dict[str, Validator] = {}


def norm_class(bug_class: str) -> str:
    key = bug_class.strip().lower().replace("-", "_")
    return ALIASES.get(key, key)


def register(*classes: str):  # noqa: ANN201
    def _wrap(cls: type) -> type:
        inst = cls()
        for c in classes:
            _REGISTRY[norm_class(c)] = inst  # type: ignore[assignment]
        return cls

    return _wrap


def get(bug_class: str) -> Validator | None:
    return _REGISTRY.get(norm_class(bug_class))


def known_classes() -> list[str]:
    return sorted(_REGISTRY.keys())


def clear() -> None:
    """Только для тестов."""
    _REGISTRY.clear()
