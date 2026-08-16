"""Legacy тесты для `orchestrator.registry` shim'а (deprecation-путь).

Проверяют, что старые вызовы (`register("sqli")`, `get("SQLI")`, `norm_class("BOLA")`)
продолжают работать через shim, переадресуя в новый enum-registry. Само содержание
логики перенесено в `tests/unit/test_registry.py` и `tests/unit/test_normalize.py`.
"""

from __future__ import annotations

import warnings

# Импорт вызывает DeprecationWarning — глушим на модульном уровне (тесты shim'а).
with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from orchestrator import registry

from orchestrator.types import ValidatorContext, Verdict


def test_norm_class_aliases_through_shim() -> None:
    assert registry.norm_class("BOLA") == "idor"
    assert registry.norm_class("path-traversal") == "lfi"
    assert registry.norm_class("SSRF") == "ssrf"


def test_legacy_register_and_get() -> None:
    """Старый `register("sqli")` над dummy-классом — работает через shim."""

    @registry.register("sqli")
    class _V:
        bug_class = "sqli"

        def validate(self, finding: dict, ctx: ValidatorContext) -> Verdict:
            _ = finding, ctx
            return Verdict(True, "ok", 1.0, "sqli", "V")

    v = registry.get("SQLI")
    assert v is not None
    # shim положил dummy-класс "как есть" (не BaseValidator) — вызов работает
    out = v.validate({}, ValidatorContext(target="x"))
    assert out.is_real


def test_get_missing_returns_none() -> None:
    assert registry.get("does_not_exist") is None


def test_known_classes_returns_strings() -> None:
    """Legacy API — список строк (enum.value), не enum."""
    result = registry.known_classes()
    assert all(isinstance(x, str) for x in result)
