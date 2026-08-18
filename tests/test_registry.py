"""Legacy тесты для `orchestrator.registry` shim'а (deprecation-путь)."""

from __future__ import annotations

import warnings

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from orchestrator import registry

from orchestrator.types import ValidatorContext, Verdict


def test_norm_class_aliases_through_shim() -> None:
    assert registry.norm_class("BOLA") == "idor"
    assert registry.norm_class("path-traversal") == "lfi"
    assert registry.norm_class("SSRF") == "ssrf"


def test_legacy_register_and_get() -> None:
    @registry.register("sqli")
    class _V:
        bug_class = "sqli"

        def validate(self, finding: dict, ctx: ValidatorContext) -> Verdict:
            _ = finding, ctx
            return Verdict(True, "ok", 1.0, "sqli", "V")

    v = registry.get("SQLI")
    assert v is not None
    out = v.validate({}, ValidatorContext(target="x"))
    assert out.is_real


def test_get_missing_returns_none() -> None:
    assert registry.get("does_not_exist") is None


def test_known_classes_returns_strings() -> None:
    result = registry.known_classes()
    assert all(isinstance(x, str) for x in result)
