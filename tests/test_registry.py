from __future__ import annotations

from orchestrator import registry
from orchestrator.types import ValidatorContext, Verdict


def test_norm_class_aliases() -> None:
    assert registry.norm_class("BOLA") == "idor"
    assert registry.norm_class("path-traversal") == "lfi"
    assert registry.norm_class("SSRF") == "ssrf"


def test_register_and_get() -> None:
    @registry.register("sqli")
    class _V:
        bug_class = "sqli"

        def validate(self, finding: dict, ctx: ValidatorContext) -> Verdict:
            _ = finding, ctx
            return Verdict(
                is_real=True,
                evidence="ok",
                confidence=1.0,
                bug_class="sqli",
                validator="V",
            )

    v = registry.get("SQLI")
    assert v is not None
    out = v.validate({}, ValidatorContext(target="x"))
    assert out.is_real


def test_get_missing_returns_none() -> None:
    assert registry.get("does_not_exist") is None
