"""Интеграционные тесты pipeline с новым enum-registry."""

from __future__ import annotations

from typing import Any

import pytest

from orchestrator.pipeline import (
    NoValidatorError,
    dedup_key,
    run_pipeline,
    validate_candidate,
)
from orchestrator.scope import Scope
from orchestrator.types import Candidate, ValidatorContext, Verdict
from orchestrator.worker import StaticWorker
from tools.core.vulnerability_class import VulnerabilityClass
from tools.validators import registry
from tools.validators.base import BaseValidator, PayloadVariant


def _make_cand(bug_class: str = "sqli", path: str = "/login") -> Candidate:
    return Candidate(
        id=Candidate.new_id(),
        bug_class=bug_class,
        target="https://x.example",
        path=path,
        method="POST",
        param="u",
    )


class _AlwaysTrueValidator(BaseValidator):
    @property
    def name(self) -> str:
        return "AlwaysTrue"

    @property
    def vulnerability_class(self) -> VulnerabilityClass:
        return VulnerabilityClass.SQLI

    def generate_payload(self, variant: PayloadVariant) -> str:
        return "t" if variant == "true" else "f"

    def compare_responses(self, resp_true: Any, resp_false: Any) -> bool:
        return True

    def validate(self, candidate: Candidate, ctx: ValidatorContext) -> Verdict:
        return Verdict(
            is_real=True,
            evidence="ok",
            confidence=0.9,
            bug_class="sqli",
            validator="AlwaysTrue",
            replays_passed=1,
            replays_total=1,
        )


class _RaisesValidator(BaseValidator):
    @property
    def name(self) -> str:
        return "Raises"

    @property
    def vulnerability_class(self) -> VulnerabilityClass:
        return VulnerabilityClass.SQLI

    def generate_payload(self, variant: PayloadVariant) -> str:
        return "x"

    def compare_responses(self, resp_true: Any, resp_false: Any) -> bool:
        return False

    def validate(self, candidate: Candidate, ctx: ValidatorContext) -> Verdict:
        raise RuntimeError("boom")


def test_validate_no_validator() -> None:
    with pytest.raises(NoValidatorError):
        validate_candidate(_make_cand(), ValidatorContext(target="x"))


def test_validate_ok() -> None:
    registry.register(VulnerabilityClass.SQLI)(_AlwaysTrueValidator)
    v = validate_candidate(_make_cand(), ValidatorContext(target="x"))
    assert v.is_real and v.validator == "AlwaysTrue"


def test_validator_exception_becomes_false() -> None:
    """Валидатор бросил → pipeline оборачивает в Verdict(is_real=False)."""
    registry.register(VulnerabilityClass.SQLI)(_RaisesValidator)
    v = validate_candidate(_make_cand(), ValidatorContext(target="x"))
    assert v.is_real is False
    assert "RuntimeError" in v.reason


def test_unknown_class_raises_no_validator_error() -> None:
    cand = Candidate(id="c-x", bug_class="totally-unknown", target="https://x")
    with pytest.raises(NoValidatorError, match="unknown bug_class"):
        validate_candidate(cand, ValidatorContext(target="x"))


def test_pipeline_dedup_and_scope() -> None:
    registry.register(VulnerabilityClass.SQLI)(_AlwaysTrueValidator)
    scope = Scope("acme")
    scope.add_domain("x.example")

    c1 = _make_cand()
    c2 = _make_cand()
    c_off = Candidate(
        id="c3",
        bug_class="sqli",
        target="https://out-of-scope.example",
        path="/",
        method="GET",
    )

    findings = run_pipeline(
        [StaticWorker([c1, c2, c_off])],
        ValidatorContext(target="https://x.example"),
        scope=scope,
    )
    assert len(findings) == 1
    assert findings[0].dedup_key == dedup_key(c1)


def test_dedup_key_stable() -> None:
    c = _make_cand()
    assert dedup_key(c) == dedup_key(c)


def test_dedup_key_normalizes_alias() -> None:
    c1 = Candidate(id="a", bug_class="bola", target="https://x", path="/o/1", method="GET")
    c2 = Candidate(id="b", bug_class="IDOR", target="https://x", path="/o/1", method="GET")
    assert dedup_key(c1) == dedup_key(c2)
