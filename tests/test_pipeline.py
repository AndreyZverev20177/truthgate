from __future__ import annotations

import pytest

from orchestrator import registry
from orchestrator.pipeline import (
    NoValidatorError,
    dedup_key,
    run_pipeline,
    validate_candidate,
)
from orchestrator.scope import Scope
from orchestrator.types import Candidate, ValidatorContext, Verdict
from orchestrator.worker import StaticWorker


def _make_cand(bug_class: str = "sqli", path: str = "/login") -> Candidate:
    return Candidate(id=Candidate.new_id(), bug_class=bug_class,
                     target="https://x.example", path=path, method="POST", param="u")


class _AlwaysTrue:
    bug_class = "sqli"
    def validate(self, finding, ctx):  # type: ignore[no-untyped-def]
        return Verdict(True, "ok", 0.9, "sqli", "AlwaysTrue", replays_passed=1, replays_total=1)


class _Raises:
    bug_class = "sqli"
    def validate(self, finding, ctx):  # type: ignore[no-untyped-def]
        raise RuntimeError("boom")


def test_validate_no_validator() -> None:
    with pytest.raises(NoValidatorError):
        validate_candidate(_make_cand(), ValidatorContext(target="x"))


def test_validate_ok() -> None:
    registry.register("sqli")(_AlwaysTrue)
    v = validate_candidate(_make_cand(), ValidatorContext(target="x"))
    assert v.is_real and v.validator == "AlwaysTrue"


def test_validator_exception_becomes_false() -> None:
    registry.register("sqli")(_Raises)
    v = validate_candidate(_make_cand(), ValidatorContext(target="x"))
    assert v.is_real is False
    assert "RuntimeError" in v.reason


def test_pipeline_dedup_and_scope() -> None:
    registry.register("sqli")(_AlwaysTrue)
    scope = Scope("acme")
    scope.add_domain("x.example")

    c1 = _make_cand()
    c2 = _make_cand()                                        # тот же dedup_key
    c_off = Candidate(id="c3", bug_class="sqli",
                      target="https://out-of-scope.example", path="/", method="GET")

    findings = run_pipeline([StaticWorker([c1, c2, c_off])],
                            ValidatorContext(target="https://x.example"), scope=scope)
    assert len(findings) == 1
    assert findings[0].dedup_key == dedup_key(c1)


def test_dedup_key_stable() -> None:
    c = _make_cand()
    assert dedup_key(c) == dedup_key(c)
