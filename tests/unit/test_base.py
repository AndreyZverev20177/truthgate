"""Unit-тесты контракта BaseValidator и ValidationEvidence."""

from __future__ import annotations

from typing import Any

import pytest

from orchestrator.types import Candidate, ValidatorContext, Verdict
from tools.core.vulnerability_class import VulnerabilityClass
from tools.validators.base import BaseValidator, PayloadVariant, ValidationEvidence

pytestmark = pytest.mark.unit


# ─── Хелпер: минимальный подкласс для проверок контракта ──────────────────


class _MockValidator(BaseValidator):
    """Тривиальная реализация — отдаёт статичные payload'ы и Verdict."""

    @property
    def name(self) -> str:
        return "mock_v1"

    @property
    def vulnerability_class(self) -> VulnerabilityClass:
        return VulnerabilityClass.SQLI

    def generate_payload(self, variant: PayloadVariant) -> str:
        return "' OR 1=1-- " if variant == "true" else "' OR 1=2-- "

    def compare_responses(self, resp_true: Any, resp_false: Any) -> bool:
        # Минимальное правило: разные статусы = разница есть
        return bool(resp_true["status"] != resp_false["status"])

    def validate(self, candidate: Candidate, ctx: ValidatorContext) -> Verdict:
        try:
            pt = self.generate_payload("true")
            pf = self.generate_payload("false")
            rt = {"status": 200, "body": "welcome admin"}
            rf = {"status": 401, "body": "unauthorized"}
            is_real = self.compare_responses(rt, rf)
            ev = ValidationEvidence(
                payload_true=pt,
                payload_false=pf,
                status_true=rt["status"],
                status_false=rf["status"],
                len_true=len(rt["body"]),
                len_false=len(rf["body"]),
                sha256_true=ValidationEvidence.sha256_of(rt["body"]),
                sha256_false=ValidationEvidence.sha256_of(rf["body"]),
                timing_ms_true=1.0,
                timing_ms_false=1.2,
            )
            return Verdict(
                is_real=is_real,
                evidence="mock",
                confidence=1.0 if is_real else 0.0,
                bug_class=self.vulnerability_class.value,
                validator=self.name,
                replays_passed=1 if is_real else 0,
                replays_total=1,
                artifacts=ev.to_dict(),
            )
        except Exception as e:  # noqa: BLE001
            return self.as_failure(e)


# ─── Тесты контракта ─────────────────────────────────────────────────


class TestBaseValidatorContract:
    def test_cannot_instantiate_abstract(self) -> None:
        """BaseValidator — ABC, прямая инстанциация должна падать."""
        with pytest.raises(TypeError):
            BaseValidator()  # type: ignore[abstract]

    def test_subclass_must_implement_all_abstracts(self) -> None:
        """Подкласс без реализации абстрактов не инстанциируется."""

        class _Incomplete(BaseValidator):
            @property
            def name(self) -> str:
                return "incomplete"
            # намеренно нет vulnerability_class / generate_payload / compare / validate

        with pytest.raises(TypeError):
            _Incomplete()  # type: ignore[abstract]

    def test_mock_subclass_instantiates(self) -> None:
        """Полный подкласс инстанциируется и отдаёт стабильные name/class."""
        v = _MockValidator()
        assert v.name == "mock_v1"
        assert v.vulnerability_class is VulnerabilityClass.SQLI
        # `.value` — то, что попадает в bug_class / sqlite runs / dedup_key
        assert v.vulnerability_class.value == "sqli"


class TestGeneratePayload:
    def test_variants_differ(self) -> None:
        """`true` и `false` payload'ы обязаны отличаться — иначе нет сигнала."""
        v = _MockValidator()
        assert v.generate_payload("true") != v.generate_payload("false")

    def test_variants_are_str(self) -> None:
        v = _MockValidator()
        assert isinstance(v.generate_payload("true"), str)
        assert isinstance(v.generate_payload("false"), str)


class TestCompareResponses:
    def test_detects_status_difference(self) -> None:
        """Разница по статусу → True."""
        v = _MockValidator()
        assert v.compare_responses({"status": 200}, {"status": 401}) is True

    def test_identical_returns_false(self) -> None:
        """Идентичные ответы → False (нет сигнала)."""
        v = _MockValidator()
        assert v.compare_responses({"status": 200}, {"status": 200}) is False


class TestValidateWorkflow:
    def test_returns_verdict_with_evidence(self) -> None:
        """`.validate` возвращает Verdict с ненулевым artifacts и правильными полями."""
        v = _MockValidator()
        cand = Candidate(
            id="c-1", bug_class="sqli", target="https://x", path="/login", method="POST", param="u"
        )
        ctx = ValidatorContext(target="https://x")
        vd = v.validate(cand, ctx)

        assert vd.is_real is True
        assert vd.bug_class == "sqli"
        assert vd.validator == "mock_v1"
        assert vd.confidence == 1.0
        # artifacts — dict, не строка (evidence-строка отдельно)
        assert isinstance(vd.artifacts, dict)
        assert vd.artifacts["payload_true"] != vd.artifacts["payload_false"]
        assert vd.artifacts["sha256_true"] != vd.artifacts["sha256_false"]
        assert len(vd.artifacts["sha256_true"]) == 64


class TestValidationEvidence:
    def test_sha256_of_consistent(self) -> None:
        """SHA256 хэш детерминирован и стабилен между str/bytes."""
        a = ValidationEvidence.sha256_of("abc")
        b = ValidationEvidence.sha256_of(b"abc")
        assert a == b
        assert len(a) == 64
        # Reference: sha256("abc")
        assert a == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    def test_frozen_and_extra_forbid(self) -> None:
        """Evidence — иммутабельный контракт, extra запрещен."""
        ev = ValidationEvidence(
            payload_true="a",
            payload_false="b",
            status_true=200,
            status_false=401,
            len_true=1,
            len_false=1,
            sha256_true="a" * 64,
            sha256_false="b" * 64,
            timing_ms_true=1.0,
            timing_ms_false=1.0,
        )
        with pytest.raises(ValueError):
            ev.payload_true = "changed"  # type: ignore[misc]
        with pytest.raises(ValueError):
            ValidationEvidence(
                payload_true="a",
                payload_false="b",
                status_true=200,
                status_false=401,
                len_true=1,
                len_false=1,
                sha256_true="a" * 64,
                sha256_false="b" * 64,
                timing_ms_true=1.0,
                timing_ms_false=1.0,
                unknown_field=42,  # type: ignore[call-arg]
            )

    def test_sha256_length_validated(self) -> None:
        """Длина sha256 = 64 hex — иначе валидатор кидает."""
        with pytest.raises(ValueError):
            ValidationEvidence(
                payload_true="a",
                payload_false="b",
                status_true=200,
                status_false=200,
                len_true=1,
                len_false=1,
                sha256_true="short",
                sha256_false="b" * 64,
                timing_ms_true=1.0,
                timing_ms_false=1.0,
            )


class TestFailureWrapping:
    def test_as_failure_returns_safe_verdict(self) -> None:
        """`.as_failure(exc)` даёт корректный Verdict без бросков."""
        v = _MockValidator()
        vd = v.as_failure(RuntimeError("boom"))
        assert vd.is_real is False
        assert vd.confidence == 0.0
        assert vd.bug_class == "sqli"
        assert vd.validator == "mock_v1"
        assert "RuntimeError" in vd.reason
        assert "boom" in vd.reason

    def test_validator_never_raises_on_broken_subclass(self) -> None:
        """Наследник, кидающий внутри try, обязан завернуть в Verdict через as_failure."""

        class _Broken(_MockValidator):
            def validate(self, candidate: Candidate, ctx: ValidatorContext) -> Verdict:
                try:
                    raise ValueError("simulated")
                except Exception as e:  # noqa: BLE001
                    return self.as_failure(e)

        v = _Broken()
        cand = Candidate(id="c", bug_class="sqli", target="https://x")
        vd = v.validate(cand, ValidatorContext(target="x"))
        assert vd.is_real is False
        assert "ValueError" in vd.reason
