"""Unit-тесты нового enum-based реестра валидаторов."""

from __future__ import annotations

from typing import Any

import pytest

from orchestrator.types import Candidate, ValidatorContext, Verdict
from tools.core.vulnerability_class import VulnerabilityClass
from tools.validators import registry
from tools.validators.base import BaseValidator, PayloadVariant

pytestmark = pytest.mark.unit


class _Dummy(BaseValidator):
    @property
    def name(self) -> str:
        return "dummy_v1"

    @property
    def vulnerability_class(self) -> VulnerabilityClass:
        return VulnerabilityClass.SQLI

    def generate_payload(self, variant: PayloadVariant) -> str:
        return "T" if variant == "true" else "F"

    def compare_responses(self, resp_true: Any, resp_false: Any) -> bool:
        return resp_true != resp_false

    def validate(self, candidate: Candidate, ctx: ValidatorContext) -> Verdict:
        return Verdict(
            is_real=True,
            evidence="ok",
            confidence=1.0,
            bug_class=self.vulnerability_class.value,
            validator=self.name,
        )


class _MismatchedClass(BaseValidator):
    @property
    def name(self) -> str:
        return "mismatched"

    @property
    def vulnerability_class(self) -> VulnerabilityClass:
        return VulnerabilityClass.SSRF

    def generate_payload(self, variant: PayloadVariant) -> str:
        return "x"

    def compare_responses(self, resp_true: Any, resp_false: Any) -> bool:
        return False

    def validate(self, candidate: Candidate, ctx: ValidatorContext) -> Verdict:
        return Verdict(is_real=False, evidence="", confidence=0.0)


class TestRegistry:
    def test_register_and_get_by_enum(self) -> None:
        registry.register(VulnerabilityClass.SQLI)(_Dummy)
        v = registry.get(VulnerabilityClass.SQLI)
        assert v is not None
        assert v.name == "dummy_v1"

    def test_get_missing_returns_none(self) -> None:
        assert registry.get(VulnerabilityClass.XXE) is None

    def test_known_classes_returns_registered(self) -> None:
        registry.register(VulnerabilityClass.SQLI)(_Dummy)
        assert registry.known_classes() == [VulnerabilityClass.SQLI]

    def test_register_rejects_non_base_validator(self) -> None:
        class _NotBase:
            pass

        with pytest.raises(TypeError):
            registry.register(VulnerabilityClass.SQLI)(_NotBase)  # type: ignore[arg-type]

    def test_register_rejects_mismatched_class(self) -> None:
        with pytest.raises(ValueError, match="не совпадает"):
            registry.register(VulnerabilityClass.SQLI)(_MismatchedClass)

    def test_clear_empties_registry(self) -> None:
        registry.register(VulnerabilityClass.SQLI)(_Dummy)
        assert registry.known_classes() == [VulnerabilityClass.SQLI]
        registry.clear()
        assert registry.known_classes() == []
        assert registry.get(VulnerabilityClass.SQLI) is None
