"""Truthgate core-контракты.

Единый канонический слой типов и enum'ов, на который опираются все остальные
модули (orchestrator, tools/validators, phase1). Не содержит логики — только
формы данных и правила валидации входа.

Ключевой принцип «ИИ находит — детерминированный код решает»:
- контракт классов задан enum'ом `VulnerabilityClass` — никаких строковых алиасов;
- вход/выход валидатора — иммутабельный pydantic (`Candidate`, `Verdict`);
- находка получает форму `Finding` только после консенсуса и proof gate.
"""

from __future__ import annotations

from tools.core.candidate import Candidate
from tools.core.finding import Finding
from tools.core.providers import AuthProvider, OOBProvider
from tools.core.severity import ProofTier, Severity
from tools.core.validator_context import ValidatorContext
from tools.core.verdict import ValidationResult, Verdict
from tools.core.vulnerability_class import VulnerabilityClass

__all__ = [
    "AuthProvider",
    "Candidate",
    "Finding",
    "OOBProvider",
    "ProofTier",
    "Severity",
    "ValidationResult",
    "ValidatorContext",
    "Verdict",
    "VulnerabilityClass",
]
