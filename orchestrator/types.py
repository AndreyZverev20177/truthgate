"""Ядро типов Truthgate.

Всё, что течёт по пайплайну (Candidate → Verdict → Finding), — иммутабельные
dataclass'ы с валидацией на входе. Никакой логики здесь — только формы данных
и контракты (Protocol) для внешних поставщиков (auth, OOB).

Инвариант: валидаторы получают ValidatorContext (изолированный срез) и возвращают
Verdict. Судья принимает Verdict.artifacts (структурированный), а не evidence-строку.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal, Protocol, runtime_checkable


class Severity(StrEnum):
    """OWASP-совместимая шкала. Кворум consensus зависит от severity (см. M4)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


ProofTier = Literal["live", "code_static", "none"]
"""Три честных тира судьи. `live` — есть машинный артефакт с корреляцией."""


@dataclass(frozen=True, slots=True)
class Candidate:
    """Гипотеза от LLM-мозга или tool-воркера. НЕ находка — пока не пройден валидатор."""

    id: str
    bug_class: str
    target: str
    path: str = "/"
    method: str = "GET"
    param: str | None = None
    payload: str | None = None
    body: Any = None
    headers: dict[str, str] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def new_id(prefix: str = "cand") -> str:
        return f"{prefix}-{secrets.token_hex(6)}"

    def as_finding_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "bug_class": self.bug_class,
            "path": self.path,
            "method": self.method,
        }
        if self.param is not None:
            d["param"] = self.param
        if self.payload is not None:
            d["payload"] = self.payload
        if self.body is not None:
            d["body"] = self.body
        if self.headers:
            d["headers"] = self.headers
        d.update(self.meta)
        return d


@dataclass(frozen=True, slots=True)
class Verdict:
    """Итог одного прогона валидатора. is_real — строго по правилу класса.

    `confidence` НЕ «насколько реально», а «насколько воспроизводимо» — доля
    успешных replay'ев. Судья читает `artifacts`, а не `evidence`.
    """

    is_real: bool
    evidence: str
    confidence: float
    bug_class: str = ""
    validator: str = ""
    reason: str = ""
    replays_passed: int = 0
    replays_total: int = 0
    artifacts: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0,1], got {self.confidence}")
        if self.replays_passed < 0 or self.replays_total < 0:
            raise ValueError("replays counts must be non-negative")
        if self.replays_passed > self.replays_total:
            raise ValueError("replays_passed > replays_total")

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_real": self.is_real,
            "bug_class": self.bug_class,
            "validator": self.validator,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
            "reason": self.reason,
            "replays": f"{self.replays_passed}/{self.replays_total}",
            "artifacts": self.artifacts,
        }


@dataclass(slots=True)
class ValidatorContext:
    """Изолированный срез окружения для валидатора."""

    target: str
    program_headers: dict[str, str] = field(default_factory=dict)
    tls_verify: bool = False
    replays: int = 3
    poll_wait_s: float = 12.0
    dry_run: bool = True
    auth: AuthProvider | None = None
    oob: OOBProvider | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Finding:
    """Sellable-находка: прошла консенсус И proof_gate."""

    id: str
    bug_class: str
    severity: Severity
    target: str
    title: str
    proof_tier: ProofTier
    consensus_votes: str
    confidence: float
    artifacts: dict[str, Any]
    verdicts: tuple[Verdict, ...]
    scope_program: str = ""
    dedup_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "bug_class": self.bug_class,
            "severity": self.severity.value,
            "target": self.target,
            "title": self.title,
            "proof_tier": self.proof_tier,
            "consensus_votes": self.consensus_votes,
            "confidence": round(self.confidence, 2),
            "scope_program": self.scope_program,
            "dedup_key": self.dedup_key,
            "artifacts": self.artifacts,
            "verdicts": [v.to_dict() for v in self.verdicts],
        }


@runtime_checkable
class AuthProvider(Protocol):
    """HTTP-opener для роли — для authz-классов (idor/bola/bfla)."""

    def opener(self, role: str) -> Any: ...
    def unauth_opener(self) -> Any: ...


@runtime_checkable
class OOBProvider(Protocol):
    """OAST-инстанс (свой interactsh) для ssrf/xxe/blind-классов."""

    def new_token(self, probe_id: str) -> tuple[str, str]: ...
    def poll(self, token: str, wait_s: float) -> list[dict[str, Any]]: ...
