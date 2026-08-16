"""Verdict — итог одного прогона валидатора.

`is_real` — строго по правилу класса (валидатор класса). `confidence` НЕ
«насколько реально», а «насколько воспроизводимо» — доля успешных replay'ев.
Судья читает `artifacts` (машинные), а не `evidence`-строку.

`ValidationResult` — стабильный псевдоним `Verdict` для внешнего API валидатора
(ТЗ п.3 disform-ошибок явно называет оба имени). На уровне консенсуса появится
отдельный `ConsensusResult` (M1 п.6), чтобы не путать «один прогон» и «сборка».
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Verdict(BaseModel):
    """Иммутабельный итог одного прогона валидатора."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    is_real: bool
    evidence: str
    confidence: float = Field(ge=0.0, le=1.0)
    bug_class: str = ""
    validator: str = ""
    reason: str = ""
    replays_passed: int = Field(default=0, ge=0)
    replays_total: int = Field(default=0, ge=0)
    artifacts: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _replays_consistent(self) -> "Verdict":
        if self.replays_passed > self.replays_total:
            raise ValueError("replays_passed > replays_total")
        return self

    def to_dict(self) -> dict[str, Any]:
        """Стабильная сериализация вердикта (для CLI/логов/sqlite)."""
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


# Псевдоним по ТЗ: валидатор возвращает ValidationResult (== Verdict пока нет
# отдельного слоя консенсуса). После M1 п.6 появится `ConsensusResult` в
# `tools/core/consensus_result.py` — тогда имена разойдутся содержательно.
ValidationResult = Verdict
