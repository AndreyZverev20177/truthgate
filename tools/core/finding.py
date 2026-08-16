"""Finding — sellable-находка. Прошла консенсус И proof gate."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tools.core.severity import ProofTier, Severity
from tools.core.verdict import Verdict


class Finding(BaseModel):
    """Иммутабельная находка, готовая к продаже (после proof_gate_v2)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    bug_class: str
    severity: Severity
    target: str
    title: str
    proof_tier: ProofTier
    consensus_votes: str
    confidence: float = Field(ge=0.0, le=1.0)
    artifacts: dict[str, Any]
    verdicts: tuple[Verdict, ...]
    scope_program: str = ""
    dedup_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Стабильная сериализация находки (для CLI и отчётов)."""
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
