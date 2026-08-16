"""Ре-экспорт `tools.core.*` для обратной совместимости.

Единственный источник истины — `tools/core/*.py` (pydantic v2). Этот модуль
оставлен как тонкий фасад, чтобы существующий импорт `from orchestrator.types
import Candidate` продолжал работать без правок в orchestrator/, cli, brain
и т.д. Новый код должен импортировать напрямую из `tools.core`.
"""

from __future__ import annotations

from tools.core import (
    AuthProvider,
    Candidate,
    Finding,
    OOBProvider,
    ProofTier,
    Severity,
    ValidationResult,
    ValidatorContext,
    Verdict,
)

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
]
