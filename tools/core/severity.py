"""Severity и ProofTier — enum'ы, общие для валидаторов, консенсуса и proof gate."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal


class Severity(StrEnum):
    """OWASP-совместимая шкала. Кворум консенсуса зависит от severity (см. M4)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


ProofTier = Literal["live", "code_static", "none"]
"""Три честных тира судьи. `live` — есть машинный артефакт с корреляцией."""
