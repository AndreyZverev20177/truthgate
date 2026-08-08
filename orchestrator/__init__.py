"""Truthgate orchestrator.

LLM-мозг + рой воркеров под единым worker-контрактом. Любой вывод работника —
только КАНДИДАТ; is_real ставит детерминированный валидатор (`tools/validators/`),
финальный `PROVEN` — судья по артефакту (`phase1/proof_gate_v2.py`).
"""

from __future__ import annotations

__version__ = "0.1.0"

from orchestrator.types import (
    AuthProvider,
    Candidate,
    Finding,
    OOBProvider,
    Severity,
    ValidatorContext,
    Verdict,
)

__all__ = [
    "AuthProvider",
    "Candidate",
    "Finding",
    "OOBProvider",
    "Severity",
    "ValidatorContext",
    "Verdict",
    "__version__",
]
