"""Pipeline: воркеры → валидатор → (M4) consensus → (M3) proof_gate → Finding.

Мигрирован на enum-based registry (`tools.validators.registry`).
Алиасы строк живут только в `tools.validators.normalize.normalize_vuln_class`.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterable

from orchestrator.scope import Scope, ScopeViolation
from orchestrator.types import Candidate, Finding, Severity, ValidatorContext, Verdict
from orchestrator.worker import Worker
from tools.core.vulnerability_class import VulnerabilityClass
from tools.validators import registry
from tools.validators.normalize import normalize_vuln_class

log = logging.getLogger("truthgate.pipeline")


class NoValidatorError(RuntimeError):
    """Нет зарегистрированного валидатора для класса кандидата."""


def _canonical_class(raw: str) -> VulnerabilityClass | None:
    return normalize_vuln_class(raw)


def dedup_key(c: Candidate) -> str:
    vc = _canonical_class(c.bug_class)
    bug = vc.value if vc is not None else c.bug_class.strip().lower()
    blob = f"{c.target}|{c.path}|{c.method}|{c.param or ''}|{bug}"
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def validate_candidate(c: Candidate, ctx: ValidatorContext) -> Verdict:
    vc = _canonical_class(c.bug_class)
    if vc is None:
        raise NoValidatorError(f"unknown bug_class {c.bug_class!r} (see normalize.py)")
    v = registry.get(vc)
    if v is None:
        raise NoValidatorError(f"no validator registered for {vc!r}")
    try:
        return v.validate(c, ctx)
    except Exception as e:  # noqa: BLE001
        log.exception("validator raised", extra={"cand_id": c.id, "bug_class": c.bug_class})
        return Verdict(
            is_real=False,
            evidence="",
            confidence=0.0,
            bug_class=vc.value,
            validator=type(v).__name__,
            reason=f"{type(e).__name__}: {e}",
        )


def run_pipeline(
    workers: Iterable[Worker],
    ctx: ValidatorContext,
    scope: Scope | None = None,
    severity_map: dict[str, Severity] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    sev_map = severity_map or {}
    seen_keys: set[str] = set()

    for w in workers:
        for cand in w.propose(ctx):
            if scope is not None:
                try:
                    scope.assert_in_scope(cand.target)
                except ScopeViolation as e:
                    log.warning("scope violation", extra={"cand_id": cand.id, "err": str(e)})
                    continue

            key = dedup_key(cand)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            verdict = validate_candidate(cand, ctx)
            if not verdict.is_real:
                continue

            vc = _canonical_class(cand.bug_class)
            sev = sev_map.get(vc.value if vc else cand.bug_class, Severity.MEDIUM)
            findings.append(
                Finding(
                    id=Candidate.new_id("find"),
                    bug_class=verdict.bug_class,
                    severity=sev,
                    target=cand.target,
                    title=f"{verdict.bug_class} on {cand.path}",
                    proof_tier="none",
                    consensus_votes="1/1",
                    confidence=verdict.confidence,
                    artifacts=verdict.artifacts,
                    verdicts=(verdict,),
                    scope_program=scope.program if scope else "",
                    dedup_key=key,
                )
            )
    return findings
