"""Pipeline: воркеры → валидатор → (M4) consensus → (M3) proof_gate → Finding."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterable

from orchestrator import registry
from orchestrator.scope import Scope, ScopeViolation
from orchestrator.types import Candidate, Finding, Severity, ValidatorContext, Verdict
from orchestrator.worker import Worker

log = logging.getLogger("truthgate.pipeline")


class NoValidatorError(RuntimeError):
    """Нет зарегистрированного валидатора для класса кандидата."""


def dedup_key(c: Candidate) -> str:
    blob = f"{c.target}|{c.path}|{c.method}|{c.param or ''}|{registry.norm_class(c.bug_class)}"
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def validate_candidate(c: Candidate, ctx: ValidatorContext) -> Verdict:
    v = registry.get(c.bug_class)
    if v is None:
        raise NoValidatorError(f"no validator for bug_class {c.bug_class!r}")
    try:
        return v.validate(c.as_finding_dict(), ctx)
    except Exception as e:
        log.exception("validator raised", extra={"cand_id": c.id, "bug_class": c.bug_class})
        return Verdict(
            is_real=False,
            evidence="",
            confidence=0.0,
            bug_class=registry.norm_class(c.bug_class),
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

            sev = sev_map.get(registry.norm_class(cand.bug_class), Severity.MEDIUM)
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
