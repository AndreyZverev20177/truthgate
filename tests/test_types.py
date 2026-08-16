"""Тесты pydantic-контрактов ядра (Candidate/Verdict/Finding/ValidatorContext).

Импортируем через `orchestrator.types` (façade) — так проверяем и re-export.
"""

from __future__ import annotations

import pytest

from orchestrator.types import (
    Candidate,
    Finding,
    Severity,
    ValidatorContext,
    Verdict,
)


class TestVerdict:
    def test_ok(self) -> None:
        v = Verdict(
            is_real=True,
            evidence="e",
            confidence=0.7,
            bug_class="sqli",
            validator="SQLi",
            replays_passed=3,
            replays_total=3,
        )
        d = v.to_dict()
        assert d["is_real"] is True
        assert d["confidence"] == 0.7
        assert d["replays"] == "3/3"

    def test_confidence_bounds(self) -> None:
        # pydantic ValidationError — subclass of ValueError в v2.x
        with pytest.raises(ValueError):
            Verdict(is_real=True, evidence="e", confidence=1.5)
        with pytest.raises(ValueError):
            Verdict(is_real=True, evidence="e", confidence=-0.1)

    def test_replays_consistency(self) -> None:
        with pytest.raises(ValueError):
            Verdict(
                is_real=True,
                evidence="e",
                confidence=0.5,
                replays_passed=4,
                replays_total=3,
            )

    def test_frozen(self) -> None:
        v = Verdict(is_real=True, evidence="e", confidence=0.5)
        with pytest.raises(ValueError):
            v.evidence = "changed"  # type: ignore[misc]


class TestCandidate:
    def test_new_id(self) -> None:
        a = Candidate.new_id()
        b = Candidate.new_id()
        assert a != b and a.startswith("cand-")

    def test_as_finding_dict_roundtrip(self) -> None:
        c = Candidate(
            id="cand-1",
            bug_class="sqli",
            target="https://x",
            path="/login",
            method="POST",
            param="u",
            payload="' OR '1'='1'-- ",
            meta={"marker": "flag"},
        )
        d = c.as_finding_dict()
        assert d["param"] == "u"
        assert d["path"] == "/login"
        assert d["marker"] == "flag"

    def test_kwargs_unpack(self) -> None:
        """Совместимость с `Candidate(**row)` в cli.run."""
        c = Candidate(**{"id": "cand-x", "bug_class": "ssrf", "target": "https://y"})
        assert c.bug_class == "ssrf"

    def test_frozen(self) -> None:
        c = Candidate(id="cand-1", bug_class="sqli", target="https://x")
        with pytest.raises(ValueError):
            c.target = "https://z"  # type: ignore[misc]


class TestValidatorContext:
    def test_defaults(self) -> None:
        ctx = ValidatorContext(target="https://x")
        assert ctx.dry_run is True
        assert ctx.replays == 3


class TestFinding:
    def test_serializes(self) -> None:
        v = Verdict(
            is_real=True,
            evidence="e",
            confidence=0.9,
            bug_class="idor",
            validator="IDOR",
            replays_passed=2,
            replays_total=2,
        )
        f = Finding(
            id="find-1",
            bug_class="idor",
            severity=Severity.HIGH,
            target="https://x",
            title="IDOR on /orders",
            proof_tier="live",
            consensus_votes="2/2",
            confidence=0.9,
            artifacts={"leak": "y"},
            verdicts=(v,),
            scope_program="acme",
            dedup_key="abc",
        )
        d = f.to_dict()
        assert d["severity"] == "high"
        assert d["verdicts"][0]["confidence"] == 0.9
