"""Anti-FP тесты для SSRFValidator (OOB, hostname strict)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from orchestrator.scope import Scope
from orchestrator.types import Candidate, ValidatorContext
from tools.core.vulnerability_class import VulnerabilityClass
from tools.validators import registry
from tools.validators.ssrf import SSRFValidator

pytestmark = pytest.mark.anti_fp

TARGET = "https://api.example"
PROBE_PATH = "/fetch"
OOB_DOMAIN = "oob.truthgate.test"


class _MockOOB:
    def __init__(self, hits_per_token: dict[str, list[dict[str, Any]]] | None = None) -> None:
        self._counter = 0
        self._tokens_issued: list[str] = []
        self._hits = hits_per_token or {}

    def new_token(self, probe_id: str) -> tuple[str, str]:
        self._counter += 1
        token = f"t{self._counter:016x}"
        self._tokens_issued.append(token)
        return token, f"http://{token}.{OOB_DOMAIN}/probe"

    def poll(self, token: str, wait_s: float) -> list[dict[str, Any]]:
        return list(self._hits.get(token, []))

    @property
    def tokens_issued(self) -> list[str]:
        return list(self._tokens_issued)


def _candidate() -> Candidate:
    return Candidate(
        id="cand-ssrf-1",
        bug_class="ssrf",
        target=TARGET,
        path=PROBE_PATH,
        method="GET",
        param="url",
    )


def _ctx_with(
    oob: _MockOOB | None,
    scope: Scope | None = None,
    transport: httpx.MockTransport | None = None,
) -> ValidatorContext:
    extra: dict = {}
    if transport is not None:
        extra["http_transport"] = transport
    if scope is not None:
        extra["scope"] = scope
    return ValidatorContext(
        target=TARGET,
        replays=1,
        dry_run=True,
        oob=oob,  # type: ignore[arg-type]
        extra=extra,
        poll_wait_s=0.001,
    )


def _dummy_transport() -> httpx.MockTransport:
    return httpx.MockTransport(lambda req: httpx.Response(status_code=200, content=b"ok"))


def test_ssrf_no_oob_provider_fail() -> None:
    v = SSRFValidator()
    ctx = ValidatorContext(target=TARGET, oob=None)
    verdict = v.validate(_candidate(), ctx)
    assert verdict.is_real is False
    assert verdict.reason == "oob_not_configured"


def test_ssrf_no_callback_fail() -> None:
    oob = _MockOOB(hits_per_token={})
    v = SSRFValidator()
    verdict = v.validate(_candidate(), _ctx_with(oob, transport=_dummy_transport()))
    assert verdict.is_real is False
    assert verdict.reason == "no_oob_callback"
    art = verdict.artifacts
    assert art["extra"]["callback_type"] == "none"
    assert art["extra"]["raw_hits_count"] == 0


def test_ssrf_callback_token_in_path_only_fail() -> None:
    class _OOB(_MockOOB):
        def poll(self, token: str, wait_s: float) -> list[dict[str, Any]]:
            return [
                {
                    "hostname": f"some-other-host.{OOB_DOMAIN}",
                    "type": "http",
                    "path": f"/echo/{token}",
                    "source_ip": "1.2.3.4",
                    "resolver_type": "public",
                }
            ]

    oob = _OOB()
    v = SSRFValidator()
    verdict = v.validate(_candidate(), _ctx_with(oob, transport=_dummy_transport()))
    assert verdict.is_real is False
    assert verdict.reason == "callback_without_token_in_hostname"
    art = verdict.artifacts
    assert art["extra"]["raw_hits_count"] == 1
    assert art["extra"]["valid_hits_count"] == 0


def test_ssrf_http_callback_token_hostname_pass_high() -> None:
    class _OOB(_MockOOB):
        def poll(self, token: str, wait_s: float) -> list[dict[str, Any]]:
            return [
                {
                    "hostname": f"{token}.{OOB_DOMAIN}",
                    "type": "http",
                    "path": "/probe",
                    "source_ip": "10.0.0.42",
                    "resolver_type": "unknown",
                }
            ]

    oob = _OOB()
    v = SSRFValidator()
    verdict = v.validate(_candidate(), _ctx_with(oob, transport=_dummy_transport()))
    assert verdict.is_real is True, verdict.evidence
    assert verdict.reason == "http_callback_confirmed"
    assert verdict.confidence == 0.95
    art = verdict.artifacts
    assert art["extra"]["callback_type"] == "http"
    assert art["oob_hit"] is True
    assert art["oob_token"]
    assert art["extra"]["callback_hostname"].startswith(art["oob_token"] + ".")


def test_ssrf_dns_only_non_public_resolver_pass_low() -> None:
    class _OOB(_MockOOB):
        def poll(self, token: str, wait_s: float) -> list[dict[str, Any]]:
            return [
                {
                    "hostname": f"{token}.{OOB_DOMAIN}",
                    "type": "dns",
                    "path": "",
                    "source_ip": "10.100.0.5",
                    "resolver_type": "non_public",
                }
            ]

    oob = _OOB()
    v = SSRFValidator()
    verdict = v.validate(_candidate(), _ctx_with(oob, transport=_dummy_transport()))
    assert verdict.is_real is True, verdict.evidence
    assert verdict.reason == "dns_only_callback"
    assert verdict.confidence == 0.65


def test_ssrf_dns_only_public_resolver_fail() -> None:
    class _OOB(_MockOOB):
        def poll(self, token: str, wait_s: float) -> list[dict[str, Any]]:
            return [
                {
                    "hostname": f"{token}.{OOB_DOMAIN}",
                    "type": "dns",
                    "path": "",
                    "source_ip": "8.8.8.8",
                    "resolver_type": "public",
                }
            ]

    oob = _OOB()
    v = SSRFValidator()
    verdict = v.validate(_candidate(), _ctx_with(oob, transport=_dummy_transport()))
    assert verdict.is_real is False
    assert verdict.reason == "dns_only_public_resolver"


def test_ssrf_token_unique_between_validate_calls() -> None:
    oob = _MockOOB(hits_per_token={})
    v = SSRFValidator()
    for _ in range(3):
        v.validate(_candidate(), _ctx_with(oob, transport=_dummy_transport()))
    tokens = oob.tokens_issued
    assert len(tokens) == 3
    assert len(set(tokens)) == 3


def test_ssrf_out_of_scope_short_circuits() -> None:
    scope = Scope("acme")
    scope.add_domain("only-this.example")
    oob = _MockOOB()
    v = SSRFValidator()
    verdict = v.validate(_candidate(), _ctx_with(oob, scope=scope, transport=_dummy_transport()))
    assert verdict.is_real is False
    assert verdict.reason == "out_of_scope"


def test_ssrf_auto_registered() -> None:
    registry.register(VulnerabilityClass.SSRF)(SSRFValidator)
    v = registry.get(VulnerabilityClass.SSRF)
    assert v is not None
    assert isinstance(v, SSRFValidator)
    assert v.name == "ssrf_oob_v1"
