"""Anti-FP тесты для IDORValidator (cross-user + приватность)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from orchestrator.types import Candidate, ValidatorContext
from tools.core.vulnerability_class import VulnerabilityClass
from tools.validators import registry
from tools.validators.idor import IDORValidator

pytestmark = pytest.mark.anti_fp

TARGET = "https://api.example"
VICTIM_PATH = "/api/v1/users/42/cards"
VICTIM_MARKER = "victim_email_hash_9f2a3c4b7e"


def _candidate() -> Candidate:
    return Candidate(
        id="cand-idor-1",
        bug_class="idor",
        target=TARGET,
        path=VICTIM_PATH,
        method="GET",
        meta={
            "victim_marker": VICTIM_MARKER,
            "attacker_role": "user_b",
        },
    )


class _MockAuth:
    def __init__(self, attacker: httpx.Client, unauth: httpx.Client) -> None:
        self._attacker = attacker
        self._unauth = unauth

    def opener(self, role: str) -> Any:
        return self._attacker

    def unauth_opener(self) -> Any:
        return self._unauth


def _client_with(response: tuple[int, bytes]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        status, body = response
        return httpx.Response(status_code=status, content=body)

    return httpx.Client(transport=httpx.MockTransport(handler))


def _ctx_with(auth: _MockAuth) -> ValidatorContext:
    return ValidatorContext(target=TARGET, replays=1, dry_run=True, auth=auth)


def test_idor_vulnerable_target_pass() -> None:
    victim_body = b'{"card_number":"4111","holder":"' + VICTIM_MARKER.encode() + b'"}'
    att_client = _client_with((200, victim_body))
    un_client = _client_with((401, b'{"error":"unauthorized"}'))
    auth = _MockAuth(att_client, un_client)

    v = IDORValidator()
    verdict = v.validate(_candidate(), _ctx_with(auth))

    assert verdict.is_real is True, verdict.evidence
    assert verdict.confidence == 1.0
    art = verdict.artifacts
    assert art["status_true"] == 200
    assert art["status_false"] == 401
    assert art["extra"]["marker_present_in_attacker"] is True
    assert art["extra"]["marker_present_in_unauth"] is False
    assert art["extra"]["unauth_private"] is True


def test_idor_safe_target_fail_access_denied() -> None:
    att_client = _client_with((403, b'{"error":"forbidden"}'))
    un_client = _client_with((401, b'{"error":"unauthorized"}'))
    auth = _MockAuth(att_client, un_client)

    v = IDORValidator()
    verdict = v.validate(_candidate(), _ctx_with(auth))

    assert verdict.is_real is False
    assert verdict.reason == "access_denied"
    assert verdict.artifacts["status_true"] == 403


def test_idor_public_resource_not_idor() -> None:
    body = b'{"card_number":"4111","holder":"' + VICTIM_MARKER.encode() + b'"}'
    att_client = _client_with((200, body))
    un_client = _client_with((200, body))
    auth = _MockAuth(att_client, un_client)

    v = IDORValidator()
    verdict = v.validate(_candidate(), _ctx_with(auth))

    assert verdict.is_real is False
    assert verdict.reason == "public_resource"
    assert verdict.artifacts["extra"]["marker_present_in_unauth"] is True


def test_idor_no_auth_provider_returns_false() -> None:
    v = IDORValidator()
    ctx = ValidatorContext(target=TARGET, auth=None)
    verdict = v.validate(_candidate(), ctx)
    assert verdict.is_real is False
    assert verdict.reason == "no_auth_provider"


def test_idor_no_victim_marker_returns_false() -> None:
    v = IDORValidator()
    cand = Candidate(id="c", bug_class="idor", target=TARGET, path=VICTIM_PATH)
    auth = _MockAuth(_client_with((200, b"")), _client_with((401, b"")))
    verdict = v.validate(cand, _ctx_with(auth))
    assert verdict.is_real is False
    assert verdict.reason == "no_victim_marker"


def test_idor_auto_registered() -> None:
    registry.register(VulnerabilityClass.IDOR)(IDORValidator)
    v = registry.get(VulnerabilityClass.IDOR)
    assert v is not None
    assert isinstance(v, IDORValidator)
