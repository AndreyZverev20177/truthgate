"""Anti-FP тесты для SQLiValidator под расширенный контракт ТЗ."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from orchestrator.scope import Scope
from orchestrator.types import Candidate, ValidatorContext
from tools.core.vulnerability_class import VulnerabilityClass
from tools.validators import registry
from tools.validators.sqli import SQLiValidator

pytestmark = pytest.mark.anti_fp

TARGET = "https://vuln.example"
LOGIN_PATH = "/login"


def _candidate() -> Candidate:
    return Candidate(
        id="cand-sqli-1",
        bug_class="sqli",
        target=TARGET,
        path=LOGIN_PATH,
        method="POST",
        param="username",
        meta={"password_param": "password", "content_type": "form"},
    )


def _ctx_with(transport: httpx.MockTransport, scope: Scope | None = None) -> ValidatorContext:
    extra: dict = {"http_transport": transport}
    if scope is not None:
        extra["scope"] = scope
    return ValidatorContext(target=TARGET, replays=1, dry_run=True, extra=extra)


def _make_transport(handler: Callable[[dict[str, str]], tuple[int, bytes]]) -> httpx.MockTransport:
    def _entry(request: httpx.Request) -> httpx.Response:
        from urllib.parse import unquote_plus
        raw = (request.content or b"").decode("utf-8", errors="replace")
        params: dict[str, str] = {}
        for pair in raw.split("&"):
            if not pair or "=" not in pair:
                continue
            k, _, v = pair.partition("=")
            params[unquote_plus(k)] = unquote_plus(v)
        status, body = handler(params)
        return httpx.Response(status_code=status, content=body)

    return httpx.MockTransport(_entry)


def test_sqli_vulnerable_target_pass() -> None:
    tautology = "' OR '1'='1' -- "

    def handler(params: dict[str, str]) -> tuple[int, bytes]:
        user = params.get("username", "")
        if user == tautology:
            return 200, b'{"user":"admin","token":"secret_xyz"}'
        return 401, b'{"error":"invalid credentials"}'

    v = SQLiValidator()
    verdict = v.validate(_candidate(), _ctx_with(_make_transport(handler)))

    assert verdict.is_real is True, verdict.evidence
    assert verdict.reason == "boolean_diff_confirmed"
    assert verdict.confidence == 0.90
    art = verdict.artifacts
    assert art["status_true"] == 200
    assert art["status_false"] == 401
    assert art["status_benign"] == 401
    assert art["false_like_benign"] is True
    assert art["true_differs_from_benign"] is True
    assert art["normalized_diff"] is True
    assert art["diff_reason"] == "status_differential"
    assert art["sha256_benign"] is not None and len(art["sha256_benign"]) == 64


def test_sqli_safe_target_fail_no_diff() -> None:
    def handler(params: dict[str, str]) -> tuple[int, bytes]:
        return 401, b'{"error":"invalid credentials"}'

    v = SQLiValidator()
    verdict = v.validate(_candidate(), _ctx_with(_make_transport(handler)))

    assert verdict.is_real is False
    assert verdict.reason == "no_boolean_diff"
    assert verdict.confidence == 0.0
    art = verdict.artifacts
    assert art["status_true"] == art["status_false"] == art["status_benign"] == 401
    assert art["normalized_diff"] is False


def test_sqli_echo_reflection_no_status_diff_fail() -> None:
    def handler(params: dict[str, str]) -> tuple[int, bytes]:
        user = params.get("username", "").encode("utf-8", "replace")
        return 400, b"received input: " + user

    v = SQLiValidator()
    verdict = v.validate(_candidate(), _ctx_with(_make_transport(handler)))

    assert verdict.is_real is False
    assert verdict.reason == "no_boolean_diff"
    art = verdict.artifacts
    assert art["sha256_true"] != art["sha256_false"]
    assert art["extra"]["sha256_norm_true"] == art["extra"]["sha256_norm_false"]


def test_sqli_body_diff_csrf_token_normalized_out_fail() -> None:
    counter = {"n": 0}

    def handler(params: dict[str, str]) -> tuple[int, bytes]:
        counter["n"] += 1
        csrf = f"csrf_{counter['n']:08d}abc"
        return (
            403,
            (
                f'<meta name="csrf-token" content="{csrf}">'
                f"<body>invalid credentials</body>"
            ).encode(),
        )

    v = SQLiValidator()
    verdict = v.validate(_candidate(), _ctx_with(_make_transport(handler)))

    assert verdict.is_real is False
    assert verdict.reason == "no_boolean_diff"
    art = verdict.artifacts
    assert art["sha256_true"] != art["sha256_false"]
    assert art["extra"]["sha256_norm_true"] == art["extra"]["sha256_norm_false"]


def test_sqli_body_only_diff_after_norm_pass_low_confidence() -> None:
    tautology = "' OR '1'='1' -- "

    def handler(params: dict[str, str]) -> tuple[int, bytes]:
        user = params.get("username", "")
        if user == tautology:
            return 200, b'{"result":"secret_data_leaked_via_sqli"}'
        return 200, b'{"result":"invalid credentials"}'

    v = SQLiValidator()
    verdict = v.validate(_candidate(), _ctx_with(_make_transport(handler)))

    assert verdict.is_real is True
    assert verdict.confidence == 0.65
    art = verdict.artifacts
    assert art["diff_reason"] == "body_differential_after_normalization"
    assert art["extra"]["status_differential"] is False
    assert art["extra"]["body_differential_after_norm"] is True


def test_sqli_out_of_scope_short_circuits() -> None:
    scope = Scope("acme")
    scope.add_domain("only-this-host.example")
    ctx = ValidatorContext(target=TARGET, extra={"scope": scope})
    v = SQLiValidator()
    verdict = v.validate(_candidate(), ctx)
    assert verdict.is_real is False
    assert verdict.reason == "out_of_scope"


def test_sqli_exception_wrapped_in_verdict() -> None:
    def _entry(request: httpx.Request) -> httpx.Response:
        raise RuntimeError("simulated network error")

    transport = httpx.MockTransport(_entry)
    v = SQLiValidator()
    verdict = v.validate(_candidate(), _ctx_with(transport))
    assert verdict.is_real is False
    assert verdict.confidence == 0.0
    assert verdict.reason


def test_sqli_auto_registered() -> None:
    registry.register(VulnerabilityClass.SQLI)(SQLiValidator)
    v = registry.get(VulnerabilityClass.SQLI)
    assert v is not None
    assert isinstance(v, SQLiValidator)
    assert v.name == "sqli_boolean_v1"
