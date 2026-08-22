"""Anti-FP тесты для SSRFValidator (OOB, hostname strict)."""

from __future__ import annotations

import contextlib
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


def test_ssrf_callback_token_in_path_only_low_pass() -> None:
    """Callback от цели есть, hostname нормализовался — LOW-tier PASS + needs_proof.

    Ранее (v1) это было FAIL. Ревью показало, что это реальный сигнал: цель
    сходила на наш OOB, просто её резолвер/прокси нормализовал hostname. Для
    консенсуса это ценно (needs_proof=True); FAIL терял информацию.
    """

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
    assert verdict.is_real is True, verdict.evidence
    assert verdict.reason == "callback_without_token_in_hostname"
    assert verdict.confidence == 0.30
    art = verdict.artifacts
    assert art["extra"]["raw_hits_count"] >= 1
    assert art["extra"]["valid_hits_count"] == 0
    assert art["extra"]["needs_proof"] is True


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


def test_ssrf_dns_only_public_resolver_fail_but_needs_proof() -> None:
    """DNS-only + public resolver → FAIL, но выставляем needs_proof=True.

    Ранее reason оставался `dns_only_public_resolver` без needs_proof-сигнала.
    После ревью: SSRF мог быть, DNS кэшировался на публичном резолвере — это
    не «не уязвимо», а «нужен другой вектор» (как WAF в SQLi).
    """

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
    assert verdict.artifacts["extra"]["needs_proof"] is True


def test_ssrf_token_unique_between_validate_calls() -> None:
    """Каждый validate() выдаёт хотя бы один новый уникальный token.

    После code-review валидатор делает до _MAX_ATTEMPTS попыток с новым
    token'ом на каждой. При отсутствии hits ранний-выход после первой
    попытки НЕ срабатывает (нет success_status тоже нет — но при dummy
    transport 200 всегда есть); поэтому tokens может быть больше 3 —
    важно, чтобы все были уникальны.
    """
    oob = _MockOOB(hits_per_token={})
    v = SSRFValidator()
    for _ in range(3):
        v.validate(_candidate(), _ctx_with(oob, transport=_dummy_transport()))
    tokens = oob.tokens_issued
    assert len(tokens) >= 3, f"expected at least 3 tokens, got {len(tokens)}"
    assert len(set(tokens)) == len(tokens), "all issued tokens must be unique"


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


# ─── code-review fixes: new coverage ────────────────────────────────────────


def test_ssrf_http_callback_imds_via_source_ip_critical() -> None:
    """Callback пришёл на valid OOB-hostname, но source_ip = IMDS (169.254.169.254).

    Сценарий: сервер сделал server-side redirect в IMDS, а оттуда запрос
    вылетел на наш OOB. Ловим это как top-severity finding (conf 0.99,
    imds_fingerprint=True).
    """

    class _OOB(_MockOOB):
        def poll(self, token: str, wait_s: float) -> list[dict[str, Any]]:
            return [
                {
                    "hostname": f"{token}.{OOB_DOMAIN}",  # валидный
                    "type": "http",
                    "path": "/probe",
                    "source_ip": "169.254.169.254",
                    "resolver_type": "non_public",
                }
            ]

    oob = _OOB()
    v = SSRFValidator()
    verdict = v.validate(_candidate(), _ctx_with(oob, transport=_dummy_transport()))
    assert verdict.is_real is True, verdict.evidence
    assert verdict.reason == "http_callback_imds"
    assert verdict.confidence == 0.99
    assert verdict.artifacts["extra"]["imds_fingerprint"] is True


def test_ssrf_body_exfiltration_oob_token() -> None:
    """Reflected SSRF: OOB-token отражён в response body → PASS body_exfil."""

    captured_token: dict[str, str] = {}

    def _mock_handler(req: httpx.Request) -> httpx.Response:
        # Возвращаем тело, содержащее OOB-token из query.  Ищем самый длинный
        # subdomain-label (не 'probe', не 'oob') — это наш token.
        url = str(req.url)
        # Достаём token из query-param 'url' (default injection).
        payload = ""
        with contextlib.suppress(Exception):
            parsed = httpx.URL(url)
            payload = parsed.params.get("url", "")
        # payload — что-то типа http://<token>.oob.truthgate.test/probe.
        host = ""
        with contextlib.suppress(Exception):
            host = httpx.URL(payload).host
        token_guess = host.split(".")[0] if host else ""
        if token_guess:
            captured_token["token"] = token_guess
        body = f"fetched: {payload}".encode()
        return httpx.Response(status_code=200, content=body)

    transport = httpx.MockTransport(_mock_handler)

    oob = _MockOOB(hits_per_token={})  # ни одного OOB callback'а
    v = SSRFValidator()
    verdict = v.validate(_candidate(), _ctx_with(oob, transport=transport))

    # body_exfil должен сработать: OOB-hostname отражён в теле.
    assert verdict.is_real is True, verdict.evidence
    assert verdict.reason == "body_exfiltration_oob_token"
    assert verdict.confidence == 0.90
    assert verdict.artifacts["extra"]["body_exfil"] is True


def test_ssrf_body_exfiltration_imds_markers() -> None:
    """Body содержит IMDS-маркер (ami-id) → PASS body_exfil + imds_fingerprint."""

    def _handler(req: httpx.Request) -> httpx.Response:
        _ = req
        body = b"ami-id\ni-0123456789abcdef0\ninstance-identity/document\n"
        return httpx.Response(status_code=200, content=body)

    oob = _MockOOB(hits_per_token={})
    v = SSRFValidator()
    verdict = v.validate(
        _candidate(), _ctx_with(oob, transport=httpx.MockTransport(_handler))
    )
    assert verdict.is_real is True, verdict.evidence
    assert verdict.reason == "body_exfiltration_imds_markers"
    assert verdict.artifacts["extra"]["imds_fingerprint"] is True
    assert "ami-id" in verdict.artifacts["extra"]["imds_body_markers"]


def test_ssrf_target_rejected_request_early_fail() -> None:
    """Все probe-запросы отдали 400/500 → reason target_rejected_request, не ждём OOB."""

    def _handler(req: httpx.Request) -> httpx.Response:
        _ = req
        return httpx.Response(status_code=400, content=b"bad request")

    oob = _MockOOB(hits_per_token={})
    v = SSRFValidator()
    verdict = v.validate(
        _candidate(), _ctx_with(oob, transport=httpx.MockTransport(_handler))
    )
    assert verdict.is_real is False
    assert verdict.reason == "target_rejected_request"
    assert verdict.artifacts["extra"]["target_all_rejected"] is True


def test_ssrf_post_json_injection_point() -> None:
    """meta.injection_point=body, content_type=json — payload в JSON-теле, метод POST."""

    seen_methods: list[str] = []
    seen_json_urls: list[str] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        seen_methods.append(req.method)
        with contextlib.suppress(Exception):
            import json as _json

            data = _json.loads(req.content.decode() or "{}") if req.content else {}
            if isinstance(data, dict) and "url" in data:
                seen_json_urls.append(str(data["url"]))
        return httpx.Response(status_code=200, content=b"ok")

    cand = Candidate(
        id="cand-ssrf-post",
        bug_class="ssrf",
        target=TARGET,
        path=PROBE_PATH,
        method="POST",
        param="url",
        meta={"injection_point": "body", "content_type": "json"},
    )
    oob = _MockOOB(hits_per_token={})
    v = SSRFValidator()
    v.validate(cand, _ctx_with(oob, transport=httpx.MockTransport(_handler)))
    assert "POST" in seen_methods, seen_methods
    # Хотя бы один payload должен быть URL с поддерживаемой схемой.
    _schemes = ("http://", "https://", "gopher://", "file://")
    assert any(u.startswith(_schemes) for u in seen_json_urls), seen_json_urls


def test_ssrf_header_injection_point() -> None:
    """meta.injection_point=header — payload попадает в X-Callback-URL header."""

    seen_headers: list[str] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        hv = req.headers.get("X-Callback-URL", "")
        if hv:
            seen_headers.append(hv)
        return httpx.Response(status_code=200, content=b"ok")

    cand = Candidate(
        id="cand-ssrf-hdr",
        bug_class="ssrf",
        target=TARGET,
        path=PROBE_PATH,
        method="GET",
        param="url",
        meta={"injection_point": "header", "header_name": "X-Callback-URL"},
    )
    oob = _MockOOB(hits_per_token={})
    v = SSRFValidator()
    v.validate(cand, _ctx_with(oob, transport=httpx.MockTransport(_handler)))
    assert seen_headers, "X-Callback-URL header must be sent at least once"


def test_ssrf_multi_scheme_variants_sent() -> None:
    """extended_schemes=True: пробуем http+https+gopher+file."""

    seen_schemes: set[str] = set()

    def _handler(req: httpx.Request) -> httpx.Response:
        # payload идёт в query 'url'
        with contextlib.suppress(Exception):
            payload = req.url.params.get("url", "")
            scheme = httpx.URL(payload).scheme if payload else ""
            if scheme:
                seen_schemes.add(scheme)
        return httpx.Response(status_code=200, content=b"ok")

    cand = Candidate(
        id="cand-ssrf-multi",
        bug_class="ssrf",
        target=TARGET,
        path=PROBE_PATH,
        method="GET",
        param="url",
        meta={"extended_schemes": True},
    )
    oob = _MockOOB(hits_per_token={})
    v = SSRFValidator()
    verdict = v.validate(
        cand, _ctx_with(oob, transport=httpx.MockTransport(_handler))
    )
    assert {"http", "https", "gopher", "file"}.issubset(seen_schemes), seen_schemes
    assert set(verdict.artifacts["extra"]["schemes_tried"]) == {
        "http",
        "https",
        "gopher",
        "file",
    }


def test_ssrf_url_parser_bypass_variants_sent() -> None:
    """Отсылаем userinfo/null-byte/tab/backslash-варианты; они видны в per_attempt."""

    def _handler(req: httpx.Request) -> httpx.Response:
        _ = req
        return httpx.Response(status_code=200, content=b"ok")

    oob = _MockOOB(hits_per_token={})
    v = SSRFValidator()
    verdict = v.validate(
        _candidate(), _ctx_with(oob, transport=httpx.MockTransport(_handler))
    )
    per_attempt = verdict.artifacts["extra"]["per_attempt"]
    assert per_attempt, "per_attempt must not be empty"
    variants = set(per_attempt[0]["variants_sent"])
    assert {"bypass_userinfo", "bypass_null_byte", "bypass_tab", "bypass_backslash"}.issubset(
        variants
    ), variants


def test_ssrf_ip_variants_sent() -> None:
    """IP-варианты ([::1], hex, decimal, short, octal) отсылаются."""

    def _handler(req: httpx.Request) -> httpx.Response:
        _ = req
        return httpx.Response(status_code=200, content=b"ok")

    oob = _MockOOB(hits_per_token={})
    v = SSRFValidator()
    verdict = v.validate(
        _candidate(), _ctx_with(oob, transport=httpx.MockTransport(_handler))
    )
    variants = set(verdict.artifacts["extra"]["per_attempt"][0]["variants_sent"])
    assert {
        "ip_ipv6_loopback",
        "ip_ipv4_hex",
        "ip_ipv4_decimal",
        "ip_ipv4_short",
        "ip_ipv4_octal",
    }.issubset(variants), variants


def test_ssrf_redirect_probe_when_template_set() -> None:
    """meta.redirector_template с {oob} — добавляется variant 'redirect_probe'."""

    def _handler(req: httpx.Request) -> httpx.Response:
        _ = req
        return httpx.Response(status_code=200, content=b"ok")

    cand = Candidate(
        id="cand-ssrf-redir",
        bug_class="ssrf",
        target=TARGET,
        path=PROBE_PATH,
        method="GET",
        param="url",
        meta={"redirector_template": "http://red.example/r?to={oob}"},
    )
    oob = _MockOOB(hits_per_token={})
    v = SSRFValidator()
    verdict = v.validate(cand, _ctx_with(oob, transport=httpx.MockTransport(_handler)))
    variants = set(verdict.artifacts["extra"]["per_attempt"][0]["variants_sent"])
    assert "redirect_probe" in variants, variants
    assert verdict.artifacts["extra"]["redirector_probed"] is True


def test_ssrf_source_ip_classified_private() -> None:
    """source_ip 10.x → 'private' в артефактах."""

    class _OOB(_MockOOB):
        def poll(self, token: str, wait_s: float) -> list[dict[str, Any]]:
            return [
                {
                    "hostname": f"{token}.{OOB_DOMAIN}",
                    "type": "http",
                    "path": "/probe",
                    "source_ip": "10.0.0.42",
                    "resolver_type": "non_public",
                }
            ]

    oob = _OOB()
    v = SSRFValidator()
    verdict = v.validate(_candidate(), _ctx_with(oob, transport=_dummy_transport()))
    assert verdict.artifacts["extra"]["callback_source_ip_class"] == "private"


def test_ssrf_payload_false_actually_sent() -> None:
    """Baseline FALSE probe действительно отправляется (Баг 10)."""

    called_urls: list[str] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        called_urls.append(str(req.url))
        return httpx.Response(status_code=200, content=b"ok")

    oob = _MockOOB(hits_per_token={})
    v = SSRFValidator()
    verdict = v.validate(
        _candidate(), _ctx_with(oob, transport=httpx.MockTransport(_handler))
    )
    # false-probe: url-param содержит 127.0.0.1:1
    assert any("127.0.0.1%3A1" in u or "127.0.0.1:1" in u for u in called_urls), called_urls
    # payload_false зафиксирован в артефактах.
    assert verdict.artifacts["payload_false"] == "http://127.0.0.1:1/probe"
    # false_probe_status в extra.
    assert "false_probe_status" in verdict.artifacts["extra"]
