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


# ---------------------------------------------------------------------------
# M1 hardening: numeric params / error-based / time-based / union / replays / WAF.
# ---------------------------------------------------------------------------


def _numeric_candidate() -> Candidate:
    return Candidate(
        id="cand-sqli-num-1",
        bug_class="sqli",
        target=TARGET,
        path="/api/product",
        method="GET",
        param="productId",
        meta={
            "param_type": "numeric",
            "param_value": "7",
            # Endpoint GET /api/product?productId=N — пароля нет.
            "password_param": "",
        },
    )


def _get_transport(handler: Callable[[dict[str, str]], tuple[int, bytes]]) -> httpx.MockTransport:
    """GET-обработчик: параметры — из query-string."""
    def _entry(request: httpx.Request) -> httpx.Response:
        from urllib.parse import parse_qs
        raw_q = request.url.query
        q_str = raw_q.decode("utf-8") if isinstance(raw_q, bytes) else raw_q
        qs = parse_qs(q_str)
        params: dict[str, str] = {k: v[0] if v else "" for k, v in qs.items()}
        status, body = handler(params)
        return httpx.Response(status_code=status, content=body)

    return httpx.MockTransport(_entry)


def test_sqli_numeric_params_pass() -> None:
    """Числовой параметр productId=7: `7 OR 1=1` vs `7 AND 1=2`, benign=-2147483647."""
    def handler(params: dict[str, str]) -> tuple[int, bytes]:
        pid = params.get("productId", "")
        # TRUE: `7 OR 1=1` — bypass, все продукты.
        if "OR 1=1" in pid:
            return 200, b'{"products":[{"id":1},{"id":2},{"id":11}]}'
        # FALSE: `7 AND 1=2` — 0 rows (предикат ложен).
        if "AND 1=2" in pid:
            return 200, b'{"products":[]}'
        # Benign с несуществующим id → 0 rows. Совпадает с FALSE-семантикой.
        if pid == "-2147483647":
            return 200, b'{"products":[]}'
        # Error-probe `'` — ошибка синтаксиса без сигнатуры БД (nudge, но не PASS).
        return 400, b'{"error":"bad request"}'

    v = SQLiValidator()
    verdict = v.validate(_numeric_candidate(), _ctx_with(_get_transport(handler)))

    assert verdict.is_real is True, verdict.evidence
    assert verdict.reason == "boolean_diff_confirmed"
    art = verdict.artifacts
    assert art["extra"]["mode"] == "numeric"
    assert art["payload_true"].startswith("7 OR 1=1")
    assert art["payload_false"].startswith("7 AND 1=2")
    assert art["extra"]["error_based_confirmed"] is False


def test_sqli_error_based_fingerprint_pass() -> None:
    """Boolean не срабатывает, но `'` вызывает MySQL-ошибку."""
    def handler(params: dict[str, str]) -> tuple[int, bytes]:
        user = params.get("username", "")
        if user == "'":
            return 500, (
                b"<html><body>You have an error in your SQL syntax; "
                b"check the manual that corresponds to your MySQL server version"
                b"</body></html>"
            )
        # Всё остальное — одинаковый безобидный отказ.
        return 401, b'{"error":"invalid credentials"}'

    v = SQLiValidator()
    verdict = v.validate(_candidate(), _ctx_with(_make_transport(handler)))

    assert verdict.is_real is True, verdict.evidence
    assert verdict.reason == "error_based_confirmed"
    art = verdict.artifacts
    assert art["extra"]["error_based_confirmed"] is True
    assert art["extra"]["db_error_fingerprint"] == "mysql"
    assert art["extra"]["db_error_fingerprint_in_benign"] is None
    assert verdict.confidence == 0.70


def test_sqli_error_based_absent_in_probe_no_upgrade() -> None:
    """Нет DB-сигнатуры → boolean-fail остаётся boolean-fail."""
    def handler(params: dict[str, str]) -> tuple[int, bytes]:
        return 401, b'{"error":"invalid credentials"}'

    v = SQLiValidator()
    verdict = v.validate(_candidate(), _ctx_with(_make_transport(handler)))

    assert verdict.is_real is False
    assert verdict.reason == "no_boolean_diff"
    art = verdict.artifacts
    assert art["extra"]["error_based_confirmed"] is False
    assert art["extra"]["db_error_fingerprint"] is None


def test_sqli_error_based_fingerprint_also_in_benign_no_upgrade() -> None:
    """MySQL-сигнатура и в err-probe, и в benign → это не эксплуатируемая инъекция."""
    body = (
        b"<html><body>server error: You have an error in your SQL syntax"
        b"</body></html>"
    )

    def handler(params: dict[str, str]) -> tuple[int, bytes]:
        return 500, body

    v = SQLiValidator()
    verdict = v.validate(_candidate(), _ctx_with(_make_transport(handler)))

    assert verdict.is_real is False
    art = verdict.artifacts
    assert art["extra"]["db_error_fingerprint"] == "mysql"
    assert art["extra"]["db_error_fingerprint_in_benign"] == "mysql"
    assert art["extra"]["error_based_confirmed"] is False


def test_sqli_waf_blocked_reason() -> None:
    """TRUE и FALSE ловятся WAF-ом (403), benign проходит (200)."""
    tautology = "' OR '1'='1' -- "
    false_payload = "' OR '1'='2' -- "

    def handler(params: dict[str, str]) -> tuple[int, bytes]:
        user = params.get("username", "")
        if user in (tautology, false_payload):
            return 403, b'{"error":"blocked by WAF"}'
        # benign и err-probe (одиночная кавычка) — 200, чтобы не попасть в WAF-множество.
        return 200, b'{"result":"ok"}'

    v = SQLiValidator()
    verdict = v.validate(_candidate(), _ctx_with(_make_transport(handler)))

    assert verdict.is_real is False
    assert verdict.reason == "waf_blocked"
    art = verdict.artifacts
    assert art["extra"]["waf_blocked"] is True
    assert art["extra"]["needs_proof"] is True
    assert art["status_true"] == 403
    assert art["status_false"] == 403
    assert art["status_benign"] == 200


def test_sqli_union_canary_extraction_upgrades_confidence(monkeypatch: pytest.MonkeyPatch) -> None:
    """boolean+status_diff → UNION probe с canary → canary в теле → 0.95."""
    tautology = "' OR '1'='1' -- "

    def handler(params: dict[str, str]) -> tuple[int, bytes]:
        user = params.get("username", "")
        if user == tautology:
            return 200, b'{"user":"admin"}'
        if "UNION SELECT" in user:
            # Extract canary and reflect it.
            import re as _re
            m = _re.search(r"'(un_[0-9a-f]{16})'", user)
            token = m.group(1) if m else "no-canary"
            return 200, ('{"row":"' + token + '"}').encode()
        return 401, b'{"error":"invalid"}'

    v = SQLiValidator()
    verdict = v.validate(_candidate(), _ctx_with(_make_transport(handler)))

    assert verdict.is_real is True, verdict.evidence
    assert verdict.reason == "union_canary_extracted"
    assert verdict.confidence == 0.95
    art = verdict.artifacts
    assert art["extra"]["union_probe_sent"] is True
    assert art["extra"]["union_canary_reflected"] is True
    assert art["diff_reason"] == "data_extraction_via_union_confirmed"


def test_sqli_time_based_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """SLEEP payload с delta ≥ 4s (два прогона) → time_based_confirmed."""
    def handler(params: dict[str, str]) -> tuple[int, bytes]:
        return 401, b'{"error":"invalid"}'

    # Подменяем time.monotonic так, чтобы каждый SLEEP-запрос выглядел >= 5s.
    # Каждый _send делает два вызова monotonic (start, end).
    ticks = iter(_gen_monotonic_ticks())
    monkeypatch.setattr("tools.validators.sqli.time.monotonic", lambda: next(ticks))

    cand = Candidate(
        id="cand-sqli-time",
        bug_class="sqli",
        target=TARGET,
        path=LOGIN_PATH,
        method="POST",
        param="username",
        meta={"password_param": "password", "content_type": "form", "timing_based": True},
    )
    v = SQLiValidator()
    verdict = v.validate(cand, _ctx_with(_make_transport(handler)))

    assert verdict.is_real is True, verdict.evidence
    assert verdict.reason == "time_based_confirmed"
    assert verdict.confidence == 0.85
    art = verdict.artifacts
    assert art["extra"]["timing_based_enabled"] is True
    assert art["extra"]["time_based_confirmed"] is True


def _gen_monotonic_ticks() -> list[float]:
    """Быстрые тики для 3+ regular-запросов, потом длинные для SLEEP-запросов."""
    ticks: list[float] = []
    t = 0.0
    # Round-1 (TRUE, FALSE, benign) + err-probe: 4 запроса.
    # (UNION-probe не вызывается — boolean fail.)
    # На каждый запрос — по 2 monotonic-вызова (start, end).
    for _ in range(4):
        ticks.extend([t, t + 0.01])
        t += 0.02
    # Теперь SLEEP: 2 прогона, каждый должен выглядеть >= 5s.
    for _ in range(2):
        ticks.extend([t, t + 6.0])
        t += 6.1
    return ticks


def test_sqli_replays_stability_multi_run() -> None:
    """При replays=3 требуется 2/3 diff-yes раундов, чтобы дать PASS."""
    tautology = "' OR '1'='1' -- "
    counter = {"n": 0}

    def handler(params: dict[str, str]) -> tuple[int, bytes]:
        user = params.get("username", "")
        counter["n"] += 1
        if user == tautology:
            return 200, b'{"user":"admin"}'
        return 401, b'{"error":"invalid"}'

    ctx = ValidatorContext(
        target=TARGET,
        replays=3,
        dry_run=True,
        extra={"http_transport": _make_transport(handler)},
    )
    v = SQLiValidator()
    verdict = v.validate(_candidate(), ctx)

    assert verdict.is_real is True
    art = verdict.artifacts
    assert art["extra"]["replays_total"] == 3
    assert art["extra"]["replays_required"] == 2
    assert art["extra"]["replays_diff_yes"] >= 2
    # Каждый раунд — 3 запроса; всего минимум 3*3 = 9 регулярных +1 err_probe.
    assert counter["n"] >= 9


def test_sqli_replays_unstable_no_pass() -> None:
    """replays=3, только 1 раунд с diff — недостаточно (required=2)."""
    tautology = "' OR '1'='1' -- "
    state = {"round": 0, "req": 0}

    def handler(params: dict[str, str]) -> tuple[int, bytes]:
        state["req"] += 1
        user = params.get("username", "")
        # Каждый раунд = 3 запроса. Только в первом раунде TRUE даёт 200.
        current_round = (state["req"] - 1) // 3 + 1
        if user == tautology and current_round == 1:
            return 200, b'{"user":"admin"}'
        return 401, b'{"error":"invalid"}'

    ctx = ValidatorContext(
        target=TARGET,
        replays=3,
        dry_run=True,
        extra={"http_transport": _make_transport(handler)},
    )
    v = SQLiValidator()
    verdict = v.validate(_candidate(), ctx)

    assert verdict.is_real is False
    art = verdict.artifacts
    assert art["extra"]["replays_diff_yes"] < 2
    assert verdict.reason in ("boolean_diff_unstable", "no_boolean_diff")
