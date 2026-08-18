"""XSS — reflection-context (Tier 1) + optional execution-differential (Tier 2).

Zero-deps (stdlib только). Tier 1 PASS: canary + raw HTML-breakout marker в окне
512 байт; escape-only → reflected_but_escaped. Tier 2 (опционально): before → trigger →
after — sha256 состояния должен измениться + expected_marker появиться.
"""

from __future__ import annotations

import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from orchestrator.types import Candidate, ValidatorContext, Verdict
from tools.core.vulnerability_class import VulnerabilityClass
from tools.validators import registry
from tools.validators.base import (
    BaseValidator,
    PayloadVariant,
    ValidationEvidence,
    check_scope,
)

_NAME = "xss_reflection_v1"

_RAW_MARKERS: tuple[bytes, ...] = (
    b"<script", b"</script", b"<img", b"onerror=", b"onload=",
    b"<svg", b"<iframe", b"javascript:",
)
_ESCAPED_MARKERS: tuple[bytes, ...] = (
    b"&lt;script", b"&lt;/script", b"&lt;img", b"onerror&#61;",
    b"&lt;svg", b"&lt;iframe",
)
_CANARY_PREFIX = "tgxss"
_PROXIMITY_WINDOW = 512


def _canary() -> str:
    return f"{_CANARY_PREFIX}_{secrets.token_hex(8)}"


def _http_get(
    url: str,
    *,
    timeout: float = 10.0,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers=headers or {}, method="GET")  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            body = resp.read()
            return int(resp.status), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return int(e.code), body


def _find_near(haystack: bytes, marker: bytes, canary_b: bytes, window: int) -> bool:
    canary_pos = 0
    while True:
        i = haystack.find(canary_b, canary_pos)
        if i < 0:
            return False
        start = max(0, i - window)
        end = min(len(haystack), i + len(canary_b) + window)
        if haystack.find(marker, start, end) >= 0:
            return True
        canary_pos = i + 1


@registry.register(VulnerabilityClass.XSS)
class XSSValidator(BaseValidator):
    """XSS Tier 1 (raw reflection) + optional Tier 2 (execution-differential)."""

    @property
    def name(self) -> str:
        return _NAME

    @property
    def vulnerability_class(self) -> VulnerabilityClass:
        return VulnerabilityClass.XSS

    def generate_payload(self, variant: PayloadVariant) -> str:
        c = "TG_CANARY_PLACEHOLDER"
        if variant == "true":
            return f'"><script>__tg({c})</script>'
        return c

    def compare_responses(self, resp_true: Any, resp_false: Any) -> bool:
        if not (isinstance(resp_true, dict) and isinstance(resp_false, dict)):
            return False
        return bool(resp_true.get("raw_markers_found") and not resp_false.get("raw_markers_found"))

    def validate(self, candidate: Candidate, ctx: ValidatorContext) -> Verdict:
        try:
            oos = check_scope(ctx, candidate.target)
            if oos == "out_of_scope":
                return self._out_of_scope_verdict(candidate.target)

            canary = _canary()
            canary_b = canary.encode("utf-8")
            true_payload = f'"><script>__tg({canary})</script>'
            false_payload = canary

            url_true = self._url_with(candidate, ctx, true_payload)
            url_false = self._url_with(candidate, ctx, false_payload)
            headers = {**(ctx.program_headers or {}), **(candidate.headers or {})}
            opener = ctx.extra.get("_http_opener") if ctx.extra else None
            _get = opener if callable(opener) else _http_get

            start = time.monotonic()
            st_t, body_t = _get(url_true, timeout=10.0, headers=headers)
            timing_t = round((time.monotonic() - start) * 1000.0, 3)

            start = time.monotonic()
            st_f, body_f = _get(url_false, timeout=10.0, headers=headers)
            timing_f = round((time.monotonic() - start) * 1000.0, 3)

            canary_reflected = canary_b in body_t
            raw_markers_in_true = [
                m.decode() for m in _RAW_MARKERS
                if _find_near(body_t, m, canary_b, _PROXIMITY_WINDOW)
            ]
            escaped_markers_in_true = [
                m.decode() for m in _ESCAPED_MARKERS if m in body_t
            ]

            tier: str = "none"
            is_real = False
            confidence = 0.0
            if not canary_reflected:
                reason = "not_reflected"
            elif raw_markers_in_true:
                tier = "reflection"
                reason = "raw_reflection_confirmed"
                is_real = True
                confidence = 0.75
            elif escaped_markers_in_true:
                reason = "reflected_but_escaped"
            else:
                reason = "reflected_without_breakout"

            exec_state_url = candidate.meta.get("exec_state_url")
            exec_trigger_url = candidate.meta.get("exec_trigger_url")
            exec_expected_marker = candidate.meta.get("exec_expected_marker")

            exec_state_before: str | None = None
            exec_state_after: str | None = None
            exec_changed = False
            exec_trigger_used = False
            exec_before_status: int | None = None
            exec_after_status: int | None = None

            if is_real and exec_state_url and exec_trigger_url:
                exec_state_url = str(exec_state_url)
                exec_trigger_url = str(exec_trigger_url)
                sb_status, sb_body = _get(exec_state_url, timeout=10.0, headers=headers)
                exec_before_status = int(sb_status)
                exec_state_before = ValidationEvidence.sha256_of(sb_body)
                _get(exec_trigger_url, timeout=10.0, headers=headers)
                exec_trigger_used = True
                sa_status, sa_body = _get(exec_state_url, timeout=10.0, headers=headers)
                exec_after_status = int(sa_status)
                exec_state_after = ValidationEvidence.sha256_of(sa_body)
                state_changed = exec_state_after != exec_state_before
                marker_check = True
                if exec_expected_marker:
                    marker = str(exec_expected_marker).encode("utf-8")
                    marker_check = marker in sa_body and marker not in sb_body
                if state_changed and marker_check:
                    exec_changed = True
                    tier = "execution"
                    reason = "execution_confirmed"
                    confidence = 1.0

            ev = ValidationEvidence(
                payload_true=true_payload,
                payload_false=false_payload,
                status_true=int(st_t),
                status_false=int(st_f),
                len_true=len(body_t),
                len_false=len(body_f),
                sha256_true=ValidationEvidence.sha256_of(body_t),
                sha256_false=ValidationEvidence.sha256_of(body_f),
                timing_ms_true=timing_t,
                timing_ms_false=timing_f,
                extra={
                    "canary_token": canary,
                    "payload_sent": true_payload,
                    "reflected_raw": canary_reflected and bool(raw_markers_in_true),
                    "reflected_escaped": canary_reflected and bool(escaped_markers_in_true),
                    "raw_markers_found": raw_markers_in_true,
                    "escaped_markers_found": escaped_markers_in_true,
                    "tier": tier,
                    "exec_state_before": exec_state_before,
                    "exec_state_after": exec_state_after,
                    "exec_before_status": exec_before_status,
                    "exec_after_status": exec_after_status,
                    "exec_changed": exec_changed,
                    "exec_trigger_used": exec_trigger_used,
                    "evidence_type": (
                        "execution_differential" if exec_changed
                        else "raw_reflection" if is_real
                        else "none"
                    ),
                },
            )

            evidence_text = (
                f"XSS {tier} tier: canary={canary}, raw_markers={raw_markers_in_true}, "
                f"exec_changed={exec_changed}, reason={reason}"
            )
            return Verdict(
                is_real=is_real,
                evidence=evidence_text,
                confidence=confidence,
                bug_class=self.vulnerability_class.value,
                validator=self.name,
                reason=reason,
                replays_passed=1 if is_real else 0,
                replays_total=1,
                artifacts=ev.to_dict(),
            )
        except Exception as e:
            return self.as_failure(e)

    def _url_with(
        self, candidate: Candidate, ctx: ValidatorContext, payload: str
    ) -> str:
        base = ctx.target.rstrip("/")
        path = candidate.path or "/"
        param = candidate.param or "q"
        query = urllib.parse.urlencode({param: payload})
        return f"{base}{path}?{query}"
