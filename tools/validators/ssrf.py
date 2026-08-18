"""SSRF — OOB callback с уникальным token в hostname.

PASS только при HTTP callback на token.oob_domain (conf 0.95) или DNS-only на
non-public resolver (conf 0.65). Token только в path/query/body → FAIL.
ctx.oob обязателен.
"""

from __future__ import annotations

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

_NAME = "ssrf_oob_v1"


def _hostname_matches_token(hostname: str, token: str, oob_domain: str) -> bool:
    if not hostname or not token or not oob_domain:
        return False
    exact = f"{token}.{oob_domain}".lower()
    host_l = hostname.lower()
    return host_l == exact or host_l.endswith(f".{exact}")


@registry.register(VulnerabilityClass.SSRF)
class SSRFValidator(BaseValidator):
    """SSRF: PASS только при OOB callback с уникальным token в hostname."""

    @property
    def name(self) -> str:
        return _NAME

    @property
    def vulnerability_class(self) -> VulnerabilityClass:
        return VulnerabilityClass.SSRF

    def generate_payload(self, variant: PayloadVariant) -> str:
        return "http://<oob-url-placeholder>/probe" if variant == "true" else "http://127.0.0.1:1/probe"

    def compare_responses(self, resp_true: Any, resp_false: Any) -> bool:
        if not (isinstance(resp_true, dict) and isinstance(resp_false, dict)):
            return False
        return bool(resp_true.get("oob_hits"))

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

            probe_id = f"ssrf-{candidate.id}"
            token, oob_url = ctx.oob.new_token(probe_id)
            token = str(token)
            oob_url = str(oob_url)
            oob_hostname = urllparse_hostname(oob_url)
            oob_domain = ""
            if oob_hostname and oob_hostname.lower().startswith(f"{token.lower()}."):
                oob_domain = oob_hostname[len(token) + 1:]
            elif oob_hostname:
                oob_domain = oob_hostname

            transport = ctx.extra.get("http_transport") if ctx.extra else None
            request_url = self._build_request_url(candidate, ctx, oob_url)
            attempts = 1
            request_error: str | None = None
            request_status: int | None = None

            with httpx.Client(
                transport=transport,
                timeout=10.0,
                verify=ctx.tls_verify,
                follow_redirects=False,
            ) as client:
                try:
                    resp = client.get(
                        request_url,
                        headers={**(ctx.program_headers or {}), **(candidate.headers or {})},
                    )
                    request_status = int(resp.status_code)
                except Exception as req_e:
                    request_error = f"{type(req_e).__name__}: {req_e}"

            wait_s = float(ctx.poll_wait_s or 12.0)
            start = time.monotonic()
            hits = ctx.oob.poll(token, wait_s) or []
            waited_ms = round((time.monotonic() - start) * 1000.0, 3)

            valid_hits: list[dict[str, Any]] = []
            for h in hits:
                if not isinstance(h, dict):
                    continue
                host = str(h.get("hostname") or "")
                if _hostname_matches_token(host, token, oob_domain):
                    valid_hits.append(h)

            http_hits = [h for h in valid_hits if str(h.get("type", "")).lower() == "http"]
            dns_hits = [h for h in valid_hits if str(h.get("type", "")).lower() == "dns"]

            is_real = False
            confidence = 0.0
            best_hit: dict[str, Any] = {}

            if http_hits:
                callback_type = "http"
                best_hit = http_hits[0]
                is_real = True
                confidence = 0.95
                reason = "http_callback_confirmed"
            elif dns_hits:
                best_hit = dns_hits[0]
                resolver_type = str(best_hit.get("resolver_type", "unknown")).lower()
                callback_type = "dns"
                if resolver_type == "non_public":
                    is_real = True
                    confidence = 0.65
                    reason = "dns_only_callback"
                elif resolver_type == "public":
                    reason = "dns_only_public_resolver"
                else:
                    reason = "dns_only_unknown_resolver"
            elif hits and not valid_hits:
                callback_type = "none"
                reason = "callback_without_token_in_hostname"
            else:
                callback_type = "none"
                reason = "no_oob_callback"

            payload_true = oob_url
            payload_false = self.generate_payload("false")
            body_placeholder = b""

            ev = ValidationEvidence(
                payload_true=payload_true,
                payload_false=payload_false,
                status_true=int(request_status) if request_status is not None else 0,
                status_false=0,
                len_true=0,
                len_false=0,
                sha256_true=ValidationEvidence.sha256_of(body_placeholder),
                sha256_false=ValidationEvidence.sha256_of(body_placeholder),
                timing_ms_true=0.0,
                timing_ms_false=0.0,
                oob_hit=is_real,
                oob_token=token,
                extra={
                    "oob_hostname": oob_hostname,
                    "oob_domain": oob_domain,
                    "callback_type": callback_type,
                    "callback_hostname": str(best_hit.get("hostname", "")) if best_hit else "",
                    "callback_path": str(best_hit.get("path", "")) if best_hit else "",
                    "callback_source_ip": str(best_hit.get("source_ip", "")) if best_hit else "",
                    "resolver_type": str(best_hit.get("resolver_type", "unknown")) if best_hit else "unknown",
                    "request_url_sent": request_url,
                    "request_status": request_status,
                    "request_error": request_error,
                    "attempts": attempts,
                    "waited_ms": waited_ms,
                    "raw_hits_count": len(hits),
                    "valid_hits_count": len(valid_hits),
                },
            )

            evidence_text = (
                f"SSRF: token={token}, callback_type={callback_type}, "
                f"hits={len(hits)}, valid={len(valid_hits)}, reason={reason}"
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

    def _build_request_url(
        self, candidate: Candidate, ctx: ValidatorContext, oob_url: str
    ) -> str:
        import urllib.parse
        base = ctx.target.rstrip("/")
        path = candidate.path or "/"
        param = candidate.param or "url"
        return f"{base}{path}?{urllib.parse.urlencode({param: oob_url})}"


def urllparse_hostname(url: str) -> str:
    import urllib.parse
    return (urllib.parse.urlparse(url).hostname or "").lower()
