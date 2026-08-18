"""IDOR / BOLA — cross-user access к чужому ресурсу с приватным маркером.

PASS только если: attacker (через ctx.auth.opener(role)) получает 200 + маркер
жертвы, unauth → 401/403/404 или маркера нет. Если маркер виден unauth →
public_resource. Требует candidate.meta['victim_marker'] и ctx.auth.
"""

from __future__ import annotations

import time
from typing import Any

from orchestrator.types import Candidate, ValidatorContext, Verdict
from tools.core.vulnerability_class import VulnerabilityClass
from tools.validators import registry
from tools.validators.base import BaseValidator, PayloadVariant, ValidationEvidence

_NAME = "idor_cross_user_v1"
_DEFAULT_ATTACKER_ROLE = "attacker"


@registry.register(VulnerabilityClass.IDOR)
class IDORValidator(BaseValidator):
    """Cross-user IDOR/BOLA с обязательной проверкой приватности ресурса."""

    @property
    def name(self) -> str:
        return _NAME

    @property
    def vulnerability_class(self) -> VulnerabilityClass:
        return VulnerabilityClass.IDOR

    def generate_payload(self, variant: PayloadVariant) -> str:
        return "attacker_role_GET" if variant == "true" else "unauth_GET"

    def compare_responses(self, resp_true: Any, resp_false: Any) -> bool:
        if not (isinstance(resp_true, dict) and isinstance(resp_false, dict)):
            return False
        att_status = int(resp_true.get("status", 0))
        un_status = int(resp_false.get("status", 0))
        marker = str(resp_true.get("_marker", ""))
        att_body = resp_true.get("body", b"") or b""
        un_body = resp_false.get("body", b"") or b""
        cross_leaked = att_status == 200 and marker.encode("utf-8") in att_body
        resource_private = un_status in (401, 403, 404) or marker.encode("utf-8") not in un_body
        return cross_leaked and resource_private

    def validate(self, candidate: Candidate, ctx: ValidatorContext) -> Verdict:
        try:
            if ctx.auth is None:
                return Verdict(
                    is_real=False,
                    evidence="IDOR требует ctx.auth (AuthProvider с opener/unauth_opener)",
                    confidence=0.0,
                    bug_class=self.vulnerability_class.value,
                    validator=self.name,
                    reason="no_auth_provider",
                )
            marker = str(candidate.meta.get("victim_marker") or "")
            if not marker:
                return Verdict(
                    is_real=False,
                    evidence="IDOR требует candidate.meta['victim_marker']",
                    confidence=0.0,
                    bug_class=self.vulnerability_class.value,
                    validator=self.name,
                    reason="no_victim_marker",
                )

            role = str(candidate.meta.get("attacker_role") or _DEFAULT_ATTACKER_ROLE)
            path = candidate.path or "/"
            url = ctx.target.rstrip("/") + path
            headers = {**(ctx.program_headers or {}), **(candidate.headers or {})}

            att_client = ctx.auth.opener(role)
            un_client = ctx.auth.unauth_opener()

            att = self._get(att_client, url, headers)
            un = self._get(un_client, url, headers)

            att["_marker"] = marker
            un["_marker"] = marker

            att_marker_in = marker.encode("utf-8") in att["body"]
            un_marker_in = marker.encode("utf-8") in un["body"]
            is_real = self.compare_responses(att, un)

            ev = ValidationEvidence(
                payload_true=self.generate_payload("true"),
                payload_false=self.generate_payload("false"),
                status_true=int(att["status"]),
                status_false=int(un["status"]),
                len_true=int(att["len"]),
                len_false=int(un["len"]),
                sha256_true=str(att["sha256"]),
                sha256_false=str(un["sha256"]),
                timing_ms_true=float(att["timing_ms"]),
                timing_ms_false=float(un["timing_ms"]),
                extra={
                    "attacker_role": role,
                    "victim_marker_sha256": ValidationEvidence.sha256_of(marker),
                    "marker_present_in_attacker": att_marker_in,
                    "marker_present_in_unauth": un_marker_in,
                    "unauth_private": (
                        int(un["status"]) in (401, 403, 404) or not un_marker_in
                    ),
                },
            )

            if is_real:
                return Verdict(
                    is_real=True,
                    evidence=(
                        f"cross-user IDOR на {path}: attacker[{role}] → HTTP "
                        f"{att['status']} (маркер жертвы в теле), "
                        f"unauth → HTTP {un['status']} (маркер отсутствует)."
                    ),
                    confidence=1.0,
                    bug_class=self.vulnerability_class.value,
                    validator=self.name,
                    replays_passed=1,
                    replays_total=1,
                    artifacts=ev.to_dict(),
                )

            if un_marker_in:
                reason = "public_resource"
                explain = f"маркер виден unauth (HTTP {un['status']}) — публичные данные"
            elif int(att["status"]) != 200 or not att_marker_in:
                reason = "access_denied"
                explain = f"attacker[{role}] не получил маркер (HTTP {att['status']})"
            else:
                reason = "no_cross_user_leak"
                explain = "не сложились cross-user leak + приватность"

            return Verdict(
                is_real=False,
                evidence=f"IDOR не подтверждён на {path}: {explain}",
                confidence=0.0,
                bug_class=self.vulnerability_class.value,
                validator=self.name,
                reason=reason,
                replays_passed=0,
                replays_total=1,
                artifacts=ev.to_dict(),
            )
        except Exception as e:
            return self.as_failure(e)

    def _get(self, client: Any, url: str, headers: dict[str, str]) -> dict[str, Any]:
        start = time.monotonic()
        resp = client.get(url, headers=headers)
        elapsed_ms = round((time.monotonic() - start) * 1000.0, 3)
        body = resp.content or b""
        return {
            "status": int(resp.status_code),
            "body": body,
            "len": len(body),
            "sha256": ValidationEvidence.sha256_of(body),
            "timing_ms": elapsed_ms,
        }
