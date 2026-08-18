"""Anti-FP тесты для XSSValidator (Tier 1 + Tier 2, zero-deps)."""

from __future__ import annotations

import sys
from typing import Any

import pytest

from orchestrator.scope import Scope
from orchestrator.types import Candidate, ValidatorContext
from tools.core.vulnerability_class import VulnerabilityClass
from tools.validators import registry
from tools.validators.xss import XSSValidator

pytestmark = pytest.mark.anti_fp

TARGET = "https://xss.example"
PATH = "/search"


def _candidate(**meta: Any) -> Candidate:
    return Candidate(
        id="cand-xss-1",
        bug_class="xss",
        target=TARGET,
        path=PATH,
        method="GET",
        param="q",
        meta=meta,
    )


def _ctx_with(opener, scope: Scope | None = None) -> ValidatorContext:
    extra: dict = {"_http_opener": opener}
    if scope is not None:
        extra["scope"] = scope
    return ValidatorContext(target=TARGET, replays=1, dry_run=True, extra=extra)


def test_xss_tier1_raw_reflection_pass() -> None:
    captured: dict = {"canary": None}

    def opener(url, *, timeout=10.0, headers=None):
        import re
        m = re.search(r"tgxss_[0-9a-f]{16}", url)
        if m:
            captured["canary"] = m.group(0)
        if "%3Cscript%3E" in url:
            body = b'<div class="q"><script>__tg(' + captured["canary"].encode() + b")</script></div>"
        else:
            body = b'<div class="q">' + captured["canary"].encode() + b"</div>"
        return 200, body

    v = XSSValidator()
    verdict = v.validate(_candidate(), _ctx_with(opener))

    assert verdict.is_real is True, verdict.evidence
    assert verdict.reason == "raw_reflection_confirmed"
    assert verdict.confidence == 0.75
    art = verdict.artifacts
    assert art["extra"]["tier"] == "reflection"
    assert art["extra"]["reflected_raw"] is True
    assert art["extra"]["evidence_type"] == "raw_reflection"
    assert any("<script" in m for m in art["extra"]["raw_markers_found"])
    assert art["extra"]["canary_token"].startswith("tgxss_")


def test_xss_reflected_but_escaped_fail() -> None:
    captured: dict = {"canary": None}

    def opener(url, *, timeout=10.0, headers=None):
        import re
        m = re.search(r"tgxss_[0-9a-f]{16}", url)
        if m:
            captured["canary"] = m.group(0)
        body = b"<div>&lt;script&gt;__tg(" + captured["canary"].encode() + b")&lt;/script&gt;</div>"
        return 200, body

    v = XSSValidator()
    verdict = v.validate(_candidate(), _ctx_with(opener))
    assert verdict.is_real is False
    assert verdict.reason == "reflected_but_escaped"
    assert verdict.confidence == 0.0
    art = verdict.artifacts
    assert art["extra"]["reflected_raw"] is False
    assert art["extra"]["reflected_escaped"] is True


def test_xss_not_reflected_fail() -> None:
    def opener(url, *, timeout=10.0, headers=None):
        return 200, b"<html><body>no user input rendered here</body></html>"

    v = XSSValidator()
    verdict = v.validate(_candidate(), _ctx_with(opener))
    assert verdict.is_real is False
    assert verdict.reason == "not_reflected"
    assert verdict.confidence == 0.0


def test_xss_canary_unique_per_validate() -> None:
    tokens = set()

    def opener(url, *, timeout=10.0, headers=None):
        import re
        m = re.search(r"tgxss_[0-9a-f]{16}", url)
        if m:
            tokens.add(m.group(0))
        return 200, b"no reflection"

    v = XSSValidator()
    for _ in range(4):
        v.validate(_candidate(), _ctx_with(opener))
    assert len(tokens) == 4


def test_xss_tier2_execution_confirmed_pass() -> None:
    captured: dict = {"canary": None, "state_reads": 0}

    def opener(url, *, timeout=10.0, headers=None):
        import re
        m = re.search(r"tgxss_[0-9a-f]{16}", url)
        if m and captured["canary"] is None:
            captured["canary"] = m.group(0)
        if url.endswith("/state"):
            captured["state_reads"] += 1
            if captured["state_reads"] == 1:
                return 200, b'{"logs":[]}'
            return 200, b'{"logs":["xss_fired_marker_z9"]}'
        if url.endswith("/trigger"):
            return 200, b'{"ok":true}'
        if "%3Cscript%3E" in url:
            body = b'<script>__tg(' + captured["canary"].encode() + b")</script>"
        else:
            body = captured["canary"].encode()
        return 200, body

    v = XSSValidator()
    cand = _candidate(
        exec_state_url=f"{TARGET}/state",
        exec_trigger_url=f"{TARGET}/trigger",
        exec_expected_marker="xss_fired_marker_z9",
    )
    verdict = v.validate(cand, _ctx_with(opener))

    assert verdict.is_real is True, verdict.evidence
    assert verdict.reason == "execution_confirmed"
    assert verdict.confidence == 1.0
    art = verdict.artifacts
    assert art["extra"]["tier"] == "execution"
    assert art["extra"]["exec_changed"] is True
    assert art["extra"]["exec_trigger_used"] is True
    assert art["extra"]["evidence_type"] == "execution_differential"
    assert art["extra"]["exec_state_before"] != art["extra"]["exec_state_after"]


def test_xss_tier2_ignored_if_tier1_fails() -> None:
    def opener(url, *, timeout=10.0, headers=None):
        if url.endswith("/state") or url.endswith("/trigger"):
            return 200, b'{"logs":["something"]}'
        return 200, b"<div>&lt;script&gt;escaped&lt;/script&gt;</div>tgxss_deadbeefdeadbeef"

    v = XSSValidator()
    cand = _candidate(
        exec_state_url=f"{TARGET}/state",
        exec_trigger_url=f"{TARGET}/trigger",
    )
    verdict = v.validate(cand, _ctx_with(opener))
    assert verdict.is_real is False
    assert verdict.reason in ("reflected_but_escaped", "not_reflected")
    art = verdict.artifacts
    assert art["extra"]["exec_trigger_used"] is False


def test_xss_out_of_scope_short_circuits() -> None:
    scope = Scope("acme")
    scope.add_domain("other.example")
    ctx = ValidatorContext(target=TARGET, extra={"scope": scope})
    v = XSSValidator()
    verdict = v.validate(_candidate(), ctx)
    assert verdict.is_real is False
    assert verdict.reason == "out_of_scope"


def test_xss_no_headless_browser_imports() -> None:
    banned = {"playwright", "selenium", "pyppeteer", "playwright.sync_api"}
    for name in list(sys.modules):
        assert not any(name == b or name.startswith(f"{b}.") for b in banned), (
            f"XSS validator должен быть zero-deps, но модуль {name!r} в sys.modules"
        )


def test_xss_auto_registered() -> None:
    registry.register(VulnerabilityClass.XSS)(XSSValidator)
    v = registry.get(VulnerabilityClass.XSS)
    assert v is not None
    assert isinstance(v, XSSValidator)
    assert v.name == "xss_reflection_v1"
