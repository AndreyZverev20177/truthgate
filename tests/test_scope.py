from __future__ import annotations

import pytest

from orchestrator.scope import Scope, ScopeViolation, load_from_dict


def test_domain_match() -> None:
    s = Scope("acme")
    s.add_domain("api.acme.com")
    assert s.check("https://api.acme.com/x")
    assert not s.check("https://other.com/")


def test_wildcard_match() -> None:
    s = load_from_dict({"program": "acme", "include": ["*.acme.com"]})
    assert s.check("https://a.acme.com/")
    assert s.check("https://b.a.acme.com/")
    assert not s.check("https://acme.com/")


def test_out_of_scope_override() -> None:
    s = load_from_dict({
        "program": "acme",
        "include": ["*.acme.com"],
        "exclude": ["status.acme.com"],
    })
    assert not s.check("https://status.acme.com/")
    assert s.check("https://api.acme.com/")


def test_assert_raises() -> None:
    s = Scope("acme")
    s.add_domain("api.acme.com")
    with pytest.raises(ScopeViolation):
        s.assert_in_scope("https://bad.com/")


def test_cidr_match() -> None:
    s = load_from_dict({"program": "acme", "include": ["203.0.113.0/24"]})
    assert s.check("https://203.0.113.5/")
    assert not s.check("https://203.0.114.5/")
