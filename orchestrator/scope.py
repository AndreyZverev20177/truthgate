"""Scope-checker: hard-gate на любой out-of-scope запрос.

Юридический предохранитель. Любой сетевой примитив в pipeline обязан вызвать
`assert_in_scope(url, program)` ДО обращения к сети. Без матча в scope-списке —
`ScopeViolation`, запрос не отправляется.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


class ScopeViolation(RuntimeError):
    """Поднимается, когда pipeline пытается тронуть цель вне scope."""


@dataclass(frozen=True, slots=True)
class ScopeRule:
    kind: str
    pattern: str
    include: bool = True


@dataclass(slots=True)
class Scope:
    program: str
    rules: list[ScopeRule] = field(default_factory=list)

    def add_domain(self, host: str, *, include: bool = True) -> None:
        self.rules.append(ScopeRule("domain", host.lower(), include))

    def add_wildcard(self, wildcard: str, *, include: bool = True) -> None:
        self.rules.append(ScopeRule("wildcard", wildcard.lower(), include))

    def add_cidr(self, cidr: str, *, include: bool = True) -> None:
        ipaddress.ip_network(cidr, strict=False)
        self.rules.append(ScopeRule("cidr", cidr, include))

    def check(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False
        matched_include = False
        for r in self.rules:
            if self._match(r, host):
                if not r.include:
                    return False
                matched_include = True
        return matched_include

    @staticmethod
    def _match(rule: ScopeRule, host: str) -> bool:
        if rule.kind == "domain":
            return host == rule.pattern
        if rule.kind == "wildcard":
            base = rule.pattern.lstrip("*.")
            return host.endswith("." + base)
        if rule.kind == "cidr":
            try:
                return ipaddress.ip_address(host) in ipaddress.ip_network(rule.pattern, strict=False)
            except ValueError:
                return False
        if rule.kind == "regex":
            return re.search(rule.pattern, host) is not None
        return False

    def assert_in_scope(self, url: str) -> None:
        if not self.check(url):
            raise ScopeViolation(f"URL out of scope for {self.program!r}: {url}")


def load_from_dict(data: dict) -> Scope:
    s = Scope(program=str(data.get("program", "")))
    for item in data.get("include", []):
        _add(s, str(item), include=True)
    for item in data.get("exclude", []):
        _add(s, str(item), include=False)
    return s


def _add(s: Scope, pattern: str, *, include: bool) -> None:
    if "/" in pattern and pattern.rsplit("/", 1)[-1].isdigit():
        s.add_cidr(pattern, include=include)
    elif pattern.startswith("*."):
        s.add_wildcard(pattern, include=include)
    else:
        s.add_domain(pattern, include=include)
