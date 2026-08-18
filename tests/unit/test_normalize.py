"""Unit-тесты normalize_vuln_class — единственного слоя алиасов."""

from __future__ import annotations

import pytest

from tools.core.vulnerability_class import VulnerabilityClass
from tools.validators.normalize import aliases_for, normalize_vuln_class

pytestmark = pytest.mark.unit


class TestDirectEnumValue:
    def test_lower_snake_case_direct_hit(self) -> None:
        assert normalize_vuln_class("sqli") is VulnerabilityClass.SQLI
        assert normalize_vuln_class("ssrf") is VulnerabilityClass.SSRF
        assert normalize_vuln_class("mass_assign") is VulnerabilityClass.MASS_ASSIGN

    def test_capitalization_normalized(self) -> None:
        assert normalize_vuln_class("SQLI") is VulnerabilityClass.SQLI
        assert normalize_vuln_class("Ssrf") is VulnerabilityClass.SSRF

    def test_hyphens_become_underscores(self) -> None:
        assert normalize_vuln_class("mass-assign") is VulnerabilityClass.MASS_ASSIGN
        assert normalize_vuln_class("open-redirect") is VulnerabilityClass.OPEN_REDIRECT


class TestAliases:
    def test_bola_maps_to_idor(self) -> None:
        assert normalize_vuln_class("BOLA") is VulnerabilityClass.IDOR
        assert normalize_vuln_class("bola") is VulnerabilityClass.IDOR
        assert normalize_vuln_class("broken_object_level_authz") is VulnerabilityClass.IDOR
        assert normalize_vuln_class("broken_object_level_authorization") is VulnerabilityClass.IDOR

    def test_path_traversal_maps_to_lfi(self) -> None:
        assert normalize_vuln_class("path-traversal") is VulnerabilityClass.LFI
        assert normalize_vuln_class("directory_traversal") is VulnerabilityClass.LFI
        assert normalize_vuln_class("local_file_inclusion") is VulnerabilityClass.LFI

    def test_cmdi_short_and_long_forms(self) -> None:
        assert normalize_vuln_class("cmd_injection") is VulnerabilityClass.CMDI
        assert normalize_vuln_class("command_injection") is VulnerabilityClass.CMDI
        assert normalize_vuln_class("os_command_injection") is VulnerabilityClass.CMDI

    def test_ssti_long_form(self) -> None:
        assert normalize_vuln_class("server_side_template_injection") is VulnerabilityClass.SSTI
        assert normalize_vuln_class("template_injection") is VulnerabilityClass.SSTI

    def test_prompt_inject_llm_variants(self) -> None:
        for raw in ("rag_inject", "rag_injection", "mem_poison", "memory_poisoning"):
            assert normalize_vuln_class(raw) is VulnerabilityClass.PROMPT_INJECT


class TestUnknown:
    def test_returns_none_on_unknown(self) -> None:
        assert normalize_vuln_class("definitely-unknown-class") is None
        assert normalize_vuln_class("csrf") is None

    def test_empty_string(self) -> None:
        assert normalize_vuln_class("") is None

    def test_whitespace_only(self) -> None:
        assert normalize_vuln_class("   ") is None


class TestAliasesFor:
    def test_returns_sorted_aliases(self) -> None:
        a = aliases_for(VulnerabilityClass.IDOR)
        assert "bola" in a
        assert any("broken_object_level" in x for x in a)
        assert a == sorted(a)

    def test_no_alias_for_direct_enum(self) -> None:
        a = aliases_for(VulnerabilityClass.BFLA)
        assert any("broken_function_level" in x for x in a)
