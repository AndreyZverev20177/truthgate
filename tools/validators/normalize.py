"""normalize_vuln_class — единственное место, где живут строковые алиасы.

Внешние источники (LLM-мозг, scanner-воркеры, CLI) присылают `bug_class`
строкой, часто с разной капитализацией и слэнгом. Всё это нормализуется здесь — на
входной границе pipeline'а. Дальше по коду ходит только `VulnerabilityClass`.
"""

from __future__ import annotations

from tools.core.vulnerability_class import VulnerabilityClass

_ALIASES: dict[str, VulnerabilityClass] = {
    "bola": VulnerabilityClass.IDOR,
    "broken_object_level_authz": VulnerabilityClass.IDOR,
    "broken_object_level_authorization": VulnerabilityClass.IDOR,
    "path_traversal": VulnerabilityClass.LFI,
    "directory_traversal": VulnerabilityClass.LFI,
    "local_file_inclusion": VulnerabilityClass.LFI,
    "command_injection": VulnerabilityClass.CMDI,
    "cmd_injection": VulnerabilityClass.CMDI,
    "os_command_injection": VulnerabilityClass.CMDI,
    "template_injection": VulnerabilityClass.SSTI,
    "server_side_template_injection": VulnerabilityClass.SSTI,
    "server_side_request_forgery": VulnerabilityClass.SSRF,
    "cross_site_scripting": VulnerabilityClass.XSS,
    "xml_external_entity": VulnerabilityClass.XXE,
    "nosql_injection": VulnerabilityClass.NOSQLI,
    "prompt_injection": VulnerabilityClass.PROMPT_INJECT,
    "rag_inject": VulnerabilityClass.PROMPT_INJECT,
    "rag_injection": VulnerabilityClass.PROMPT_INJECT,
    "mem_poison": VulnerabilityClass.PROMPT_INJECT,
    "memory_poisoning": VulnerabilityClass.PROMPT_INJECT,
    "excessive_agent_capability": VulnerabilityClass.EXCESSIVE_AGENCY,
    "agentic_overreach": VulnerabilityClass.EXCESSIVE_AGENCY,
    "broken_function_level_authz": VulnerabilityClass.BFLA,
    "broken_function_level_authorization": VulnerabilityClass.BFLA,
    "mass_assignment": VulnerabilityClass.MASS_ASSIGN,
    "mass-assignment": VulnerabilityClass.MASS_ASSIGN,
    "over_binding": VulnerabilityClass.MASS_ASSIGN,
    "unvalidated_redirect": VulnerabilityClass.OPEN_REDIRECT,
    "url_redirection": VulnerabilityClass.OPEN_REDIRECT,
    "sql_injection": VulnerabilityClass.SQLI,
    "jwt_vulnerabilities": VulnerabilityClass.JWT,
    "jwt_vulnerability": VulnerabilityClass.JWT,
}


def _key(raw: str) -> str:
    return raw.strip().lower().replace("-", "_")


def normalize_vuln_class(raw: str) -> VulnerabilityClass | None:
    """Нормализовать строку в канонический `VulnerabilityClass` или None."""
    key = _key(raw)
    try:
        return VulnerabilityClass(key)
    except ValueError:
        pass
    return _ALIASES.get(key)


def aliases_for(vc: VulnerabilityClass) -> list[str]:
    """Список известных строковых алиасов для данного класса (для CLI/docs)."""
    return sorted(k for k, v in _ALIASES.items() if v is vc)
