"""normalize_vuln_class — единственное место, где живут строковые алиасы.

Внешние источники (LLM-мозг, scanner-воркеры, CLI) присылают `bug_class`
строкой, часто с разной капитализацией и слэнгом (`BOLA`, `path-traversal`,
`server_side_template_injection`). Всё это нормализуется здесь — на входной
границе pipeline'а. Дальше по коду ходит только `VulnerabilityClass`.

Правила таблицы алиасов:
- ключи — lower_snake_case (после `.lower().replace("-", "_")`);
- значения — канонический enum, не строка;
- если алиас пересекается со значением enum'а (`sqli` → `VulnerabilityClass.SQLI`),
  явно указывать его не нужно — `VulnerabilityClass(key)` найдёт его сам;
- новые алиасы добавляются сюда — и НИКОГДА в `tools.validators.registry`.
"""

from __future__ import annotations

from tools.core.vulnerability_class import VulnerabilityClass

# Только те строки, которые НЕ совпадают буквально с enum.value.
# Прямое совпадение (`"sqli"` → `VulnerabilityClass.SQLI`) обрабатывается через
# `VulnerabilityClass(key)` без записи в таблицу — экономит место и не даёт
# рассинхрону между алиасом и каноническим значением.
_ALIASES: dict[str, VulnerabilityClass] = {
    # IDOR / BOLA — OWASP API-1 «Broken Object Level Authorization»
    "bola": VulnerabilityClass.IDOR,
    "broken_object_level_authz": VulnerabilityClass.IDOR,
    "broken_object_level_authorization": VulnerabilityClass.IDOR,
    # LFI vs Path Traversal — исторически синонимы для web
    "path_traversal": VulnerabilityClass.LFI,
    "directory_traversal": VulnerabilityClass.LFI,
    "local_file_inclusion": VulnerabilityClass.LFI,
    # Command Injection — короткая и полная форма
    "command_injection": VulnerabilityClass.CMDI,
    "cmd_injection": VulnerabilityClass.CMDI,
    "os_command_injection": VulnerabilityClass.CMDI,
    # SSTI — краткая и полная
    "template_injection": VulnerabilityClass.SSTI,
    "server_side_template_injection": VulnerabilityClass.SSTI,
    # SSRF — полная форма
    "server_side_request_forgery": VulnerabilityClass.SSRF,
    # XSS — полная
    "cross_site_scripting": VulnerabilityClass.XSS,
    # XXE — полная
    "xml_external_entity": VulnerabilityClass.XXE,
    # NoSQLi — краткая и полная
    "nosql_injection": VulnerabilityClass.NOSQLI,
    # Prompt Injection — вариации от LLM-агентов
    "prompt_injection": VulnerabilityClass.PROMPT_INJECT,
    "rag_inject": VulnerabilityClass.PROMPT_INJECT,
    "rag_injection": VulnerabilityClass.PROMPT_INJECT,
    "mem_poison": VulnerabilityClass.PROMPT_INJECT,
    "memory_poisoning": VulnerabilityClass.PROMPT_INJECT,
    # Excessive Agency — LLM-агенты
    "excessive_agent_capability": VulnerabilityClass.EXCESSIVE_AGENCY,
    "agentic_overreach": VulnerabilityClass.EXCESSIVE_AGENCY,
    # BFLA — Broken Function Level Authorization (OWASP API-5)
    "broken_function_level_authz": VulnerabilityClass.BFLA,
    "broken_function_level_authorization": VulnerabilityClass.BFLA,
    # Mass Assignment
    "mass_assignment": VulnerabilityClass.MASS_ASSIGN,
    "mass-assignment": VulnerabilityClass.MASS_ASSIGN,  # ключи lowercased+underscored, но на всякий
    "over_binding": VulnerabilityClass.MASS_ASSIGN,
    # Open Redirect
    "unvalidated_redirect": VulnerabilityClass.OPEN_REDIRECT,
    "url_redirection": VulnerabilityClass.OPEN_REDIRECT,
    # SQLi — редкие полные формы
    "sql_injection": VulnerabilityClass.SQLI,
    # JWT — полная
    "jwt_vulnerabilities": VulnerabilityClass.JWT,
    "jwt_vulnerability": VulnerabilityClass.JWT,
}


def _key(raw: str) -> str:
    """Стабильная нормализация строки в ключ таблицы."""
    return raw.strip().lower().replace("-", "_")


def normalize_vuln_class(raw: str) -> VulnerabilityClass | None:
    """Нормализовать строку в канонический `VulnerabilityClass` или None.

    Порядок: (1) прямое совпадение с enum.value; (2) таблица `_ALIASES`.
    None возвращается для неизвестных значений — вызывающий код (pipeline)
    сам решает: skip кандидата с warning или зарегистрировать как «unknown».
    """
    key = _key(raw)
    # (1) прямое совпадение — самый частый путь (LLM и tools пишут канон).
    try:
        return VulnerabilityClass(key)
    except ValueError:
        pass
    # (2) алиас.
    return _ALIASES.get(key)


def aliases_for(vc: VulnerabilityClass) -> list[str]:
    """Список известных строковых алиасов для данного класса (для CLI/docs)."""
    return sorted(k for k, v in _ALIASES.items() if v is vc)
