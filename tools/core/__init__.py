"""Truthgate core-контракты.

Единый канонический слой типов и enum'ов, на который опираются все остальные
модули (orchestrator, tools/validators, phase1). Не содержит логики — только
формы данных и правила валидации входа.

Ключевой принцип «ИИ находит — детерминированный код решает» задан здесь
через enum `VulnerabilityClass`: любой валидатор регистрируется по канону,
никаких строковых алиасов и синонимов.
"""

from __future__ import annotations

from tools.core.vulnerability_class import VulnerabilityClass

__all__ = ["VulnerabilityClass"]
