"""Worker-контракт.

Единый интерфейс для всех источников кандидатов: LLM-мозг, tool-обёртки (nuclei,
sqlmap), ручной ввод. Любой воркер возвращает `Iterable[Candidate]` — pipeline
дальше сам решает, что валидировать.

Инвариант: воркер НИКОГДА не ставит is_real. Только валидатор.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from orchestrator.types import Candidate, ValidatorContext


class Worker(ABC):
    name: str = "worker"

    @abstractmethod
    def propose(self, ctx: ValidatorContext) -> Iterable[Candidate]:
        """Вернуть итератор кандидатов на валидацию."""


class StaticWorker(Worker):
    """Тривиальный воркер: возвращает заранее подготовленный список."""

    name = "static"

    def __init__(self, candidates: list[Candidate]) -> None:
        self._candidates = list(candidates)

    def propose(self, ctx: ValidatorContext) -> Iterable[Candidate]:
        _ = ctx
        return iter(self._candidates)
