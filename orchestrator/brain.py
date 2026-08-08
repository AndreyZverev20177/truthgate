"""LLM-мозг агента (M5 — здесь только seam).

Мозг предлагает гипотезы (Candidate) и решает, какие tool-воркеры звать. НЕ
принимает финальных решений о находке — это делает валидатор + судья.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from orchestrator.types import Candidate, ValidatorContext
from orchestrator.worker import Worker


class Brain(ABC):
    @abstractmethod
    def propose(self, ctx: ValidatorContext, recon: dict) -> Iterable[Candidate]:
        """Гипотезы уязвимостей на основании recon-данных цели."""


class StubBrain(Brain):
    """Ничего не предлагает. Заглушка для M0-каркаса."""

    def propose(self, ctx: ValidatorContext, recon: dict) -> Iterable[Candidate]:
        _ = ctx, recon
        return iter([])


class BrainWorker(Worker):
    """Мостик: превращает `Brain` в `Worker`."""

    name = "brain"

    def __init__(self, brain: Brain, recon: dict | None = None) -> None:
        self.brain = brain
        self.recon = recon or {}

    def propose(self, ctx: ValidatorContext) -> Iterable[Candidate]:
        return self.brain.propose(ctx, self.recon)
