"""BaseValidator — контракт детерминированного валидатора.

Ядро принципа Truthgate «ИИ находит — детерминированный код решает»:
любой валидатор наследует этот класс и реализует минимум четыре
абстрактных метода. Валидатор возвращает `Verdict` (dataclass из
`orchestrator.types`) с машинными артефактами в `Verdict.artifacts`
(структурированный `ValidationEvidence`), а не с прозой в `evidence`.

Инварианты, обязательные для наследников:

1. **Sync `.validate(candidate, ctx) -> Verdict`**. Оркестратор вызывает через
   `ThreadPoolExecutor + future.result(timeout=10)`, поэтому валидатору
   разрешён обычный HTTP (`httpx.Client`) и файловые операции. Ни в коем случае
   не бросать исключений наружу — оборачивать в `Verdict(is_real=False,
   confidence=0.0, reason=<exc>)`. Pipeline подстраховывает, но это правило
   именно на стороне валидатора (defence in depth).

2. **`generate_payload("true"/"false") -> str`** — пара payload'ов для
   boolean-based стратегии.

3. **`compare_responses(resp_true, resp_false) -> bool`** — детерминированное
   правило: есть ли отличие, характерное для этого класса?

4. **`vulnerability_class -> VulnerabilityClass`** — регистрация в реестре
   идёт по каноническому enum.

5. **`name -> str`** — стабильный slug валидатора.

`ValidationEvidence` — pydantic-модель (frozen). Расширена под ТЗ M1 п.4-6:
добавлены benign-control поля (payload_benign, status_benign, len_benign,
sha256_benign, timing_ms_benign) для SQLi/XSS anti-FP и differential-flags
(diff_reason, normalized_diff, false_like_benign, true_differs_from_benign)
как детерминированные метки решения. Все новые поля опциональны — старые
валидаторы и тесты продолжают работать.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from orchestrator.scope import Scope, ScopeViolation
from orchestrator.types import Candidate, ValidatorContext, Verdict
from tools.core.vulnerability_class import VulnerabilityClass

PayloadVariant = Literal["true", "false"]


class ValidationEvidence(BaseModel):
    """Машинные артефакты одного прогона валидатора.

    Пара TRUE/FALSE обязательна (boolean-differential — базовый паттерн).
    Опциональный benign-control (payload_benign/status_benign/len_benign/
    sha256_benign/timing_ms_benign) — для SQLi/XSS anti-FP: помогает отличить
    настоящий injection от tar-pit («все запросы отклоняются» → FALSE и benign
    совпадают, TRUE не отличается → is_real=False).

    Differential-flags (diff_reason, normalized_diff, false_like_benign,
    true_differs_from_benign) — детерминированные метки решения. Судья
    (`proof_gate_v2`) читает их напрямую.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # Пара TRUE/FALSE — обязательна.
    payload_true: str
    payload_false: str

    # HTTP-артефакты (детерминированные): статус, длина, sha256(body_normalized).
    status_true: int = Field(ge=0)
    status_false: int = Field(ge=0)
    len_true: int = Field(ge=0)
    len_false: int = Field(ge=0)
    sha256_true: str = Field(min_length=64, max_length=64)
    sha256_false: str = Field(min_length=64, max_length=64)

    # Тайминг в миллисекундах.
    timing_ms_true: float = Field(ge=0.0)
    timing_ms_false: float = Field(ge=0.0)

    # Benign-control (опциональный третий запрос для anti-FP).
    payload_benign: str | None = None
    status_benign: int | None = Field(default=None, ge=0)
    len_benign: int | None = Field(default=None, ge=0)
    sha256_benign: str | None = Field(default=None, min_length=64, max_length=64)
    timing_ms_benign: float | None = Field(default=None, ge=0.0)

    # Differential-flags (детерминированные метки решения).
    diff_reason: str | None = None
    normalized_diff: bool | None = None
    false_like_benign: bool | None = None
    true_differs_from_benign: bool | None = None

    # OOB (для ssrf/xxe/cmdi/blind-классов).
    oob_hit: bool = False
    oob_token: str | None = None

    # Класс-специфичные поля (DOM snapshot, LFI marker, JWT claims и т.п.).
    extra: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Стабильная сериализация для `Verdict.artifacts`."""
        return self.model_dump(mode="json")

    @staticmethod
    def sha256_of(data: bytes | str) -> str:
        """Хэш тела ответа (используется наследниками). Без соли."""
        raw = data.encode("utf-8", errors="replace") if isinstance(data, str) else data
        return hashlib.sha256(raw).hexdigest()


def check_scope(ctx: ValidatorContext, url: str) -> str | None:
    """Проверка scope перед сетевым действием (defence in depth).

    Валидатор вызывает эту функцию первой строкой в `validate()` — если scope
    задан через `ctx.extra["scope"]` (тип `Scope`) и URL не в нём, возвращает
    строку-reason. Если scope не задан — возвращает None (pipeline уже
    проверил на своём уровне).

    Возвращает:
        `None` — можно продолжать сетевые действия.
        `"out_of_scope"` — цель НЕ в scope, валидатор ДОЛЖЕН вернуть
        `Verdict(is_real=False, reason="out_of_scope")`.
    """
    scope = None
    if ctx.extra:
        scope = ctx.extra.get("scope")
    if scope is None or not isinstance(scope, Scope):
        return None
    try:
        scope.assert_in_scope(url)
    except ScopeViolation:
        return "out_of_scope"
    return None


class BaseValidator(ABC):
    """Контракт детерминированного валидатора — сердце M1–M2.

    Наследник реализует минимальный набор:
    - `name` (property) — стабильный slug
    - `vulnerability_class` (property) — из канонического enum
    - `generate_payload(variant)` — пара payload'ов
    - `compare_responses(rt, rf)` — детерминированное правило детекции
    - `validate(candidate, ctx)` — вызывает 1-4 и собирает Verdict

    Никаких сетевых вызовов в этом файле — только контракт и хэлперы.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Стабильное имя валидатора (для логов и sqlite `runs.validator`)."""

    @property
    @abstractmethod
    def vulnerability_class(self) -> VulnerabilityClass:
        """Канонический класс уязвимости из `VulnerabilityClass` enum."""

    @abstractmethod
    def generate_payload(self, variant: PayloadVariant) -> str:
        """Пара payload'ов для boolean-based стратегии.

        `"true"` — payload, который должен сработать на уязвимой цели.
        `"false"` — payload-контроль, поведение цели не должно измениться.
        """

    @abstractmethod
    def compare_responses(self, resp_true: Any, resp_false: Any) -> bool:
        """Есть ли разница между ответами, характерная для этого класса?"""

    @abstractmethod
    def validate(self, candidate: Candidate, ctx: ValidatorContext) -> Verdict:
        """Прогон валидатора. Sync — pipeline вызывает под ThreadPoolExecutor."""

    def as_failure(self, exc: BaseException) -> Verdict:
        """Хэлпер для безопасной обёртки исключения."""
        return Verdict(
            is_real=False,
            evidence="",
            confidence=0.0,
            bug_class=self.vulnerability_class.value,
            validator=self.name,
            reason=f"{type(exc).__name__}: {exc}",
        )

    def _out_of_scope_verdict(self, target: str) -> Verdict:
        """Стандартный Verdict для случая out-of-scope цели."""
        return Verdict(
            is_real=False,
            evidence=f"target {target!r} is not in configured scope",
            confidence=0.0,
            bug_class=self.vulnerability_class.value,
            validator=self.name,
            reason="out_of_scope",
        )
