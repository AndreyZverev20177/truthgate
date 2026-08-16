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
   boolean-based стратегии. `"true"` должен «сработать» на уязвимой цели
   (SQL инъекция `' OR 1=1-- `, SSRF на OOB-URL). `"false"` — контроль
   (`' OR 1=2-- `, недоступный внутренний адрес). Пара — фундамент
   compare_responses.

3. **`compare_responses(resp_true, resp_false) -> bool`** — детерминированное
   правило: есть ли отличие, характерное для этого класса? Каждый класс
   определяет свою метрику (статус, длина, содержимое маркера, тайминг,
   OOB-hit). Возвращает `True` только если разница — сигнал уязвимости.

4. **`vulnerability_class -> VulnerabilityClass`** — регистрация в реестре
   идёт по каноническому enum, а не по строке. Никаких алиасов на этой
   границе — нормализация строк живёт отдельным слоем в `normalize_vuln_class`
   на входе (cli, кандидаты от LLM).

5. **`name -> str`** — стабильный slug валидатора (пример: `"sqli_boolean_v1"`).
   Пишется в `runs.validator` sqlite-метрик и логи.

`ValidationEvidence` — pydantic-модель (frozen) для машинных артефактов
одного прогона: SHA256 тел ответов, статус-коды, длины, тайминги, OOB-hit.
Судья (`proof_gate_v2`) читает поля напрямую — никакого парсинга строк.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from orchestrator.types import Candidate, ValidatorContext, Verdict
from tools.core.vulnerability_class import VulnerabilityClass

PayloadVariant = Literal["true", "false"]


class ValidationEvidence(BaseModel):
    """Машинные артефакты одного прогона boolean-based валидатора.

    Формат стабилен между валидаторами; специфичные поля идут в `extra`
    (SSRF складывает туда `oob_hits`, LFI — маркер, XSS — DOM-снимок).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # Пара payload'ов, которую валидатор реально отправил.
    payload_true: str
    payload_false: str

    # HTTP-артефакты (детерминированные): статус, длина, sha256(body_normalized).
    status_true: int = Field(ge=0)
    status_false: int = Field(ge=0)
    len_true: int = Field(ge=0)
    len_false: int = Field(ge=0)
    sha256_true: str = Field(min_length=64, max_length=64)
    sha256_false: str = Field(min_length=64, max_length=64)

    # Тайминг в миллисекундах — для timing-based и мониторинга.
    timing_ms_true: float = Field(ge=0.0)
    timing_ms_false: float = Field(ge=0.0)

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
        """Есть ли разница между ответами, характерная для этого класса?

        Возвращает True — сигнал уязвимости; False — цель не подтверждает.
        Метрика (статус, длина, sha256, тайминг, маркер) — на усмотрение
        наследника, но правило должно быть детерминированным.
        """

    @abstractmethod
    def validate(self, candidate: Candidate, ctx: ValidatorContext) -> Verdict:
        """Прогон валидатора. Sync — pipeline вызывает под ThreadPoolExecutor.

        Наследник обязан:
          1. Собрать payload'ы через `generate_payload("true"/"false")`.
          2. Выполнить два запроса (или больше — если replay/OOB-poll).
          3. Вычислить `is_real` через `compare_responses`.
          4. Собрать `ValidationEvidence` (sha256, статусы, длины, тайминги).
          5. Обернуть исключения → `Verdict(is_real=False, confidence=0.0,
             reason=<exc>)`. Никогда не бросать наружу.
          6. Заполнить `Verdict.bug_class = self.vulnerability_class.value`,
             `Verdict.validator = self.name`.
          7. Установить `Verdict.artifacts = evidence.to_dict()`.
        """

    def as_failure(self, exc: BaseException) -> Verdict:
        """Хэлпер для безопасной обёртки исключения.

        Использовать в `except:` веткё `validate()`. Приводит `Exception` к
        безопасному `Verdict(is_real=False, confidence=0.0)` с сохранением
        типа и сообщения — для последующего анализа причин FN.
        """
        return Verdict(
            is_real=False,
            evidence="",
            confidence=0.0,
            bug_class=self.vulnerability_class.value,
            validator=self.name,
            reason=f"{type(exc).__name__}: {exc}",
        )
