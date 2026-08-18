"""Детерминированные валидаторы Truthgate.

Каждый файл-валидатор регистрирует себя в `tools.validators.registry` через
декоратор `@register(VulnerabilityClass.<VAL>)`. Импорт этого пакета
автоматически подтягивает все реализованные детекторы.
"""

from __future__ import annotations

# Регистрация валидаторов при импорте пакета.
# Порядок соответствует M1-M2: сначала M1 (SQLi, SSRF, IDOR), потом M2.
from tools.validators import idor, sqli, ssrf, xss  # noqa: F401  — sideeffect: @register в модулях
