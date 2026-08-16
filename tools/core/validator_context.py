"""ValidatorContext — изолированный срез окружения для одного прогона валидатора.

Mutable (валидатор может допилить `extra`), но крупные зависимости
(`auth`, `oob`) передаются готовыми объектами извне.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tools.core.providers import AuthProvider, OOBProvider


class ValidatorContext(BaseModel):
    """Всё, что валидатору нужно знать о цели и окружении."""

    # arbitrary_types_allowed — для Protocol-полей auth/oob (это runtime_checkable,
    # но pydantic всё равно требует явного разрешения нестандартных типов).
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    target: str
    program_headers: dict[str, str] = Field(default_factory=dict)
    tls_verify: bool = False
    replays: int = 3
    poll_wait_s: float = 12.0
    dry_run: bool = True
    auth: AuthProvider | None = None
    oob: OOBProvider | None = None
    extra: dict[str, Any] = Field(default_factory=dict)
