"""Candidate — гипотеза от LLM-мозга или tool-воркера.

НЕ находка. Пока не пройден валидатор — только запрос на проверку.
Иммутабельный pydantic-контракт: любой воркер возвращает `Iterable[Candidate]`,
pipeline дальше сам решает, что валидировать.
"""

from __future__ import annotations

import secrets
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Candidate(BaseModel):
    """Иммутабельный кандидат: (target, path, method, param, payload) + meta."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    bug_class: str
    target: str
    path: str = "/"
    method: str = "GET"
    param: str | None = None
    payload: str | None = None
    body: Any = None
    headers: dict[str, str] = Field(default_factory=dict)
    meta: dict[str, Any] = Field(default_factory=dict)

    @staticmethod
    def new_id(prefix: str = "cand") -> str:
        """Короткий уникальный id для кандидата/находки."""
        return f"{prefix}-{secrets.token_hex(6)}"

    def as_finding_dict(self) -> dict[str, Any]:
        """Плоский dict для передачи в `Validator.validate(finding, ctx)`."""
        d: dict[str, Any] = {
            "id": self.id,
            "bug_class": self.bug_class,
            "path": self.path,
            "method": self.method,
        }
        if self.param is not None:
            d["param"] = self.param
        if self.payload is not None:
            d["payload"] = self.payload
        if self.body is not None:
            d["body"] = self.body
        if self.headers:
            d["headers"] = self.headers
        d.update(self.meta)
        return d
