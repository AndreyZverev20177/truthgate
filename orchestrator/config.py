"""Конфиг оркестратора: env + опциональный yaml поверх.

Строгий Pydantic settings — упавший env лучше упавшего в runtime агента.
Дефолт `dry_run=True` — режим reachability + canary. Боевые примитивы включаются
явно per-target через `--allow-destructive`, никогда глобально.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator


class LLMConfig(BaseModel):
    provider: Literal["anthropic", "openai", "none"] = "none"
    model: str = "claude-sonnet-4-5"
    api_key: str = ""
    max_tokens: int = 4096
    temperature: float = 0.2
    budget_usd_per_run: float = 5.0


class RuntimeConfig(BaseModel):
    max_rps_per_host: float = 5.0
    max_concurrency: int = 8
    dry_run: bool = True
    log_level: str = "INFO"
    artifact_dir: Path = Path("./artifacts")
    user_agent: str = "Truthgate/0.1 (+authorized-bug-bounty; contact: security@example.com)"

    @field_validator("max_rps_per_host")
    @classmethod
    def _sane_rps(cls, v: float) -> float:
        if v <= 0 or v > 100:
            raise ValueError("max_rps_per_host must be in (0, 100]")
        return v


class OOBConfig(BaseModel):
    url: str = ""
    token: str = ""


class PlatformsConfig(BaseModel):
    h1_user: str = ""
    h1_token: str = ""
    bugcrowd_token: str = ""
    intigriti_token: str = ""


class Config(BaseModel):
    llm: LLMConfig = Field(default_factory=LLMConfig)
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    oob: OOBConfig = Field(default_factory=OOBConfig)
    platforms: PlatformsConfig = Field(default_factory=PlatformsConfig)

    @classmethod
    def load(cls, yaml_path: Path | None = None) -> Config:
        data: dict = {}
        if yaml_path and yaml_path.exists():
            data = yaml.safe_load(yaml_path.read_text()) or {}
        provider = os.getenv("TRUTHGATE_LLM_PROVIDER", data.get("llm", {}).get("provider", "none"))
        return cls(
            llm=LLMConfig(
                provider=provider,  # type: ignore[arg-type]
                model=os.getenv("TRUTHGATE_LLM_MODEL", data.get("llm", {}).get("model", "claude-sonnet-4-5")),
                api_key=(
                    os.getenv("ANTHROPIC_API_KEY", "")
                    if provider == "anthropic"
                    else os.getenv("OPENAI_API_KEY", "")
                ),
                budget_usd_per_run=float(
                    os.getenv("TRUTHGATE_LLM_BUDGET_USD", data.get("llm", {}).get("budget_usd_per_run", 5.0))
                ),
            ),
            runtime=RuntimeConfig(
                max_rps_per_host=float(os.getenv("TRUTHGATE_MAX_RPS_PER_HOST", "5")),
                max_concurrency=int(os.getenv("TRUTHGATE_MAX_CONCURRENCY", "8")),
                dry_run=os.getenv("TRUTHGATE_DRY_RUN", "true").lower() != "false",
                log_level=os.getenv("TRUTHGATE_LOG_LEVEL", "INFO"),
                artifact_dir=Path(os.getenv("TRUTHGATE_ARTIFACT_DIR", "./artifacts")),
            ),
            oob=OOBConfig(
                url=os.getenv("TRUTHGATE_OOB_URL", ""),
                token=os.getenv("TRUTHGATE_OOB_TOKEN", ""),
            ),
            platforms=PlatformsConfig(
                h1_user=os.getenv("H1_API_USER", ""),
                h1_token=os.getenv("H1_API_TOKEN", ""),
                bugcrowd_token=os.getenv("BUGCROWD_API_TOKEN", ""),
                intigriti_token=os.getenv("INTIGRITI_API_TOKEN", ""),
            ),
        )
