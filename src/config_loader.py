"""Hunter 2 config loader.

Three files:
    configs/programs.yaml — bug-bounty programs (scope, rules, schedule)
    configs/tools.yaml    — tool registry (single source of truth)
    configs/llm.yaml      — LLM endpoint + model
Environment variables substituted with ${VAR} pattern.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, field_validator

from .core.logger import get_logger

log = get_logger("config_loader")

AGGR_LEVELS = ("passive", "active", "aggressive")


# ---------------- programs.yaml ----------------


class NotifyConfig(BaseModel):
    on_new_subdomain: bool = True
    on_critical_vuln: bool = True
    on_scope_violation_attempt: bool = True


class ScheduleConfig(BaseModel):
    cron: Optional[str] = None
    enabled: bool = False


class ProgramConfig(BaseModel):
    platform: Optional[str] = None
    aggressiveness: str = "passive"
    in_scope: List[str] = Field(default_factory=list)
    out_of_scope: List[str] = Field(default_factory=list)
    rules: List[str] = Field(default_factory=list)
    notify: NotifyConfig = Field(default_factory=NotifyConfig)
    schedule: ScheduleConfig = Field(default_factory=ScheduleConfig)

    @field_validator("aggressiveness")
    @classmethod
    def _check_aggr(cls, v: str) -> str:
        if v not in AGGR_LEVELS:
            raise ValueError(f"aggressiveness must be one of {AGGR_LEVELS}, got {v!r}")
        return v


class ProgramsFile(BaseModel):
    programs: Dict[str, ProgramConfig] = Field(default_factory=dict)


# ---------------- tools.yaml ----------------


class ToolDef(BaseModel):
    binary: str
    description: str = ""
    enabled: bool = True
    min_level: str = "passive"
    rate_multiplier: float = 1.0
    timeout: int = 300
    args: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("min_level")
    @classmethod
    def _check_level(cls, v: str) -> str:
        if v not in AGGR_LEVELS:
            raise ValueError(f"min_level must be one of {AGGR_LEVELS}, got {v!r}")
        return v


class ToolsFile(BaseModel):
    tools: Dict[str, ToolDef] = Field(default_factory=dict)
    rate_multipliers: Dict[str, float] = Field(
        default_factory=lambda: {"passive": 1.0, "active": 0.6, "aggressive": 1.5}
    )


# ---------------- llm.yaml ----------------


class LLMAvailabilityCheck(BaseModel):
    enabled: bool = True
    on_unavailable: str = "warn_and_continue_without_llm"


class LLMFallback(BaseModel):
    enabled: bool = False


class LLMConfig(BaseModel):
    provider: str = "local"
    base_url: str = "http://localhost:8090/v1"
    model: str = "gemma4:latest"
    api_key: str = "not-needed"
    context_length: int = 65536
    temperature: float = 0.1
    timeout: int = 120
    session_ttl_days: int = 30
    fallback: LLMFallback = Field(default_factory=LLMFallback)
    availability_check: LLMAvailabilityCheck = Field(default_factory=LLMAvailabilityCheck)


class LLMFile(BaseModel):
    llm: LLMConfig = Field(default_factory=LLMConfig)


# ---------------- combined ----------------


class HunterConfig(BaseModel):
    programs: Dict[str, ProgramConfig]
    tools: Dict[str, ToolDef]
    rate_multipliers: Dict[str, float]
    llm: LLMConfig

    def tools_at_or_below(self, level: str) -> Dict[str, ToolDef]:
        """Tools whose min_level <= given level."""
        idx = AGGR_LEVELS.index(level)
        allowed = set(AGGR_LEVELS[: idx + 1])
        return {
            name: t
            for name, t in self.tools.items()
            if t.enabled and t.min_level in allowed
        }


# ---------------- helpers ----------------


_ENV_RE = re.compile(r"\$\{([^}]+)\}")


def substitute_env_vars(value: Any) -> Any:
    if isinstance(value, str):
        def _sub(m):
            return os.environ.get(m.group(1), "")
        return _ENV_RE.sub(_sub, value)
    if isinstance(value, dict):
        return {k: substitute_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute_env_vars(v) for v in value]
    return value


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path) as f:
        return substitute_env_vars(yaml.safe_load(f) or {})


def load_config(config_dir: str | os.PathLike = "./configs") -> HunterConfig:
    """Load and validate all three config files."""
    cfg_dir = Path(config_dir)
    programs_raw = _load_yaml(cfg_dir / "programs.yaml")
    tools_raw = _load_yaml(cfg_dir / "tools.yaml")
    llm_raw = _load_yaml(cfg_dir / "llm.yaml")

    pf = ProgramsFile(**programs_raw)
    tf = ToolsFile(**tools_raw)
    lf = LLMFile(**llm_raw)

    cfg = HunterConfig(
        programs=pf.programs,
        tools=tf.tools,
        rate_multipliers=tf.rate_multipliers,
        llm=lf.llm,
    )
    log.info(
        f"Loaded config: {len(cfg.programs)} programs, {len(cfg.tools)} tools, "
        f"llm={cfg.llm.model}"
    )
    return cfg


def get_program(cfg: HunterConfig, name: str) -> ProgramConfig:
    if name not in cfg.programs:
        raise KeyError(f"Program '{name}' not found. Available: {list(cfg.programs)}")
    return cfg.programs[name]
