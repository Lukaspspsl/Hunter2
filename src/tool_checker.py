"""Binary availability check for Hunter 2.

Driven from tools.yaml — registry is single source of truth.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import Dict

from .config_loader import HunterConfig
from .core.logger import get_logger

log = get_logger("tool_checker")


@dataclass
class ToolStatus:
    name: str
    binary: str
    enabled: bool
    available: bool
    path: str | None
    min_level: str


def check_tools(cfg: HunterConfig) -> Dict[str, ToolStatus]:
    """Probe every tool's binary on PATH. Returns map name -> ToolStatus."""
    results: Dict[str, ToolStatus] = {}
    for name, t in cfg.tools.items():
        path = shutil.which(t.binary) if t.enabled else None
        status = ToolStatus(
            name=name,
            binary=t.binary,
            enabled=t.enabled,
            available=path is not None,
            path=path,
            min_level=t.min_level,
        )
        results[name] = status
        if t.enabled and not path:
            log.warning(f"tool '{name}' enabled but binary '{t.binary}' not on PATH")
        elif t.enabled:
            log.debug(f"tool '{name}' OK ({path})")
    return results


def report(results: Dict[str, ToolStatus]) -> str:
    lines = ["Tool availability:"]
    for name, st in sorted(results.items()):
        mark = "OK   " if st.available else ("OFF  " if not st.enabled else "MISS ")
        lines.append(f"  [{mark}] {name:20s} ({st.binary}) min_level={st.min_level}")
    return "\n".join(lines)
