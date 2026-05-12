"""Technology fingerprinting via Wappalyzer CLI.

Replaces the Hunter 1.0 tech_detector which mixed httpx + wappalyzer in one
module. In Hunter 2, httpx already exposes tech hints (tech_detect=true) for
quick passes, and this module is the dedicated deep fingerprint.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from ..config_loader import ToolDef
from ..core.executor import CommandExecutor
from ..core.logger import get_logger
from ..core.scope_engine import ScopeEngine, ScopeViolationError

log = get_logger("tech_detector")


@dataclass
class TechFinding:
    name: str
    version: Optional[str] = None
    category: Optional[str] = None


@dataclass
class TechResult:
    target: str
    technologies: list[TechFinding] = field(default_factory=list)


class TechDetector:
    def __init__(
        self,
        tool: ToolDef,
        executor: CommandExecutor,
        scope: ScopeEngine,
        output_dir: Optional[Path] = None,
    ):
        self.tool = tool
        self.executor = executor
        self.scope = scope
        self.output_dir = output_dir or Path("./data/raw_results")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def detect(self, targets: Iterable[str]) -> list[TechResult]:
        results: list[TechResult] = []
        for t in targets:
            try:
                self.scope.assert_in_scope(t)
            except ScopeViolationError:
                continue
            url = t if t.startswith("http") else f"https://{t}"
            res = await self.executor.run(
                self.tool.binary, url, "--json",
                timeout=self.tool.timeout, module="WAPPALYZER",
            )
            techs: list[TechFinding] = []
            if res.success and res.stdout.strip():
                try:
                    payload = json.loads(res.stdout)
                except json.JSONDecodeError:
                    log.warning(f"wappalyzer non-json output for {t}")
                    payload = {}
                items = payload.get("technologies") if isinstance(payload, dict) else payload
                for tech in items or []:
                    techs.append(
                        TechFinding(
                            name=tech.get("name", "unknown"),
                            version=tech.get("version") or None,
                            category=", ".join(
                                c.get("name") for c in (tech.get("categories") or []) if c.get("name")
                            ) or None,
                        )
                    )
            results.append(TechResult(target=t, technologies=techs))
        total = sum(len(r.technologies) for r in results)
        log.info(f"wappalyzer fingerprinted {len(results)} targets, {total} findings")
        return results
