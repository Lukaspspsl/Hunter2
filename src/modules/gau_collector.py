"""Historical URL collection via gau + waybackurls.

Zero target traffic — pulls from Wayback Machine and Common Crawl.
Module-level dedup; DB unique constraint backs us up.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..config_loader import ToolDef
from ..core.executor import CommandExecutor
from ..core.logger import get_logger
from ..core.scope_engine import ScopeEngine

log = get_logger("gau_collector")


@dataclass
class GauResult:
    target: str
    urls: set[str] = field(default_factory=set)
    sources: dict[str, set[str]] = field(default_factory=dict)


class GauCollector:
    def __init__(
        self,
        gau_tool: ToolDef,
        wayback_tool: Optional[ToolDef],
        executor: CommandExecutor,
        scope: ScopeEngine,
        output_dir: Optional[Path] = None,
    ):
        self.gau = gau_tool
        self.wayback = wayback_tool
        self.executor = executor
        self.scope = scope
        self.output_dir = output_dir or Path("./data/raw_results")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def collect(self, target: str) -> GauResult:
        """Run gau and waybackurls in parallel, dedupe URLs."""
        ok, reason = self.scope.is_in_scope(target)
        if not ok:
            log.debug(f"skip OOS target {target}: {reason}")
            return GauResult(target=target)

        result = GauResult(target=target)
        tasks: list[asyncio.Task] = []

        async def _gau() -> tuple[str, set[str]]:
            res = await self.executor.run(
                self.gau.binary, target, "--threads", "5",
                timeout=self.gau.timeout, module="GAU",
            )
            urls = {l.strip() for l in res.stdout.splitlines() if l.strip()}
            return "gau", urls

        async def _wayback() -> tuple[str, set[str]]:
            res = await self.executor.run(
                self.wayback.binary, target,
                timeout=self.wayback.timeout, module="WAYBACK",
            )
            urls = {l.strip() for l in res.stdout.splitlines() if l.strip()}
            return "waybackurls", urls

        if self.gau:
            tasks.append(asyncio.create_task(_gau()))
        if self.wayback:
            tasks.append(asyncio.create_task(_wayback()))

        for coro in asyncio.as_completed(tasks):
            try:
                source, urls = await coro
            except Exception as e:
                log.warning(f"historical url source failed: {e}")
                continue
            result.urls.update(urls)
            result.sources[source] = urls

        log.info(
            f"gau/wayback collected {len(result.urls)} unique URLs for {target}"
        )
        return result
