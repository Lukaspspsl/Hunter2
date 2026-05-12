"""HTTP probing via ProjectDiscovery httpx.

Returns status code, title, TLS metadata, redirects, and a tech-detect hint.
All targets are scope-checked before any subprocess invocation.
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

log = get_logger("httpx_prober")


@dataclass
class HttpxResult:
    target: str
    url: Optional[str] = None
    status_code: Optional[int] = None
    title: Optional[str] = None
    content_length: Optional[int] = None
    tech: list[str] = field(default_factory=list)
    tls_subject: Optional[str] = None
    tls_issuer: Optional[str] = None
    final_url: Optional[str] = None
    raw: Optional[dict] = None
    alive: bool = False


class HttpxProber:
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

    async def probe(self, targets: Iterable[str]) -> list[HttpxResult]:
        """Probe a batch of targets. Returns one HttpxResult per in-scope target."""
        in_scope: list[str] = []
        for t in targets:
            try:
                self.scope.assert_in_scope(t)
                in_scope.append(t)
            except ScopeViolationError:
                continue

        if not in_scope:
            return []

        input_file = self.output_dir / "httpx_input.txt"
        output_file = self.output_dir / "httpx_output.jsonl"
        input_file.write_text("\n".join(in_scope) + "\n")

        args = self.tool.args or {}
        cmd = [
            self.tool.binary,
            "-l", str(input_file),
            "-json",
            "-silent",
            "-no-color",
            "-o", str(output_file),
            "-threads", str(args.get("threads", 50)),
            "-timeout", str(min(self.tool.timeout, 30)),
        ]
        if args.get("follow_redirects", True):
            cmd.append("-follow-redirects")
        if args.get("tech_detect", True):
            cmd.append("-tech-detect")
        cmd.extend(["-title", "-status-code", "-content-length", "-tls-grab"])

        result = await self.executor.run(
            *cmd, timeout=self.tool.timeout, module="HTTPX"
        )
        if not output_file.exists():
            log.warning(f"httpx produced no output (exit={result.returncode})")
            return []

        results: dict[str, HttpxResult] = {}
        for line in output_file.read_text().splitlines():
            if not line.strip():
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = doc.get("input") or doc.get("host") or doc.get("url", "")
            host = host.replace("https://", "").replace("http://", "").split("/")[0]
            tls = doc.get("tls", {}) or {}
            r = HttpxResult(
                target=host,
                url=doc.get("url"),
                status_code=doc.get("status_code"),
                title=doc.get("title"),
                content_length=doc.get("content_length"),
                tech=list(doc.get("tech") or []),
                tls_subject=(tls.get("subject_cn") if isinstance(tls, dict) else None),
                tls_issuer=(tls.get("issuer_cn") if isinstance(tls, dict) else None),
                final_url=doc.get("final_url"),
                raw=doc,
                alive=True,
            )
            results[host] = r

        for t in in_scope:
            results.setdefault(t, HttpxResult(target=t, alive=False))

        log.info(
            f"httpx probed {len(in_scope)} targets, "
            f"{sum(1 for r in results.values() if r.alive)} alive"
        )
        return list(results.values())
