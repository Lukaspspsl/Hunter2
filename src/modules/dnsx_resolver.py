"""DNS validation via ProjectDiscovery dnsx.

Splits a list of candidate hosts into live and dead based on resolver answers.
Also reports wildcard-suspect entries so alterx permutations can be filtered.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from ..config_loader import ToolDef
from ..core.executor import CommandExecutor
from ..core.logger import get_logger
from ..core.scope_engine import ScopeEngine

log = get_logger("dnsx_resolver")


@dataclass
class DnsxResult:
    live: list[str] = field(default_factory=list)
    dead: list[str] = field(default_factory=list)
    a_records: dict[str, list[str]] = field(default_factory=dict)
    wildcard_suspects: list[str] = field(default_factory=list)


class DnsxResolver:
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

    async def resolve(self, targets: Iterable[str]) -> DnsxResult:
        """dnsx is passive (DNS only) but still scope-gated for hygiene."""
        in_scope: list[str] = []
        for t in targets:
            ok, _ = self.scope.is_in_scope(t)
            if ok:
                in_scope.append(t)

        if not in_scope:
            return DnsxResult()

        input_file = self.output_dir / "dnsx_input.txt"
        output_file = self.output_dir / "dnsx_output.jsonl"
        input_file.write_text("\n".join(in_scope) + "\n")

        args = self.tool.args or {}
        cmd = [
            self.tool.binary,
            "-l", str(input_file),
            "-json",
            "-silent",
            "-resp",
            "-a",
            "-o", str(output_file),
            "-t", str(args.get("threads", 50)),
            "-retry", str(args.get("retry", 2)),
        ]

        result = await self.executor.run(
            *cmd, timeout=self.tool.timeout, module="DNSX"
        )
        out = DnsxResult()
        if not output_file.exists():
            log.warning(f"dnsx no output (exit={result.returncode})")
            out.dead = in_scope
            return out

        seen: set[str] = set()
        ip_hosts: dict[str, list[str]] = {}
        for line in output_file.read_text().splitlines():
            if not line.strip():
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = doc.get("host")
            if not host:
                continue
            seen.add(host)
            a = doc.get("a") or []
            if a:
                out.a_records[host] = a
                for ip in a:
                    ip_hosts.setdefault(ip, []).append(host)

        out.live = sorted(seen)
        out.dead = sorted(set(in_scope) - seen)

        # naive wildcard heuristic: ≥8 hosts pointing at the same IP
        for ip, hosts in ip_hosts.items():
            if len(hosts) >= 8:
                out.wildcard_suspects.extend(hosts)

        log.info(
            f"dnsx resolved {len(out.live)} live / {len(out.dead)} dead "
            f"({len(out.wildcard_suspects)} wildcard-suspect)"
        )
        return out
