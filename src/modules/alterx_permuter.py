"""Subdomain permutation via alterx.

Decision: validate permutations via DnsxResolver before persisting (per plan
Open Question #1). The orchestrator wires the two together.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from ..config_loader import ToolDef
from ..core.executor import CommandExecutor
from ..core.logger import get_logger


log = get_logger("alterx_permuter")


@dataclass
class AlterxResult:
    permutations: list[str] = field(default_factory=list)


class AlterxPermuter:
    def __init__(
        self,
        tool: ToolDef,
        executor: CommandExecutor,
        output_dir: Optional[Path] = None,
    ):
        self.tool = tool
        self.executor = executor
        self.output_dir = output_dir or Path("./data/raw_results")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def permute(self, seeds: Iterable[str]) -> AlterxResult:
        """Emit permutations from seed subdomains. Caller validates via dnsx."""
        seeds = [s.strip().lower() for s in seeds if s.strip()]
        if not seeds:
            return AlterxResult()

        input_file = self.output_dir / "alterx_input.txt"
        output_file = self.output_dir / "alterx_output.txt"
        input_file.write_text("\n".join(seeds) + "\n")

        result = await self.executor.run(
            self.tool.binary,
            "-l", str(input_file),
            "-o", str(output_file),
            "-silent",
            timeout=self.tool.timeout,
            module="ALTERX",
        )
        if not output_file.exists():
            log.warning(f"alterx no output (exit={result.returncode})")
            return AlterxResult()

        perms = [l.strip().lower() for l in output_file.read_text().splitlines() if l.strip()]
        # dedupe vs seed set
        seed_set = set(seeds)
        perms = sorted({p for p in perms if p not in seed_set})
        log.info(f"alterx generated {len(perms)} permutations from {len(seeds)} seeds")
        return AlterxResult(permutations=perms)
