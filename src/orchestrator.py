"""Passive scan orchestrator — runs the full discovery pipeline.

Pipeline (passive level):
  1. subfinder + crt.sh — seed subdomain set per scope root
  2. ScopeEngine.filter_targets — split in-scope / OOS, persist both
  3. dnsx — resolve, keep live
  4. httpx — probe live hosts
  5. alterx — permute live subdomains
  6. dnsx — validate permutations, fold new live hosts in

Every external invocation goes through ToolCaller so it lands in
ToolExecution. This module is what the REPL and the scheduler both
call into; it has no LLM dependency itself.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx as _httpx_client

from .config_loader import HunterConfig, ProgramConfig
from .core.database import Database
from .core.executor import CommandExecutor
from .core.logger import get_logger
from .core.scope_engine import OOSTarget, ScopeEngine
from .llm.tool_caller import ToolCaller, ToolCallResult
from .modules.alterx_permuter import AlterxPermuter
from .modules.dnsx_resolver import DnsxResolver
from .modules.httpx_prober import HttpxProber
from .modules.notifier import Notifier

log = get_logger("orchestrator")


@dataclass
class ScanReport:
    scan_id: int
    program: str
    level: str
    seed_targets: list[str] = field(default_factory=list)
    discovered: list[str] = field(default_factory=list)
    in_scope: list[str] = field(default_factory=list)
    oos: list[OOSTarget] = field(default_factory=list)
    live: list[str] = field(default_factory=list)
    permutations_added: list[str] = field(default_factory=list)
    new_subdomains: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"scan #{self.scan_id} {self.program}: "
            f"{len(self.discovered)} discovered "
            f"({len(self.in_scope)} in_scope / {len(self.oos)} OOS) "
            f"-> {len(self.live)} live "
            f"(+{len(self.permutations_added)} new from alterx); "
            f"{len(self.new_subdomains)} new since last scan"
        )


class Orchestrator:
    def __init__(
        self,
        cfg: HunterConfig,
        db: Database,
        program: str,
        program_cfg: ProgramConfig,
        executor: Optional[CommandExecutor] = None,
        output_dir: Optional[Path] = None,
    ):
        self.cfg = cfg
        self.db = db
        self.program = program
        self.program_cfg = program_cfg
        self.executor = executor or CommandExecutor(rate_limit="moderate")
        self.output_dir = output_dir or Path("./data/raw_results") / program
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.scope = ScopeEngine(
            program_name=program,
            in_scope=program_cfg.in_scope,
            out_of_scope=program_cfg.out_of_scope,
        )

        self.httpx_prober = HttpxProber(
            cfg.tools["httpx"], self.executor, self.scope, self.output_dir
        ) if "httpx" in cfg.tools else None
        self.dnsx_resolver = DnsxResolver(
            cfg.tools["dnsx"], self.executor, self.scope, self.output_dir
        ) if "dnsx" in cfg.tools else None
        self.alterx_permuter = AlterxPermuter(
            cfg.tools["alterx"], self.executor, self.output_dir
        ) if "alterx" in cfg.tools else None
        self.notifier = Notifier(
            tool=cfg.tools.get("notify"),
            executor=self.executor,
        )

    # ----- subdomain discovery primitives -----

    async def _subfinder(self, root: str) -> list[str]:
        tool = self.cfg.tools.get("subfinder")
        if not tool:
            return []
        out = self.output_dir / f"subfinder_{root}.txt"
        cmd = [
            tool.binary,
            "-d", root,
            "-silent",
            "-o", str(out),
            "-t", str((tool.args or {}).get("threads", 10)),
        ]
        result = await self.executor.run(*cmd, timeout=tool.timeout, module="SUBFINDER")
        if not out.exists():
            log.warning(f"subfinder produced no file for {root} (exit={result.returncode})")
            return []
        return [l.strip() for l in out.read_text().splitlines() if l.strip()]

    async def _crtsh(self, root: str) -> list[str]:
        """Hunter2-native crt.sh query (no Hunter 1.0 config coupling)."""
        clean = root.replace("*.", "").strip()
        url = "https://crt.sh/"
        params = {"q": f"%.{clean}", "output": "json"}
        try:
            async with _httpx_client.AsyncClient(timeout=30.0) as client:
                r = await client.get(url, params=params)
                if r.status_code != 200:
                    return []
                data = r.json()
        except Exception as e:
            log.warning(f"crt.sh query failed for {clean}: {e}")
            return []
        subs: set[str] = set()
        for entry in data:
            for field_name in ("name_value", "common_name"):
                val = entry.get(field_name) or ""
                for line in val.splitlines():
                    line = line.strip().lower().lstrip("*.")
                    if line and (line == clean or line.endswith(f".{clean}")):
                        subs.add(line)
        return sorted(subs)

    # ----- scan pipeline -----

    async def run_passive_scan(
        self,
        triggered_by: str = "manual",
        notify: bool = True,
    ) -> ScanReport:
        # 1. db setup
        prog_row = self.db.upsert_program(
            name=self.program,
            platform=self.program_cfg.platform,
            aggressiveness=self.program_cfg.aggressiveness,
        )
        prog_id = prog_row.id
        seeds = [s.replace("*.", "") for s in self.program_cfg.in_scope]
        scan_id = self.db.create_scan(
            target_source=",".join(seeds),
            program=self.program,
            program_id=prog_id,
            aggressiveness="passive",
            triggered_by=triggered_by,
        )
        report = ScanReport(
            scan_id=scan_id,
            program=self.program,
            level="passive",
            seed_targets=seeds,
        )

        previous = self._previous_domain_set(self.program)

        # 2. discover
        discovered: set[str] = set()
        for root in seeds:
            try:
                sf, ct = await asyncio.gather(
                    self._subfinder(root),
                    self._crtsh(root),
                )
                discovered.update(sf)
                discovered.update(ct)
                discovered.add(root)
                log.info(f"discovery [{root}]: subfinder={len(sf)} crtsh={len(ct)}")
            except Exception as e:
                report.errors.append(f"discovery {root}: {e}")
                log.error(f"discovery failed for {root}: {e}")

        report.discovered = sorted(discovered)

        # 3. scope split + persist OOS
        in_scope, oos = self.scope.filter_targets(discovered)
        report.in_scope = sorted(in_scope)
        report.oos = oos

        entries: list[dict] = []
        for d in in_scope:
            entries.append({"domain": d, "source_tool": "discover", "in_scope": True})
        for o in oos:
            entries.append(
                {
                    "domain": o.target,
                    "source_tool": "discover",
                    "in_scope": False,
                    "oos_reason": o.reason,
                }
            )
        if entries:
            self.db.add_subdomains_bulk(
                scan_id, entries, previous_domains=previous, program_id=prog_id
            )

        # 4. dnsx — live filter
        live: list[str] = []
        if self.dnsx_resolver and in_scope:
            try:
                dns = await self.dnsx_resolver.resolve(in_scope)
                live = list(dns.live)
                report.live = live
            except Exception as e:
                report.errors.append(f"dnsx: {e}")
                log.error(f"dnsx failed: {e}")

        # 5. httpx probe (best-effort)
        if self.httpx_prober and live:
            try:
                await self.httpx_prober.probe(live)
            except Exception as e:
                report.errors.append(f"httpx: {e}")
                log.error(f"httpx failed: {e}")

        # 6. alterx permutations -> dnsx validate
        if self.alterx_permuter and live:
            try:
                alterx = await self.alterx_permuter.permute(live)
                perms = list(alterx.permutations)
                if perms and self.dnsx_resolver:
                    perm_in_scope, perm_oos = self.scope.filter_targets(perms)
                    dns2 = await self.dnsx_resolver.resolve(perm_in_scope)
                    new_live = [d for d in dns2.live if d not in set(live)]
                    report.permutations_added = new_live
                    if new_live:
                        self.db.add_subdomains_bulk(
                            scan_id,
                            [
                                {"domain": d, "source_tool": "alterx", "in_scope": True}
                                for d in new_live
                            ],
                            previous_domains=previous,
                            program_id=prog_id,
                        )
                    # store OOS permutations too
                    if perm_oos:
                        self.db.add_subdomains_bulk(
                            scan_id,
                            [
                                {
                                    "domain": o.target,
                                    "source_tool": "alterx",
                                    "in_scope": False,
                                    "oos_reason": o.reason,
                                }
                                for o in perm_oos
                            ],
                            previous_domains=previous,
                            program_id=prog_id,
                        )
            except Exception as e:
                report.errors.append(f"alterx: {e}")
                log.error(f"alterx failed: {e}")

        # 7. diff vs previous
        all_in_scope = set(in_scope) | set(report.permutations_added)
        report.new_subdomains = sorted(all_in_scope - previous)

        self.db.complete_scan(scan_id, status="completed")

        if notify and report.new_subdomains and self.program_cfg.notify.on_new_subdomain:
            try:
                await self.notifier.new_subdomains(
                    program=self.program,
                    domains=report.new_subdomains,
                )
            except Exception as e:
                log.warning(f"notify failed: {e}")

        log.info(report.summary())
        self._write_report(scan_id, report)
        return report

    # ----- helpers -----

    def _previous_domain_set(self, program: str) -> set[str]:
        latest = self.db.get_latest_scan(program=program)
        if not latest:
            return set()
        return self.db.get_all_domains_from_scan(latest.id)

    def _write_report(self, scan_id: int, report: ScanReport) -> None:
        try:
            path = self.output_dir / f"scan_{scan_id}_report.json"
            path.write_text(
                json.dumps(
                    {
                        "scan_id": report.scan_id,
                        "program": report.program,
                        "level": report.level,
                        "seed_targets": report.seed_targets,
                        "discovered": report.discovered,
                        "in_scope": report.in_scope,
                        "oos": [{"target": o.target, "reason": o.reason} for o in report.oos],
                        "live": report.live,
                        "permutations_added": report.permutations_added,
                        "new_subdomains": report.new_subdomains,
                        "errors": report.errors,
                    },
                    indent=2,
                )
            )
        except Exception as e:
            log.warning(f"failed to write scan report: {e}")


def build_tool_caller(
    cfg: HunterConfig,
    db: Database,
    program: str,
    scope: ScopeEngine,
    orchestrator: Orchestrator,
    scan_id: Optional[int] = None,
) -> ToolCaller:
    """Wire orchestrator methods into the ToolCaller registry.

    This is what the ReAct engine talks to — each tool the LLM can call
    maps to a coroutine that returns a short summary string for the
    observation back to the LLM.
    """
    tc = ToolCaller(cfg=cfg, db=db, scope=scope, program=program, scan_id=scan_id)

    async def _httpx_handler(target: str = "", **_):
        if not orchestrator.httpx_prober:
            return "httpx unavailable"
        results = await orchestrator.httpx_prober.probe([target])
        if not results:
            return f"{target}: no response"
        r = results[0]
        tech = ",".join(r.tech) if r.tech else "-"
        return (
            f"{target}: status={r.status_code} title={(r.title or '')[:60]!r} "
            f"tech=[{tech}] alive={r.alive}"
        )

    async def _dnsx_handler(target: str = "", **_):
        if not orchestrator.dnsx_resolver:
            return "dnsx unavailable"
        dns = await orchestrator.dnsx_resolver.resolve([target])
        if target in dns.live:
            ips = dns.a_records.get(target, [])
            return f"{target}: live A={','.join(ips)}"
        return f"{target}: dead"

    async def _crtsh_handler(target: str = "", **_):
        subs = await orchestrator._crtsh(target)
        return f"{target}: {len(subs)} subdomains via crt.sh"

    async def _subfinder_handler(target: str = "", **_):
        subs = await orchestrator._subfinder(target)
        return f"{target}: {len(subs)} subdomains via subfinder"

    async def _alterx_handler(target: str = "", **_):
        if not orchestrator.alterx_permuter:
            return "alterx unavailable"
        res = await orchestrator.alterx_permuter.permute([target])
        return f"{target}: {len(res.permutations)} permutations generated"

    async def _notify_handler(title: str = "Hunter alert", body: str = "", **_):
        ok = await orchestrator.notifier.send(title, body)
        return f"slack {'sent' if ok else 'failed'}"

    tc.register("httpx", _httpx_handler)
    tc.register("dnsx", _dnsx_handler)
    tc.register("crtsh", _crtsh_handler)
    tc.register("subfinder", _subfinder_handler)
    tc.register("alterx", _alterx_handler)
    tc.register("notify", _notify_handler)
    return tc
