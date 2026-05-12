"""Terminal REPL — `hunter2 chat`.

Interactive loop driven by the ReAct engine. The user types natural
language; the engine emits <think>/<action>/<final> blocks, the ToolCaller
runs each action under the program's aggressiveness ceiling, and tool
output flows back as observations. Escalation prompts pause for the user.

Special commands (typed instead of free text):
    /help                   show this help
    /program <name>         switch active program
    /level                  print current ceiling
    /scan                   run a passive scan now (no LLM)
    /history                last 20 tool executions for this program
    /no-llm <bool>          toggle LLM offline mode
    /exit                   leave

Conversation history persists to the LLMSession DB row. Readline
history lives in ~/.hunter2_history.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.patch_stdout import patch_stdout
from rich.console import Console
from rich.table import Table

from .config_loader import HunterConfig, ProgramConfig, load_config
from .core.database import Database, init_db
from .core.logger import get_logger
from .llm.client import LLMClient
from .llm.react_engine import EscalationRequest, ReActEngine
from .orchestrator import Orchestrator, build_tool_caller

log = get_logger("repl")
console = Console()

HISTORY_PATH = Path(os.path.expanduser("~/.hunter2_history"))


class Repl:
    def __init__(
        self,
        cfg: HunterConfig,
        db: Database,
        program: str,
        no_llm: bool = False,
    ):
        self.cfg = cfg
        self.db = db
        self.program = program
        self.no_llm = no_llm
        self.session_id: Optional[int] = None
        self.llm: Optional[LLMClient] = None
        self.engine: Optional[ReActEngine] = None
        self.orchestrator: Optional[Orchestrator] = None
        self._set_program(program)

    # ----- setup -----

    def _set_program(self, name: str) -> None:
        if name not in self.cfg.programs:
            console.print(f"[red]unknown program {name!r}[/red]")
            return
        prog_cfg: ProgramConfig = self.cfg.programs[name]
        self.program = name
        self.orchestrator = Orchestrator(
            cfg=self.cfg, db=self.db, program=name, program_cfg=prog_cfg
        )
        if not self.no_llm:
            self.llm = LLMClient(self.cfg.llm)
            tc = build_tool_caller(
                cfg=self.cfg,
                db=self.db,
                program=name,
                scope=self.orchestrator.scope,
                orchestrator=self.orchestrator,
            )
            self.engine = ReActEngine(
                cfg=self.cfg,
                db=self.db,
                llm=self.llm,
                tool_caller=tc,
                program=name,
                level=prog_cfg.aggressiveness,
            )
            self.session_id = self.db.create_llm_session(program=name)
        else:
            self.engine = None
            self.session_id = None
        console.print(
            f"[green]program={name}[/green] "
            f"ceiling={prog_cfg.aggressiveness} "
            f"llm={'off' if self.no_llm else self.cfg.llm.model}"
        )

    async def _llm_health(self) -> str:
        if self.no_llm or not self.llm:
            return "offline (--no-llm)"
        ok = await self.llm.is_available()
        return f"{'connected' if ok else 'unreachable'} @ {self.cfg.llm.base_url}"

    # ----- main loop -----

    async def run(self) -> None:
        latest = self.db.get_latest_scan(program=self.program)
        last_scan = (
            f"last scan #{latest.id} {latest.completed_at}"
            if latest and latest.completed_at
            else "no prior scan"
        )
        console.print("[bold]Hunter 2.0 — security recon assistant[/bold]")
        console.print(f"Program: {self.program} ({self.cfg.programs[self.program].aggressiveness} ceiling)")
        console.print(f"LLM: {await self._llm_health()}")
        console.print(f"DB:  {last_scan}")
        console.print("Type /help for commands, /exit to quit.\n")

        HISTORY_PATH.touch(exist_ok=True)
        prompt = PromptSession(history=FileHistory(str(HISTORY_PATH)))

        try:
            with patch_stdout():
                while True:
                    try:
                        text = await prompt.prompt_async("hunter> ")
                    except (EOFError, KeyboardInterrupt):
                        break
                    text = text.strip()
                    if not text:
                        continue
                    if text.startswith("/"):
                        if await self._handle_command(text):
                            break
                        continue
                    await self._handle_chat(text)
        finally:
            if self.session_id is not None:
                self.db.close_llm_session(self.session_id)
            if self.llm:
                await self.llm.aclose()

    # ----- command handlers -----

    async def _handle_command(self, text: str) -> bool:
        parts = text.split()
        cmd = parts[0]
        args = parts[1:]
        if cmd in ("/exit", "/quit"):
            return True
        if cmd == "/help":
            console.print(_HELP)
            return False
        if cmd == "/program":
            if not args:
                console.print("usage: /program <name>")
                return False
            self._set_program(args[0])
            return False
        if cmd == "/level":
            console.print(f"ceiling = {self.cfg.programs[self.program].aggressiveness}")
            return False
        if cmd == "/scan":
            if not self.orchestrator:
                console.print("[red]no orchestrator[/red]")
                return False
            console.print("[yellow]running passive scan…[/yellow]")
            report = await self.orchestrator.run_passive_scan(triggered_by="repl")
            console.print(report.summary())
            return False
        if cmd == "/history":
            self._print_history()
            return False
        if cmd == "/no-llm":
            self.no_llm = not self.no_llm if not args else args[0].lower() in ("1", "true", "on", "yes")
            console.print(f"no_llm = {self.no_llm}")
            self._set_program(self.program)
            return False
        console.print(f"[red]unknown command {cmd}[/red] — /help")
        return False

    def _print_history(self) -> None:
        rows = self.db.list_tool_executions(program=self.program, limit=20)
        t = Table("started", "tool", "target", "status", "ms", "summary")
        for r in rows:
            t.add_row(
                str(r.started_at)[:19] if r.started_at else "-",
                r.tool_name,
                (r.target or "-")[:40],
                r.status,
                str(r.duration_ms or "-"),
                (r.result_summary or "-")[:60],
            )
        console.print(t)

    # ----- chat path -----

    async def _handle_chat(self, text: str) -> None:
        if self.engine is None or self.session_id is None:
            console.print("[yellow]LLM disabled — only / commands work[/yellow]")
            return
        self.engine.add_user(text)
        self.db.append_llm_message(self.session_id, "user", text)
        run = await self.engine.step()

        for step in run.steps:
            if step.kind == "think":
                console.print(f"[dim]think:[/dim] {step.body}")
            elif step.kind == "action":
                tr = step.tool_result
                marker = "OK" if (tr and tr.ok) else "FAIL"
                console.print(f"[cyan]action:[/cyan] {step.body}  [{marker}] {tr.summary if tr else ''}")
                if tr and tr.execution_id:
                    self.db.append_llm_tool_execution(self.session_id, tr.execution_id)
            elif step.kind == "escalate":
                console.print(f"[magenta]escalate:[/magenta] {step.body}")
            elif step.kind == "final":
                console.print(f"[bold green]final:[/bold green] {step.body}")
                self.db.append_llm_message(self.session_id, "assistant", step.body)
            else:
                console.print(f"[dim]{step.kind}:[/dim] {step.body}")

        if run.error:
            console.print(f"[red]engine error:[/red] {run.error}")
            return

        if run.escalation:
            await self._handle_escalation(run.escalation)

    async def _handle_escalation(self, esc: EscalationRequest) -> None:
        console.print("[bold magenta]ESCALATION REQUEST[/bold magenta]")
        console.print(f"  {esc.from_level} -> {esc.to_level}")
        console.print(f"  target: {esc.target or '-'}")
        console.print(f"  reason: {esc.reason}")
        ans = (await PromptSession().prompt_async("approve? (yes/no/<action>) ")).strip()
        if ans.lower() in ("no", "n", ""):
            self.engine.reject_escalation(esc)
            console.print("[yellow]rejected[/yellow]")
            return
        if ans.lower() in ("yes", "y"):
            console.print(
                "[yellow]ok — re-ask the LLM for the exact action to run at the new level[/yellow]"
            )
            self.engine.reject_escalation(esc)  # need explicit action; let LLM propose
            return
        # treat ans as the action to run under the escalated ceiling
        result = await self.engine.approve_escalation(esc, action=ans)
        console.print(
            f"[cyan]escalated action:[/cyan] {ans}  "
            f"[{'OK' if result.ok else 'FAIL'}] {result.summary}"
        )


_HELP = """commands:
  /help              this help
  /program <name>    switch active program
  /level             show current aggressiveness ceiling
  /scan              run a passive scan now (no LLM)
  /history           recent tool executions for this program
  /no-llm [on|off]   toggle LLM offline mode
  /exit              quit
"""


async def run_repl(
    config_dir: str = "./configs",
    program: Optional[str] = None,
    no_llm: bool = False,
) -> None:
    cfg = load_config(config_dir)
    db = init_db()
    if not cfg.programs:
        console.print("[red]no programs defined in configs/programs.yaml[/red]")
        return
    if program is None:
        program = next(iter(cfg.programs))
    repl = Repl(cfg=cfg, db=db, program=program, no_llm=no_llm)
    await repl.run()
