"""Hunter 2 CLI entry — typer subcommands.

Subcommands:
    chat       interactive REPL (LLM-driven recon)
    scan       one-shot passive scan
    programs   list configured programs
    tools      list tool registry + binary availability
    scheduler  run forever, fire cron jobs from programs.yaml
    dashboard  start the FastAPI read-only dashboard
"""

from __future__ import annotations

import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .config_loader import load_config
from .core.database import init_db
from .core.logger import setup_logging
from .orchestrator import Orchestrator
from .tool_checker import check_tools, report as tool_report

app = typer.Typer(add_completion=False, help="Hunter 2 — LLM-driven recon")
console = Console()


@app.callback()
def _root(
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    config_dir: str = typer.Option("./configs", "--config-dir"),
):
    setup_logging(level="DEBUG" if verbose else "INFO")
    # stash on typer context via globals (cheap)
    _STATE["config_dir"] = config_dir


_STATE: dict = {"config_dir": "./configs"}


@app.command()
def chat(
    program: Optional[str] = typer.Option(None, "--program", "-p"),
    no_llm: bool = typer.Option(False, "--no-llm"),
):
    """Interactive REPL — talk to the LLM, run tools, escalate on demand."""
    from .repl import run_repl
    asyncio.run(
        run_repl(
            config_dir=_STATE["config_dir"],
            program=program,
            no_llm=no_llm,
        )
    )


@app.command()
def scan(
    program: str = typer.Argument(..., help="program name from programs.yaml"),
    triggered_by: str = typer.Option("manual", "--triggered-by"),
):
    """Run a single passive scan for a program. No LLM involved."""
    cfg = load_config(_STATE["config_dir"])
    if program not in cfg.programs:
        console.print(f"[red]unknown program {program!r}[/red]")
        raise typer.Exit(1)
    db = init_db()
    prog_cfg = cfg.programs[program]
    orch = Orchestrator(cfg=cfg, db=db, program=program, program_cfg=prog_cfg)

    async def _go():
        report = await orch.run_passive_scan(triggered_by=triggered_by)
        console.print(report.summary())
        if report.errors:
            console.print(f"[yellow]errors:[/yellow] {report.errors}")

    asyncio.run(_go())


@app.command()
def programs():
    """List configured programs with their scope summary."""
    cfg = load_config(_STATE["config_dir"])
    t = Table("name", "platform", "ceiling", "in_scope", "OOS", "cron")
    for name, p in cfg.programs.items():
        t.add_row(
            name,
            p.platform or "-",
            p.aggressiveness,
            ", ".join(p.in_scope[:3]) + ("…" if len(p.in_scope) > 3 else ""),
            ", ".join(p.out_of_scope[:3]) + ("…" if len(p.out_of_scope) > 3 else ""),
            (p.schedule.cron if p.schedule.enabled else "-") or "-",
        )
    console.print(t)


@app.command()
def tools():
    """Show registered tools and whether each binary is available."""
    cfg = load_config(_STATE["config_dir"])
    statuses = check_tools(cfg)
    console.print(tool_report(statuses))


@app.command()
def scheduler():
    """Run cron loop until SIGINT/SIGTERM. Drives passive scans without LLM."""
    from .scheduler import run_scheduler
    asyncio.run(run_scheduler(config_dir=_STATE["config_dir"]))


@app.command()
def dashboard(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
):
    """Start the read-only FastAPI dashboard. (Phase 5)"""
    try:
        import uvicorn
        from .dashboard.app import create_app
    except Exception as e:
        console.print(f"[red]dashboard not available: {e}[/red]")
        raise typer.Exit(1)
    cfg = load_config(_STATE["config_dir"])
    db = init_db()
    uvicorn.run(create_app(cfg, db), host=host, port=port)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
