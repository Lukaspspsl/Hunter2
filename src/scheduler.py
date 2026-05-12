"""APScheduler-driven cron loop for passive monitoring.

Reads each program's schedule.cron expression and registers a job
that runs a passive scan via the Orchestrator. The LLM is never
involved on the cron path — invariant #5 in HUNTER2_PLAN.md
("Cron jobs run without LLM").
"""

from __future__ import annotations

import asyncio
import signal
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from .config_loader import HunterConfig, load_config
from .core.database import Database, init_db
from .core.logger import get_logger
from .orchestrator import Orchestrator

log = get_logger("scheduler")


def _make_trigger(cron_expr: str) -> CronTrigger:
    """Accept a 5-field unix cron expression."""
    return CronTrigger.from_crontab(cron_expr)


async def _run_passive_for_program(
    cfg: HunterConfig,
    db: Database,
    program: str,
) -> None:
    prog_cfg = cfg.programs.get(program)
    if prog_cfg is None:
        log.error(f"program '{program}' not in config — skipping scheduled scan")
        return
    log.info(f"[cron] passive scan starting for {program}")
    orch = Orchestrator(cfg=cfg, db=db, program=program, program_cfg=prog_cfg)
    try:
        report = await orch.run_passive_scan(triggered_by="cron")
        log.info(f"[cron] {report.summary()}")
    except Exception as e:
        log.exception(f"[cron] passive scan for {program} crashed: {e}")


def build_scheduler(
    cfg: HunterConfig,
    db: Database,
) -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler()
    registered = 0
    for name, prog in cfg.programs.items():
        sched = prog.schedule
        if not sched.enabled or not sched.cron:
            log.debug(f"skip cron for {name} (disabled or no expression)")
            continue
        try:
            trigger = _make_trigger(sched.cron)
        except Exception as e:
            log.error(f"bad cron expression for {name!r}: {sched.cron!r} ({e})")
            continue
        scheduler.add_job(
            _run_passive_for_program,
            trigger=trigger,
            args=[cfg, db, name],
            id=f"passive_{name}",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        registered += 1
        log.info(f"registered cron '{sched.cron}' for program={name}")
    log.info(f"scheduler ready ({registered} jobs)")
    return scheduler


async def run_scheduler(config_dir: str = "./configs", db_path: Optional[str] = None) -> None:
    cfg = load_config(config_dir)
    db = init_db(db_path) if db_path else init_db()
    scheduler = build_scheduler(cfg, db)

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _stop(*_):
        log.info("scheduler stopping (signal)")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _stop)
        except NotImplementedError:
            pass  # windows

    scheduler.start()
    log.info("scheduler started — waiting for cron triggers")
    try:
        await stop_event.wait()
    finally:
        scheduler.shutdown(wait=False)
