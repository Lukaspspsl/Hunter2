"""FastAPI dashboard wiring.

Read-only view over the SQLite DB: tool execution timeline, program
list, OOS asset panel. No mutations from this surface — the orchestrator
and REPL are the only writers.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates

from ..config_loader import HunterConfig
from ..core.database import Database
from ..core.logger import get_logger
from .routes import router

log = get_logger("dashboard")


def create_app(cfg: HunterConfig, db: Database) -> FastAPI:
    app = FastAPI(
        title="Hunter 2 Dashboard",
        description="Read-only recon timeline + OOS asset panel",
        version="2.0.0",
    )

    templates_dir = Path(__file__).parent / "templates"
    templates_dir.mkdir(parents=True, exist_ok=True)

    app.state.cfg = cfg
    app.state.db = db
    app.state.templates = Jinja2Templates(directory=str(templates_dir))

    app.include_router(router)
    log.info("dashboard ready")
    return app
