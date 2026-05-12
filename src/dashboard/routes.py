"""Dashboard routes — read-only HTML + JSON.

Pages:
  GET  /                static index that links into the rest
  GET  /timeline        live execution timeline (polls /api/timeline)
  GET  /programs        list of configured programs + scope summary
  GET  /oos-assets      OOS subdomains the orchestrator tagged
  GET  /health          liveness probe (Railway healthcheck)

JSON:
  GET  /api/timeline?program=&limit=
  GET  /api/programs
  GET  /api/oos?program=
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, HTMLResponse

router = APIRouter()


def _db(req: Request):
    return req.app.state.db


def _cfg(req: Request):
    return req.app.state.cfg


def _tpl(req: Request):
    return req.app.state.templates


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return _tpl(request).TemplateResponse(
        request, "index.html", {"cfg": _cfg(request)},
    )


@router.get("/timeline", response_class=HTMLResponse)
async def timeline_page(request: Request, program: Optional[str] = None):
    return _tpl(request).TemplateResponse(
        request,
        "timeline.html",
        {"program": program, "programs": list(_cfg(request).programs)},
    )


@router.get("/programs", response_class=HTMLResponse)
async def programs_page(request: Request):
    return _tpl(request).TemplateResponse(
        request, "programs.html", {"programs": _cfg(request).programs},
    )


@router.get("/oos-assets", response_class=HTMLResponse)
async def oos_page(request: Request, program: Optional[str] = None):
    db = _db(request)
    if program is None and _cfg(request).programs:
        program = next(iter(_cfg(request).programs))
    rows = db.get_oos_subdomains(program) if program else []
    return _tpl(request).TemplateResponse(
        request,
        "oos.html",
        {
            "program": program,
            "programs": list(_cfg(request).programs),
            "rows": rows,
        },
    )


# ---------- JSON ----------


@router.get("/api/timeline")
async def api_timeline(
    request: Request,
    program: Optional[str] = None,
    limit: int = 100,
) -> JSONResponse:
    rows = _db(request).list_tool_executions(program=program, limit=limit)
    out = []
    for r in rows:
        out.append(
            {
                "id": r.id,
                "tool": r.tool_name,
                "target": r.target,
                "program": r.program,
                "status": r.status,
                "duration_ms": r.duration_ms,
                "exit_code": r.exit_code,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                "summary": (r.result_summary or "")[:200],
                "triggered_by": r.triggered_by,
            }
        )
    return JSONResponse(out)


@router.get("/api/programs")
async def api_programs(request: Request) -> JSONResponse:
    cfg = _cfg(request)
    out = {}
    for name, p in cfg.programs.items():
        out[name] = {
            "platform": p.platform,
            "aggressiveness": p.aggressiveness,
            "in_scope": p.in_scope,
            "out_of_scope": p.out_of_scope,
            "schedule": {"cron": p.schedule.cron, "enabled": p.schedule.enabled},
        }
    return JSONResponse(out)


@router.get("/api/oos")
async def api_oos(request: Request, program: str) -> JSONResponse:
    rows = _db(request).get_oos_subdomains(program)
    return JSONResponse(
        [
            {
                "domain": r.domain,
                "reason": r.oos_reason,
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            }
            for r in rows
        ]
    )
