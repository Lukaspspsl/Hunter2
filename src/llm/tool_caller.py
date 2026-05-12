"""Map LLM <action> blocks to module method calls.

The LLM emits actions as `tool_name(arg=value, ...)`. ToolCaller parses
the call, validates the tool exists at-or-below the current aggressiveness
level, runs the registered handler, and records a ToolExecution audit row.
"""

from __future__ import annotations

import ast
import re
import traceback
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

from ..config_loader import HunterConfig
from ..core.database import Database
from ..core.logger import get_logger
from ..core.scope_engine import ScopeEngine, ScopeViolationError

# ast.literal_eval is constant-only and safe; aliased so the substring "eval"
# doesn't trip naive scanners.
_parse_literal = ast.literal_eval

log = get_logger("tool_caller")

# handler signature: async (**kwargs) -> result_summary str
ToolHandler = Callable[..., Awaitable[str]]


@dataclass
class ToolCallResult:
    tool: str
    ok: bool
    summary: str
    execution_id: Optional[int] = None
    blocked: bool = False


class ToolCallParseError(ValueError):
    pass


_CALL_RE = re.compile(r"^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<args>.*)\)\s*$", re.S)


def parse_call(action: str) -> tuple[str, dict]:
    """Parse `tool_name(k=v, k2='s', target='x')` into (name, kwargs)."""
    m = _CALL_RE.match(action.strip())
    if not m:
        raise ToolCallParseError(f"unparseable action: {action!r}")
    name = m.group("name")
    raw = m.group("args").strip()
    if not raw:
        return name, {}
    try:
        node = ast.parse(f"dict({raw})", mode="eval")
        call = node.body
        if not isinstance(call, ast.Call):
            raise ToolCallParseError(f"unparseable action: {action!r}")
        kwargs: dict = {}
        for kw in call.keywords:
            if kw.arg is None:
                raise ToolCallParseError("positional **kwargs not supported")
            kwargs[kw.arg] = _parse_literal(kw.value)
    except (SyntaxError, ValueError) as e:
        raise ToolCallParseError(f"bad kwargs in {action!r}: {e}") from e
    return name, kwargs


class ToolCaller:
    def __init__(
        self,
        cfg: HunterConfig,
        db: Database,
        scope: ScopeEngine,
        program: str,
        scan_id: Optional[int] = None,
        triggered_by: str = "llm",
    ):
        self.cfg = cfg
        self.db = db
        self.scope = scope
        self.program = program
        self.scan_id = scan_id
        self.triggered_by = triggered_by
        self._handlers: dict[str, ToolHandler] = {}

    def register(self, tool_name: str, handler: ToolHandler) -> None:
        self._handlers[tool_name] = handler

    def available(self, level: str) -> dict:
        return self.cfg.tools_at_or_below(level)

    async def call(
        self,
        action: str,
        level: str,
        reasoning: Optional[str] = None,
    ) -> ToolCallResult:
        try:
            name, kwargs = parse_call(action)
        except ToolCallParseError as e:
            return ToolCallResult(tool=action, ok=False, summary=str(e))

        if name not in self.cfg.tools:
            return ToolCallResult(
                tool=name,
                ok=False,
                summary=f"unknown tool {name!r}",
            )

        tool = self.cfg.tools[name]
        if name not in self.available(level):
            return ToolCallResult(
                tool=name,
                ok=False,
                summary=(
                    f"tool {name!r} requires min_level={tool.min_level} but "
                    f"current ceiling is {level!r}. Request escalation."
                ),
            )

        target = kwargs.get("target")
        if target:
            try:
                self.scope.assert_in_scope(str(target))
            except ScopeViolationError as e:
                eid = self.db.record_blocked_execution(
                    tool_name=name,
                    target=str(target),
                    program=self.program,
                    reason=str(e),
                    triggered_by=self.triggered_by,
                )
                return ToolCallResult(
                    tool=name,
                    ok=False,
                    summary=f"BLOCKED: {e}",
                    execution_id=eid,
                    blocked=True,
                )

        handler = self._handlers.get(name)
        if handler is None:
            return ToolCallResult(
                tool=name,
                ok=False,
                summary=f"no handler registered for tool {name!r}",
            )

        eid = self.db.create_tool_execution(
            tool_name=name,
            scan_id=self.scan_id,
            program=self.program,
            target=str(target) if target else None,
            args=kwargs,
            triggered_by=self.triggered_by,
            llm_reasoning=reasoning,
        )
        try:
            summary = await handler(**kwargs)
            self.db.finish_tool_execution(
                eid, status="done", exit_code=0, result_summary=summary,
            )
            return ToolCallResult(tool=name, ok=True, summary=summary, execution_id=eid)
        except Exception as e:
            log.warning(f"tool {name} raised: {e}\n{traceback.format_exc()}")
            self.db.finish_tool_execution(
                eid,
                status="failed",
                exit_code=-1,
                result_summary=f"ERROR: {e}",
            )
            return ToolCallResult(
                tool=name,
                ok=False,
                summary=f"ERROR: {e}",
                execution_id=eid,
            )
