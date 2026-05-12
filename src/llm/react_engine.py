"""ReAct loop driver: observe -> think -> act, with human-in-loop escalation.

The LLM emits XML-tagged blocks. Each turn the engine:
  1. Sends current message history to LLMClient.
  2. Parses the response for <action>, <final>, or <escalate>.
  3. Action: ToolCaller runs it under the current ceiling; observation
     gets appended as the next user message.
  4. Escalate: pause loop, return EscalationRequest. Caller decides to
     approve (bumps ceiling for one tool call) or reject.
  5. Final: loop ends, return assistant conclusion.

Scope is not the engine's concern — ToolCaller enforces it before each
subprocess. The engine only enforces aggressiveness ceilings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from ..config_loader import AGGR_LEVELS, HunterConfig
from ..core.database import Database
from ..core.logger import get_logger
from .client import ChatMessage, LLMClient, LLMUnavailable
from .prompts import build_system_prompt
from .tool_caller import ToolCallResult, ToolCaller

log = get_logger("react_engine")


_TAG_RE = re.compile(
    r"<(?P<tag>think|action|final|escalate)>(?P<body>.*?)</(?P=tag)>",
    re.DOTALL | re.IGNORECASE,
)


@dataclass
class EscalationRequest:
    from_level: str
    to_level: str
    target: Optional[str]
    reason: str
    raw: str

    def summary(self) -> str:
        return (
            f"ESCALATION: {self.from_level} -> {self.to_level} "
            f"on {self.target or '<unspecified>'} — {self.reason}"
        )


@dataclass
class ReActStep:
    kind: str
    body: str
    tool_result: Optional[ToolCallResult] = None


@dataclass
class ReActRun:
    steps: list[ReActStep] = field(default_factory=list)
    final: Optional[str] = None
    escalation: Optional[EscalationRequest] = None
    error: Optional[str] = None


def _parse_blocks(text: str) -> list[tuple[str, str]]:
    return [(m.group("tag").lower(), m.group("body").strip()) for m in _TAG_RE.finditer(text)]


def _parse_escalate(body: str, raw: str) -> EscalationRequest:
    fields: dict[str, str] = {}
    for line in body.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            fields[k.strip().lower()] = v.strip()
    return EscalationRequest(
        from_level=fields.get("from", ""),
        to_level=fields.get("to", ""),
        target=fields.get("target") or None,
        reason=fields.get("reason", ""),
        raw=raw,
    )


def _level_valid(level: str) -> bool:
    return level in AGGR_LEVELS


class ReActEngine:
    """Drives one ReAct session against the LLM for one program."""

    def __init__(
        self,
        cfg: HunterConfig,
        db: Database,
        llm: LLMClient,
        tool_caller: ToolCaller,
        program: str,
        level: str,
        scope_note: str = "",
        max_turns: int = 12,
    ):
        if not _level_valid(level):
            raise ValueError(f"invalid ceiling {level!r}")
        self.cfg = cfg
        self.db = db
        self.llm = llm
        self.tools = tool_caller
        self.program = program
        self.level = level
        self.scope_note = scope_note
        self.max_turns = max_turns
        self.messages: list[ChatMessage] = []
        self._init_system_prompt()

    def _init_system_prompt(self) -> None:
        tools_at_level = self.cfg.tools_at_or_below(self.level)
        prompt = build_system_prompt(
            program_name=self.program,
            level=self.level,
            tools=tools_at_level,
            scope_note=self.scope_note,
        )
        self.messages = [ChatMessage(role="system", content=prompt)]

    def add_user(self, text: str) -> None:
        self.messages.append(ChatMessage(role="user", content=text))

    def _append_assistant(self, text: str) -> None:
        self.messages.append(ChatMessage(role="assistant", content=text))

    def _append_observation(self, text: str) -> None:
        self.messages.append(
            ChatMessage(role="user", content=f"<observe>{text}</observe>")
        )

    async def step(self) -> ReActRun:
        """Run the loop until <final>, <escalate>, error, or max_turns."""
        run = ReActRun()
        for turn in range(self.max_turns):
            try:
                reply = await self.llm.chat(
                    self.messages,
                    stop=["</final>", "</escalate>"],
                )
            except LLMUnavailable as e:
                run.error = f"LLM unavailable: {e}"
                return run

            # llama.cpp drops the closing tag when matching a stop sequence; restore.
            reply = _restore_closing_tags(reply)
            self._append_assistant(reply)

            blocks = _parse_blocks(reply)
            if not blocks:
                run.error = f"no recognised blocks in LLM reply (turn {turn})"
                run.steps.append(ReActStep(kind="raw", body=reply))
                return run

            for tag, body in blocks:
                if tag == "think":
                    run.steps.append(ReActStep(kind="think", body=body))
                    continue
                if tag == "final":
                    run.steps.append(ReActStep(kind="final", body=body))
                    run.final = body
                    return run
                if tag == "escalate":
                    esc = _parse_escalate(body, reply)
                    run.steps.append(ReActStep(kind="escalate", body=body))
                    run.escalation = esc
                    return run
                if tag == "action":
                    result = await self.tools.call(
                        action=body,
                        level=self.level,
                        reasoning=_last_think(run),
                    )
                    run.steps.append(
                        ReActStep(kind="action", body=body, tool_result=result)
                    )
                    obs = _format_observation(result)
                    self._append_observation(obs)
                    # break out of block loop to send observation back to LLM
                    break

        run.error = f"max_turns ({self.max_turns}) exhausted"
        return run

    async def approve_escalation(
        self,
        esc: EscalationRequest,
        action: str,
    ) -> ToolCallResult:
        """Run a single tool at the escalated ceiling.

        The engine's standing ceiling is unchanged — only this one call runs
        under `esc.to_level`. The decision is the caller's responsibility;
        this method assumes the user has approved.
        """
        if not _level_valid(esc.to_level):
            raise ValueError(f"invalid escalation target {esc.to_level!r}")
        log.info(
            f"escalation approved: {esc.from_level} -> {esc.to_level} "
            f"action={action!r}"
        )
        result = await self.tools.call(
            action=action,
            level=esc.to_level,
            reasoning=f"escalation approved: {esc.reason}",
        )
        obs = _format_observation(result)
        self._append_observation(f"[escalated] {obs}")
        return result

    def reject_escalation(self, esc: EscalationRequest) -> None:
        log.info(f"escalation rejected: {esc.summary()}")
        self._append_observation(
            f"Escalation rejected by user. Continue within {self.level} ceiling."
        )


def _last_think(run: ReActRun) -> Optional[str]:
    for s in reversed(run.steps):
        if s.kind == "think":
            return s.body
    return None


def _format_observation(r: ToolCallResult) -> str:
    status = "OK" if r.ok else ("BLOCKED" if r.blocked else "FAIL")
    return f"{r.tool} {status}: {r.summary}"


_OPEN_TAG_RE = re.compile(r"<(final|escalate)>", re.IGNORECASE)


def _restore_closing_tags(text: str) -> str:
    """If a stop sequence cut off a closing tag, add it back."""
    for m in _OPEN_TAG_RE.finditer(text):
        tag = m.group(1).lower()
        close = f"</{tag}>"
        if close.lower() not in text.lower():
            text = text + close
    return text
