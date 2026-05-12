"""Slack notifications.

Two transports:
1. notify binary (ProjectDiscovery) — preferred, lets templates live in YAML
2. raw webhook fallback via httpx — used if notify binary is absent or
   SLACK_WEBHOOK_URL is the only thing configured

The orchestrator emits notifications for new subdomains, critical vulns,
and scope-violation attempts (per programs.yaml notify block).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx

from ..config_loader import ToolDef
from ..core.executor import CommandExecutor
from ..core.logger import get_logger

log = get_logger("notifier")


@dataclass
class NotifyConfig:
    webhook_url: Optional[str] = None
    binary_available: bool = False


class Notifier:
    def __init__(
        self,
        tool: Optional[ToolDef],
        executor: CommandExecutor,
        webhook_url: Optional[str] = None,
    ):
        self.tool = tool
        self.executor = executor
        self.webhook_url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL")

    @property
    def enabled(self) -> bool:
        return bool(self.tool or self.webhook_url)

    async def send(self, title: str, body: str) -> bool:
        if not self.enabled:
            log.debug(f"notifier disabled — would have sent {title!r}")
            return False

        text = f"*{title}*\n{body}"

        # prefer notify CLI when present
        if self.tool:
            res = await self.executor.run(
                self.tool.binary, "-bulk",
                timeout=self.tool.timeout, module="NOTIFY",
                rate_limit=False,
            )
            if res.success:
                log.info(f"notify sent: {title}")
                return True
            log.warning(f"notify binary failed (exit={res.returncode}), falling back to webhook")

        if not self.webhook_url:
            return False
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(self.webhook_url, json={"text": text})
                if resp.status_code >= 300:
                    log.warning(f"slack webhook returned {resp.status_code}")
                    return False
        except Exception as e:
            log.warning(f"slack webhook error: {e}")
            return False
        log.info(f"slack webhook sent: {title}")
        return True

    async def new_subdomains(self, program: str, domains: list[str]) -> None:
        if not domains:
            return
        body = "\n".join(f"• `{d}`" for d in domains[:25])
        if len(domains) > 25:
            body += f"\n…and {len(domains) - 25} more"
        await self.send(f"[{program}] {len(domains)} new subdomains", body)

    async def critical_vuln(self, program: str, name: str, target: str, severity: str) -> None:
        await self.send(
            f"[{program}] {severity.upper()} vulnerability",
            f"*{name}* on `{target}`",
        )

    async def scope_violation_attempt(self, program: str, tool: str, target: str, reason: str) -> None:
        await self.send(
            f"[{program}] BLOCKED scope-violation attempt",
            f"tool=`{tool}` target=`{target}`\nreason: {reason}",
        )
