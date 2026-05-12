"""Scope engine — hard gate for active operations + OOS tagger.

Invariant: every active tool MUST call assert_in_scope() before subprocess.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, Optional
from urllib.parse import urlparse

from .logger import get_logger

log = get_logger("scope_engine")


class ScopeViolationError(Exception):
    """Raised when an OOS target reaches an active tool."""


@dataclass(frozen=True)
class OOSTarget:
    target: str
    reason: str


def _strip(target: str) -> str:
    """Normalize a target to host or CIDR — drop scheme, path, port."""
    t = target.strip().lower()
    if "://" in t:
        t = urlparse(t).hostname or t
    # strip trailing slashes/paths
    t = t.split("/")[0]
    # strip explicit port
    if t.count(":") == 1 and not _is_ip(t):
        t = t.split(":")[0]
    return t


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return "/" in value
    except ValueError:
        return False


def _matches_pattern(target: str, pattern: str) -> bool:
    """Match host against glob pattern or CIDR."""
    target = target.lower()
    pattern = pattern.lower().strip()

    if _is_cidr(pattern):
        if not _is_ip(target):
            return False
        net = ipaddress.ip_network(pattern, strict=False)
        return ipaddress.ip_address(target) in net

    if _is_ip(pattern) and _is_ip(target):
        return target == pattern

    # glob match — fnmatch handles *.example.com style
    if fnmatch.fnmatchcase(target, pattern):
        return True
    # bare-domain pattern should also match exact host (e.g. "bose.com" matches "bose.com")
    return target == pattern


class ScopeEngine:
    """Per-program scope evaluator.

    program_config schema (from programs.yaml):
        in_scope: list[str]        domains / CIDRs / glob patterns
        out_of_scope: list[str]    explicit exclusions, checked FIRST
    """

    def __init__(
        self,
        program_name: str,
        in_scope: Iterable[str],
        out_of_scope: Iterable[str] | None = None,
    ):
        self.program_name = program_name
        self.in_scope_patterns: list[str] = [p.strip() for p in in_scope if p.strip()]
        self.oos_patterns: list[str] = [p.strip() for p in (out_of_scope or []) if p.strip()]

    @classmethod
    def from_program_config(cls, name: str, cfg: dict) -> "ScopeEngine":
        return cls(
            program_name=name,
            in_scope=cfg.get("in_scope", []),
            out_of_scope=cfg.get("out_of_scope", []),
        )

    def is_in_scope(self, target: str) -> tuple[bool, Optional[str]]:
        """Return (in_scope, reason_if_oos)."""
        host = _strip(target)
        if not host:
            return False, "empty target"

        # OOS rules override in_scope
        for pat in self.oos_patterns:
            if _matches_pattern(host, pat):
                return False, f"matches OOS pattern '{pat}'"

        for pat in self.in_scope_patterns:
            if _matches_pattern(host, pat):
                return True, None

        return False, "no in-scope pattern matched"

    def filter_targets(
        self, targets: Iterable[str]
    ) -> tuple[list[str], list[OOSTarget]]:
        """Split targets into in-scope and OOS-tagged."""
        in_scope: list[str] = []
        oos: list[OOSTarget] = []
        for t in targets:
            ok, reason = self.is_in_scope(t)
            if ok:
                in_scope.append(t)
            else:
                oos.append(OOSTarget(target=t, reason=reason or "unknown"))
        if oos:
            log.warning(
                f"[{self.program_name}] filtered {len(oos)} OOS targets out of "
                f"{len(in_scope) + len(oos)} total"
            )
        return in_scope, oos

    def assert_in_scope(self, target: str) -> None:
        """Raise ScopeViolationError if target is OOS. Call before every subprocess."""
        ok, reason = self.is_in_scope(target)
        if not ok:
            log.error(
                f"[{self.program_name}] SCOPE VIOLATION blocked: {target} — {reason}"
            )
            raise ScopeViolationError(
                f"target '{target}' is out of scope for program "
                f"'{self.program_name}': {reason}"
            )
