"""
Subdomain enumeration module.
Uses subfinder, amass, and assetfinder.
"""

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..core.executor import CommandExecutor, CommandResult
from ..core.logger import get_logger
from ..config_loader import HunterConfig
from ..tool_checker import ToolChecker
from .crtsh import CrtshEnumerator

log = get_logger("subdomain_enum")


def _get_config_value(config, key: str, default=None):
    """Get a config value from either a dict or Pydantic model."""
    if isinstance(config, dict):
        return config.get(key, default)
    return getattr(config, key, default)


@dataclass
class SubdomainResult:
    """Result from subdomain enumeration."""
    domain: str
    subdomains: set[str] = field(default_factory=set)
    sources: dict[str, set[str]] = field(default_factory=dict)  # tool -> subdomains
    
    def add(self, subdomain: str, source: str) -> None:
        """Add a subdomain from a source."""
        subdomain = subdomain.strip().lower()
        if subdomain:
            self.subdomains.add(subdomain)
            if source not in self.sources:
                self.sources[source] = set()
            self.sources[source].add(subdomain)
    
    def merge(self, other: "SubdomainResult") -> None:
        """Merge results from another enumeration."""
        self.subdomains.update(other.subdomains)
        for source, subs in other.sources.items():
            if source not in self.sources:
                self.sources[source] = set()
            self.sources[source].update(subs)


class SubdomainEnumerator:
    """Enumerate subdomains using multiple tools."""
    
    def __init__(
        self,
        config: HunterConfig,
        tools: ToolChecker,
        executor: CommandExecutor,
        output_dir: Optional[Path] = None,
    ):
        self.config = config
        self.tools = tools
        self.executor = executor
        self.output_dir = output_dir or Path("./data/raw_results")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize crt.sh enumerator
        self.crtsh = CrtshEnumerator(config, output_dir)
    
    async def enumerate(self, target: str) -> SubdomainResult:
        """
        Enumerate subdomains for a target domain.
        
        Args:
            target: Target domain (e.g., example.com or *.example.com)
            
        Returns:
            SubdomainResult with all discovered subdomains
        """
        # Clean target
        domain = target.replace("*.", "").strip()
        log.info(f"Starting enumeration for {domain}")
        
        result = SubdomainResult(domain=domain)
        config = self.config.subdomain_enum
        
        if not config.enabled:
            log.info("Subdomain enumeration disabled in config")
            return result
        
        # Run enabled tools concurrently
        tasks = []

        # Helper to check if tool is enabled (handles both dict and Pydantic model)
        def is_tool_enabled(tool_name: str) -> bool:
            tool_cfg = config.tools.get(tool_name)
            if tool_cfg is None:
                return False
            if isinstance(tool_cfg, dict):
                return tool_cfg.get("enabled", True)
            return getattr(tool_cfg, "enabled", True)

        if is_tool_enabled("subfinder"):
            if self.tools.is_available("subfinder"):
                tasks.append(self._run_subfinder(domain, config.tools["subfinder"]))
            else:
                log.warning("subfinder not available, skipping")

        if is_tool_enabled("amass"):
            if self.tools.is_available("amass"):
                tasks.append(self._run_amass(domain, config.tools["amass"]))
            else:
                log.warning("amass not available, skipping")

        if is_tool_enabled("assetfinder"):
            if self.tools.is_available("assetfinder"):
                tasks.append(self._run_assetfinder(domain, config.tools["assetfinder"]))
            else:
                log.warning("assetfinder not available, skipping")
        
        # Add crt.sh (no external tool needed, uses HTTP API)
        if config.crtsh.enabled:
            tasks.append(self._run_crtsh(domain))
        
        if not tasks:
            log.error("No subdomain enumeration tools available!")
            return result
        
        # Run all tools concurrently
        tool_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for tool_result in tool_results:
            if isinstance(tool_result, Exception):
                # Log error but continue - don't fail entire scan if one tool fails
                if "Timeout" in str(tool_result) or "timed out" in str(tool_result).lower():
                    log.warning(f"Tool timed out (this is normal for slow tools like amass): {tool_result}")
                else:
                    log.error(f"Tool failed with exception: {tool_result}")
            elif isinstance(tool_result, SubdomainResult):
                result.merge(tool_result)
        
        log.info(f"Enumeration complete: {len(result.subdomains)} unique subdomains")
        
        # Log per-tool stats
        for source, subs in result.sources.items():
            log.debug(f"  {source}: {len(subs)} subdomains")
        
        # Save raw results
        await self._save_results(domain, result)
        
        return result
    
    async def _run_subfinder(self, domain: str, config) -> SubdomainResult:
        """Run subfinder for subdomain enumeration."""
        log.info(f"Running subfinder for {domain}")

        result = SubdomainResult(domain=domain)
        threads = _get_config_value(config, "threads", 10)
        timeout = _get_config_value(config, "timeout", 300)
        
        cmd_result = await self.executor.run(
            "subfinder",
            "-d", domain,
            "-silent",
            "-t", str(threads),
            timeout=timeout,
            module="SUBDOMAIN",
        )
        
        if cmd_result.success:
            for line in cmd_result.stdout.strip().split("\n"):
                subdomain = line.strip()
                if subdomain and self._is_valid_subdomain(subdomain, domain):
                    result.add(subdomain, "subfinder")
            
            log.info(f"subfinder found {len(result.subdomains)} subdomains")
        else:
            log.error(f"subfinder failed: {cmd_result.stderr}")
        
        return result
    
    async def _run_amass(self, domain: str, config) -> SubdomainResult:
        """Run amass for subdomain enumeration."""
        log.info(f"Running amass for {domain}")

        result = SubdomainResult(domain=domain)
        passive_only = _get_config_value(config, "passive_only", True)
        timeout = _get_config_value(config, "timeout", 600)
        
        args = ["amass", "enum", "-d", domain]
        if passive_only:
            args.append("-passive")
        
        cmd_result = await self.executor.run(
            *args,
            timeout=timeout,
            module="SUBDOMAIN",
        )
        
        if cmd_result.success:
            for line in cmd_result.stdout.strip().split("\n"):
                subdomain = line.strip()
                if subdomain and self._is_valid_subdomain(subdomain, domain):
                    result.add(subdomain, "amass")
            
            log.info(f"amass found {len(result.subdomains)} subdomains")
        else:
            log.error(f"amass failed: {cmd_result.stderr}")
        
        return result
    
    async def _run_assetfinder(self, domain: str, config) -> SubdomainResult:
        """Run assetfinder for subdomain enumeration."""
        log.info(f"Running assetfinder for {domain}")

        result = SubdomainResult(domain=domain)
        subs_only = _get_config_value(config, "subs_only", True)
        
        args = ["assetfinder"]
        if subs_only:
            args.append("--subs-only")
        args.append(domain)
        
        cmd_result = await self.executor.run(
            *args,
            timeout=300,
            module="SUBDOMAIN",
        )
        
        if cmd_result.success:
            for line in cmd_result.stdout.strip().split("\n"):
                subdomain = line.strip()
                if subdomain and self._is_valid_subdomain(subdomain, domain):
                    result.add(subdomain, "assetfinder")
            
            log.info(f"assetfinder found {len(result.subdomains)} subdomains")
        else:
            log.error(f"assetfinder failed: {cmd_result.stderr}")
        
        return result
    
    async def _run_crtsh(self, domain: str) -> SubdomainResult:
        """Run crt.sh for subdomain enumeration."""
        result = SubdomainResult(domain=domain)
        
        try:
            crtsh_result = await self.crtsh.enumerate(domain)
            for subdomain in crtsh_result.subdomains:
                result.add(subdomain, "crtsh")
        except Exception as e:
            log.error(f"crt.sh failed for {domain}: {e}")
        
        return result
    
    def _is_valid_subdomain(self, subdomain: str, parent_domain: str) -> bool:
        """Check if a subdomain belongs to the parent domain."""
        subdomain = subdomain.lower().strip()
        parent_domain = parent_domain.lower().strip()
        
        # Must end with parent domain
        if not subdomain.endswith(parent_domain):
            return False
        
        # Basic validation
        if len(subdomain) > 253:
            return False
        
        # No wildcards or special chars
        if "*" in subdomain or " " in subdomain:
            return False
        
        return True
    
    async def _save_results(self, domain: str, result: SubdomainResult) -> None:
        """Save enumeration results to file."""
        output_file = self.output_dir / f"subdomains_{domain.replace('.', '_')}.json"
        
        data = {
            "domain": domain,
            "total": len(result.subdomains),
            "subdomains": sorted(list(result.subdomains)),
            "sources": {k: sorted(list(v)) for k, v in result.sources.items()},
        }
        
        output_file.write_text(json.dumps(data, indent=2))
        log.debug(f"Results saved to {output_file}")
    
    async def enumerate_many(
        self,
        targets: list[str],
        max_concurrent: int = 3,
    ) -> dict[str, SubdomainResult]:
        """
        Enumerate subdomains for multiple targets.
        
        Args:
            targets: List of target domains
            max_concurrent: Maximum concurrent enumerations
            
        Returns:
            Dictionary of domain -> SubdomainResult
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def enum_with_semaphore(target: str) -> tuple[str, SubdomainResult]:
            async with semaphore:
                result = await self.enumerate(target)
                return target, result
        
        tasks = [enum_with_semaphore(t) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        output = {}
        for r in results:
            if isinstance(r, Exception):
                log.error(f"Enumeration failed: {r}")
            else:
                target, result = r
                output[target] = result
        
        return output
    
    async def close(self) -> None:
        """Cleanup resources."""
        await self.crtsh.close()

