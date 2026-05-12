"""
Secret scanning module using TruffleHog.
Scans Git repositories for exposed secrets.
"""

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..core.executor import CommandExecutor
from ..core.logger import get_logger
from ..config_loader import HunterConfig
from ..tool_checker import ToolChecker

log = get_logger("secret_scanner")


@dataclass
class SecretFinding:
    """A discovered secret."""
    source: str  # trufflehog
    secret_type: str
    file_path: Optional[str] = None
    repository: Optional[str] = None
    commit_hash: Optional[str] = None
    branch: Optional[str] = None
    line_number: Optional[int] = None
    secret_preview: Optional[str] = None  # Redacted preview
    match: Optional[str] = None
    
    def redact_preview(self, max_length: int = 20) -> str:
        """Create a redacted preview of the secret."""
        if not self.match:
            return "***REDACTED***"
        
        if len(self.match) <= 8:
            return "***"
        
        # Show first 3 and last 3 characters
        return f"{self.match[:3]}***{self.match[-3:]}"


@dataclass
class SecretScanResult:
    """Results from secret scanning."""
    target: str
    findings: list[SecretFinding] = field(default_factory=list)
    
    @property
    def count(self) -> int:
        return len(self.findings)
    
    def add(self, finding: SecretFinding) -> None:
        """Add a finding with redacted preview."""
        finding.secret_preview = finding.redact_preview()
        self.findings.append(finding)


class SecretScanner:
    """Scan for exposed secrets using TruffleHog."""
    
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
    
    async def scan(
        self,
        target: str,
        repo_url: Optional[str] = None,
    ) -> SecretScanResult:
        """
        Scan for secrets related to a target.
        
        Args:
            target: Target domain or organization name
            repo_url: Optional specific repository URL to scan
            
        Returns:
            SecretScanResult with all findings
        """
        log.info(f"Starting secret scan for {target}")
        
        result = SecretScanResult(target=target)
        config = self.config.secrets
        
        # If no repo_url provided, try to construct GitHub URLs from target
        if not repo_url:
            # Try common GitHub organization patterns
            repo_urls = self._generate_repo_urls(target)
            if repo_urls:
                log.info(f"Generated {len(repo_urls)} potential repository URLs for {target}")
                for url in repo_urls:
                    if config.trufflehog.enabled and self.tools.is_available("trufflehog"):
                        findings = await self._run_trufflehog(url, config.trufflehog)
                        result.findings.extend(findings)
            else:
                log.warning(f"No repository URLs found for {target}. Provide repo_url to scan specific repositories.")
        else:
            # Scan the provided repository URL
            if config.trufflehog.enabled and self.tools.is_available("trufflehog"):
                findings = await self._run_trufflehog(repo_url, config.trufflehog)
                result.findings.extend(findings)
            else:
                log.warning("trufflehog not available or disabled, skipping secret scan")
        
        if result.count == 0 and not config.trufflehog.enabled:
            log.warning("Secret scanning is disabled in configuration")
        elif result.count == 0 and not self.tools.is_available("trufflehog"):
            log.warning("trufflehog not available, cannot perform secret scan")
        
        log.info(f"Secret scan complete: {result.count} findings")
        
        # Save results
        await self._save_results(target, result)
        
        return result
    
    def _generate_repo_urls(self, target: str) -> list[str]:
        """
        Generate potential GitHub repository URLs from a target domain.
        
        This is a simple heuristic - in practice, you might want to use
        GitHub API to search for repositories belonging to the organization.
        """
        repo_urls = []
        
        # Extract organization name from domain
        # e.g., "example.com" -> "example"
        org_name = target.split(".")[0]
        
        # Common GitHub URL patterns
        patterns = [
            f"https://github.com/{org_name}/{org_name}",
            f"https://github.com/{org_name}/{org_name}-api",
            f"https://github.com/{org_name}/{org_name}-backend",
            f"https://github.com/{org_name}/{org_name}-frontend",
            f"https://github.com/{org_name}/www",
            f"https://github.com/{org_name}/website",
        ]
        
        # Also try the full domain as org name
        if "." in target:
            domain_org = target.replace(".", "-")
            patterns.extend([
                f"https://github.com/{domain_org}/{domain_org}",
            ])
        
        return patterns
    
    async def _run_trufflehog(
        self,
        repo_url: str,
        config,
    ) -> list[SecretFinding]:
        """Run TruffleHog on a repository."""
        log.info(f"Running trufflehog on {repo_url}")
        
        findings = []
        output_file = self.output_dir / f"trufflehog_{self._sanitize_repo_name(repo_url)}.json"
        
        # Build trufflehog command
        args = [
            "trufflehog",
            repo_url,
            "--json",
        ]
        
        # Add configuration options
        # Note: Python trufflehog (v2.2.1) requires values for --entropy flag
        # The value should be a boolean string ("true" or "false")
        if config.entropy:
            args.extend(["--entropy", "true"])  # Enable entropy checks
        
        if config.regex:
            args.append("--regex")  # regex is a flag without value
        
        if config.max_depth:
            args.extend(["--max_depth", str(config.max_depth)])
        
        if config.branch:
            args.extend(["--branch", config.branch])
        
        log.debug(f"Running: {' '.join(args)}")
        
        # Run trufflehog and capture output
        cmd_result = await self.executor.run(
            *args,
            timeout=600,  # 10 minute timeout
            rate_limit=False,
            module="SECRETS",
        )
        
        # Check if command failed
        if not cmd_result.success:
            # Exit code 1 might mean no secrets found (which is OK)
            if cmd_result.returncode == 1:
                log.debug(f"trufflehog completed for {repo_url} with no findings (exit code 1)")
            else:
                log.warning(f"trufflehog failed for {repo_url} (exit code {cmd_result.returncode}): {cmd_result.stderr or 'Unknown error'}")
            return findings
        
        # Parse JSON output (trufflehog outputs JSON lines)
        if cmd_result.stdout:
            try:
                for line in cmd_result.stdout.strip().split("\n"):
                    if line.strip():
                        try:
                            item = json.loads(line)
                            finding = SecretFinding(
                                source="trufflehog",
                                secret_type=item.get("reason", "unknown"),
                                file_path=item.get("path"),
                                commit_hash=item.get("commitHash"),
                                branch=item.get("branch"),
                                line_number=item.get("lineNumber"),
                                match=item.get("stringsFound", [""])[0] if item.get("stringsFound") else None,
                                repository=repo_url,
                            )
                            findings.append(finding)
                        except json.JSONDecodeError:
                            # Skip invalid JSON lines
                            continue
                
                log.info(f"trufflehog found {len(findings)} secrets in {repo_url}")
                
            except Exception as e:
                log.error(f"Failed to parse trufflehog output: {e}")
        
        # Also check if trufflehog wrote to a file (some versions do)
        if output_file.exists():
            try:
                data = json.loads(output_file.read_text())
                if isinstance(data, list):
                    for item in data:
                        finding = SecretFinding(
                            source="trufflehog",
                            secret_type=item.get("reason", "unknown"),
                            file_path=item.get("path"),
                            commit_hash=item.get("commitHash"),
                            branch=item.get("branch"),
                            line_number=item.get("lineNumber"),
                            match=item.get("stringsFound", [""])[0] if item.get("stringsFound") else None,
                            repository=repo_url,
                        )
                        findings.append(finding)
            except json.JSONDecodeError as e:
                log.error(f"Failed to parse trufflehog output file: {e}")
        
        return findings
    
    def _sanitize_repo_name(self, repo_url: str) -> str:
        """Sanitize repository URL for use in filenames."""
        return repo_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_")
    
    async def _save_results(self, target: str, result: SecretScanResult) -> None:
        """Save scan results to file."""
        output_file = self.output_dir / f"secrets_{target.replace('.', '_')}.json"
        
        data = {
            "target": target,
            "total": result.count,
            "findings": [
                {
                    "source": f.source,
                    "type": f.secret_type,
                    "file": f.file_path,
                    "repo": f.repository,
                    "commit": f.commit_hash,
                    "branch": f.branch,
                    "line": f.line_number,
                    "preview": f.secret_preview,
                }
                for f in result.findings
            ],
        }
        
        output_file.write_text(json.dumps(data, indent=2))
        log.debug(f"Results saved to {output_file}")
    
    async def scan_repositories(
        self,
        repo_urls: list[str],
        max_concurrent: int = 2,
    ) -> list[SecretScanResult]:
        """Scan multiple repositories for secrets."""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_with_semaphore(url: str) -> SecretScanResult:
            async with semaphore:
                return await self.scan(url, repo_url=url)
        
        tasks = [scan_with_semaphore(url) for url in repo_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = []
        for r in results:
            if isinstance(r, Exception):
                log.error(f"Repository scan failed: {r}")
            else:
                valid_results.append(r)
        
        return valid_results
