"""
Vulnerability scanning module using Nuclei.
"""

import asyncio
import json
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from ..core.executor import CommandExecutor
from ..core.logger import get_logger
from ..config_loader import HunterConfig
from ..tool_checker import ToolChecker

log = get_logger("vuln_scanner")


@dataclass
class VulnFinding:
    """A vulnerability finding from Nuclei."""
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    description: Optional[str] = None
    reference: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    extracted_results: Optional[list[str]] = None
    curl_command: Optional[str] = None


@dataclass
class VulnScanResult:
    """Results from vulnerability scanning."""
    targets_scanned: int = 0
    findings: list[VulnFinding] = field(default_factory=list)
    
    @property
    def total(self) -> int:
        return len(self.findings)
    
    @property
    def critical(self) -> list[VulnFinding]:
        return [f for f in self.findings if f.severity.lower() == "critical"]
    
    @property
    def high(self) -> list[VulnFinding]:
        return [f for f in self.findings if f.severity.lower() == "high"]
    
    @property
    def medium(self) -> list[VulnFinding]:
        return [f for f in self.findings if f.severity.lower() == "medium"]
    
    def add(self, finding: VulnFinding) -> None:
        self.findings.append(finding)
    
    def by_severity(self) -> dict[str, list[VulnFinding]]:
        """Group findings by severity."""
        result = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in self.findings:
            sev = f.severity.lower()
            if sev in result:
                result[sev].append(f)
        return result


class VulnerabilityScanner:
    """Scan for vulnerabilities using Nuclei."""
    
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
        targets: list[str],
        severity: Optional[list[str]] = None,
    ) -> VulnScanResult:
        """
        Scan targets for vulnerabilities.
        
        Args:
            targets: List of URLs to scan
            severity: Severity levels to include (uses config default if None)
            
        Returns:
            VulnScanResult with all findings
        """
        if not self.tools.is_available("nuclei"):
            log.error("nuclei not available, cannot perform vulnerability scan")
            return VulnScanResult()
        
        config = self.config.vuln_scan.nuclei
        
        if not config.enabled:
            log.info("Vulnerability scanning disabled in config")
            return VulnScanResult()
        
        if not targets:
            log.warning("No targets provided for vulnerability scan")
            return VulnScanResult()

        # Filter out unresolvable targets before running nuclei
        reachable = []
        for target in targets:
            if await self._check_target_reachable(target):
                reachable.append(target)
            else:
                log.warning(f"Target {target} does not resolve, skipping vulnerability scan")

        if not reachable:
            log.warning("No reachable targets, skipping vulnerability scan")
            return VulnScanResult()

        targets = reachable

        # Use provided severity or config default
        severity = severity or config.severity
        
        log.info(f"Starting vulnerability scan on {len(targets)} targets")
        log.info(f"Severity filter: {', '.join(severity)}")
        
        result = VulnScanResult(targets_scanned=len(targets))
        
        findings = await self._run_nuclei(
            targets=targets,
            severity=severity,
            rate_limit=config.rate_limit,
            templates=config.templates,
        )
        
        for finding in findings:
            result.add(finding)
        
        # Log summary
        by_sev = result.by_severity()
        log.info(f"Vulnerability scan complete: {result.total} findings")
        for sev, findings in by_sev.items():
            if findings:
                log.info(f"  {sev.upper()}: {len(findings)}")
        
        # Save results
        await self._save_results(result)
        
        return result
    
    async def _run_nuclei(
        self,
        targets: list[str],
        severity: list[str],
        rate_limit: int = 150,
        templates: Optional[list[str]] = None,
    ) -> list[VulnFinding]:
        """Run Nuclei scanner."""
        findings = []
        
        # Write targets to file
        targets_file = self.output_dir / "nuclei_targets.txt"
        targets_file.write_text("\n".join(targets))
        
        # Output file
        output_file = self.output_dir / "nuclei_output.jsonl"
        
        args = [
            "nuclei",
            "-l", str(targets_file),        # Target list
            "-severity", ",".join(severity), # Severity filter
            "-rate-limit", str(rate_limit),  # Rate limit
            "-jsonl",                        # JSON lines output
            "-o", str(output_file),          # Output file
            "-silent",                       # Silent mode
            "-nc",                           # No color
        ]
        
        # Add custom header if configured
        bug_bounty_header = getattr(self.config.general, 'bug_bounty_header', None)
        if bug_bounty_header:
            # Parse header (format: "Header-Name: value" or "Header-Name:value")
            if ":" in bug_bounty_header:
                header_name, header_value = bug_bounty_header.split(":", 1)
                args.extend(["-H", f"{header_name.strip()}: {header_value.strip()}"])
                log.debug(f"Adding custom header to nuclei: {header_name.strip()}: {header_value.strip()}")
            else:
                log.warning(f"Invalid header format: {bug_bounty_header}, expected 'Header-Name: value'")
        
        # Add template categories if specified
        if templates:
            for template in templates:
                args.extend(["-t", template])
        
        log.debug(f"Running: {' '.join(args)}")
        
        cmd_result = await self.executor.run(
            *args,
            timeout=self.config.vuln_scan.nuclei.timeout,  # Use config timeout
            rate_limit=False,
            module="NUCLEI",
        )
        
        # Parse output
        if output_file.exists() and output_file.stat().st_size > 0:
            findings = self._parse_nuclei_output(output_file)
            log.info(f"nuclei found {len(findings)} vulnerabilities")
        else:
            if not cmd_result.success:
                error_msg = cmd_result.stderr or cmd_result.stdout or "Unknown error"
                log.error(f"nuclei failed: {error_msg}")
            elif output_file.exists() and output_file.stat().st_size == 0:
                log.debug("nuclei completed but found no vulnerabilities")
            else:
                log.warning("nuclei output file not created - scan may have failed silently")
        
        return findings
    
    def _parse_nuclei_output(self, output_file: Path) -> list[VulnFinding]:
        """Parse Nuclei JSON lines output."""
        findings = []
        
        try:
            with open(output_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        
                        finding = VulnFinding(
                            template_id=data.get("template-id", ""),
                            name=data.get("info", {}).get("name", "Unknown"),
                            severity=data.get("info", {}).get("severity", "unknown"),
                            host=data.get("host", ""),
                            matched_at=data.get("matched-at", ""),
                            description=data.get("info", {}).get("description"),
                            reference=data.get("info", {}).get("reference"),
                            tags=data.get("info", {}).get("tags"),
                            extracted_results=data.get("extracted-results"),
                            curl_command=data.get("curl-command"),
                        )
                        
                        findings.append(finding)
                        
                        # Log high/critical findings immediately
                        if finding.severity.lower() in ["critical", "high"]:
                            log.warning(
                                f"[{finding.severity.upper()}] {finding.name} at {finding.matched_at}"
                            )
                        
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            log.error(f"Failed to parse nuclei output: {e}")
        
        return findings
    
    async def _check_target_reachable(self, target: str) -> bool:
        """Check if target DNS resolves (quick pre-flight check)."""
        try:
            parsed = urlparse(target)
            hostname = parsed.hostname or parsed.path
            loop = asyncio.get_event_loop()
            await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname, hostname),
                timeout=3.0,
            )
            return True
        except (socket.gaierror, asyncio.TimeoutError, OSError) as e:
            log.debug(f"DNS resolution failed for {target}: {type(e).__name__}")
            return False

    async def _save_results(self, result: VulnScanResult) -> None:
        """Save scan results to JSON."""
        output_file = self.output_dir / "vuln_scan_results.json"
        
        data = {
            "targets_scanned": result.targets_scanned,
            "total_findings": result.total,
            "by_severity": {
                sev: len(findings)
                for sev, findings in result.by_severity().items()
            },
            "findings": [
                {
                    "template_id": f.template_id,
                    "name": f.name,
                    "severity": f.severity,
                    "host": f.host,
                    "matched_at": f.matched_at,
                    "description": f.description,
                    "reference": f.reference,
                    "tags": f.tags,
                }
                for f in result.findings
            ],
        }
        
        output_file.write_text(json.dumps(data, indent=2))
        log.debug(f"Results saved to {output_file}")
    
    async def scan_with_custom_templates(
        self,
        targets: list[str],
        template_paths: list[str],
        severity: Optional[list[str]] = None,
    ) -> VulnScanResult:
        """Scan with custom Nuclei templates."""
        if not self.tools.is_available("nuclei"):
            log.error("nuclei not available")
            return VulnScanResult()
        
        config = self.config.vuln_scan.nuclei
        severity = severity or config.severity
        
        result = VulnScanResult(targets_scanned=len(targets))
        
        # Write targets to file
        targets_file = self.output_dir / "nuclei_targets.txt"
        targets_file.write_text("\n".join(targets))
        
        output_file = self.output_dir / "nuclei_custom_output.jsonl"
        
        args = [
            "nuclei",
            "-l", str(targets_file),
            "-severity", ",".join(severity),
            "-jsonl",
            "-o", str(output_file),
            "-silent",
        ]
        
        # Add custom template paths
        for path in template_paths:
            args.extend(["-t", path])
        
        await self.executor.run(
            *args,
            timeout=self.config.vuln_scan.nuclei.timeout,
            rate_limit=False,
            module="NUCLEI",
        )
        
        if output_file.exists():
            for finding in self._parse_nuclei_output(output_file):
                result.add(finding)
        
        return result

