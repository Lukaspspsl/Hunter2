"""
Directory bruteforce module using ffuf.
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

log = get_logger("dir_bruteforce")


@dataclass
class DirectoryFinding:
    """A discovered directory/path."""
    path: str
    status_code: int
    content_length: Optional[int] = None
    content_type: Optional[str] = None
    redirect_url: Optional[str] = None


@dataclass
class DirBruteResult:
    """Results from directory bruteforcing."""
    target: str
    findings: list[DirectoryFinding] = field(default_factory=list)
    
    @property
    def count(self) -> int:
        return len(self.findings)
    
    def add(self, finding: DirectoryFinding) -> None:
        self.findings.append(finding)
    
    def filter_by_status(self, codes: list[int]) -> list[DirectoryFinding]:
        """Filter findings by status code."""
        return [f for f in self.findings if f.status_code in codes]


class DirectoryBruteforcer:
    """Bruteforce directories using ffuf."""
    
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
    
    async def bruteforce(
        self,
        target: str,
        wordlist: Optional[str] = None,
    ) -> DirBruteResult:
        """
        Bruteforce directories on a target.

        Args:
            target: Target URL (e.g., https://example.com)
            wordlist: Custom wordlist path (uses config default if None)

        Returns:
            DirBruteResult with discovered paths
        """
        # Ensure target has protocol
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        # Validate target is reachable before running ffuf
        if not await self._check_target_reachable(target):
            log.warning(f"Target {target} is not reachable, skipping directory bruteforce")
            return DirBruteResult(target=target)

        log.info(f"Starting directory bruteforce for {target}")
        
        result = DirBruteResult(target=target)
        config = self.config.dir_bruteforce.ffuf
        
        if not config.enabled:
            log.info("Directory bruteforce disabled in config")
            return result
        
        if not self.tools.is_available("ffuf"):
            log.warning("ffuf not available, skipping directory bruteforce")
            return result
        
        # Use provided wordlist or config default
        wordlist_path = wordlist or config.wordlist
        
        # Check if wordlist exists, try common locations if absolute path doesn't exist
        wordlist_file = Path(wordlist_path)
        if not wordlist_file.exists():
            # Try relative to project root
            project_wordlist = Path("wordlists") / wordlist_file.name
            if project_wordlist.exists():
                wordlist_path = str(project_wordlist)
            # Try common seclists location
            elif Path("/usr/share/seclists/Discovery/Web-Content/common.txt").exists():
                wordlist_path = "/usr/share/seclists/Discovery/Web-Content/common.txt"
            else:
                log.warning(f"Wordlist not found: {wordlist_path}. Skipping directory bruteforce.")
                log.info("Tip: Download wordlist with: curl -o wordlists/common.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt")
                return result
        
        # Run ffuf
        findings = await self._run_ffuf(
            target=target,
            wordlist=wordlist_path,
            threads=config.threads,
            rate=config.rate,
            extensions=config.extensions,
        )
        
        for finding in findings:
            result.add(finding)
        
        log.info(f"Directory bruteforce complete: {result.count} paths found")
        
        # Save results
        await self._save_results(target, result)
        
        return result
    
    async def _run_ffuf(
        self,
        target: str,
        wordlist: str,
        threads: int = 40,
        rate: int = 100,
        extensions: Optional[list[str]] = None,
    ) -> list[DirectoryFinding]:
        """Run ffuf for directory discovery."""
        findings = []
        
        # Ensure target ends with /FUZZ
        fuzz_url = target.rstrip("/") + "/FUZZ"
        
        # Output file for JSON results
        output_file = self.output_dir / f"ffuf_{self._sanitize_filename(target)}.json"
        
        args = [
            "ffuf",
            "-u", fuzz_url,
            "-w", wordlist,
            "-t", str(threads),
            "-rate", str(rate),
            "-o", str(output_file),
            "-of", "json",
            "-mc", "200,201,204,301,302,307,308,401,403,405",
            "-ac",  # Auto-calibrate filtering
            "-s",   # Silent mode
        ]
        
        # Add custom header if configured
        bug_bounty_header = getattr(self.config.general, 'bug_bounty_header', None)
        if bug_bounty_header:
            # Parse header (format: "Header-Name: value" or "Header-Name:value")
            if ":" in bug_bounty_header:
                header_name, header_value = bug_bounty_header.split(":", 1)
                args.extend(["-H", f"{header_name.strip()}: {header_value.strip()}"])
                log.debug(f"Adding custom header to ffuf: {header_name.strip()}: {header_value.strip()}")
            else:
                log.warning(f"Invalid header format: {bug_bounty_header}, expected 'Header-Name: value'")
        
        # Add extensions if specified
        if extensions:
            ext_str = ",".join(extensions)
            args.extend(["-e", ext_str])
        
        log.debug(f"Running: {' '.join(args)}")
        
        cmd_result = await self.executor.run(
            *args,
            timeout=self.config.dir_bruteforce.ffuf.timeout,  # Use config timeout
            rate_limit=False,  # ffuf has its own rate limiting
            module="FFUF",
        )
        
        # Parse output file
        if output_file.exists():
            try:
                data = json.loads(output_file.read_text())
                results = data.get("results", [])
                
                for item in results:
                    finding = DirectoryFinding(
                        path=item.get("input", {}).get("FUZZ", ""),
                        status_code=item.get("status", 0),
                        content_length=item.get("length"),
                        content_type=item.get("content-type"),
                        redirect_url=item.get("redirectlocation"),
                    )
                    findings.append(finding)
                
                log.info(f"ffuf found {len(findings)} paths")
                
            except json.JSONDecodeError as e:
                log.error(f"Failed to parse ffuf output: {e}")
        else:
            if not cmd_result.success:
                log.error(f"ffuf failed: {cmd_result.stderr}")
        
        return findings
    
    async def _check_target_reachable(self, target: str) -> bool:
        """Check if target DNS resolves (quick pre-flight check)."""
        import socket
        from urllib.parse import urlparse

        try:
            parsed = urlparse(target)
            hostname = parsed.hostname or parsed.path

            # Quick DNS resolution check (not connectivity)
            loop = asyncio.get_event_loop()
            await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname, hostname),
                timeout=3.0
            )
            return True
        except (socket.gaierror, asyncio.TimeoutError, OSError) as e:
            log.debug(f"DNS resolution failed for {target}: {type(e).__name__}")
            return False

    def _sanitize_filename(self, url: str) -> str:
        """Sanitize URL for use in filename."""
        import re
        # Remove protocol and special chars
        name = re.sub(r"https?://", "", url)
        name = re.sub(r"[^\w\-.]", "_", name)
        return name[:100]
    
    async def _save_results(self, target: str, result: DirBruteResult) -> None:
        """Save bruteforce results to file."""
        filename = self._sanitize_filename(target)
        output_file = self.output_dir / f"dirs_{filename}.json"
        
        data = {
            "target": target,
            "total": result.count,
            "findings": [
                {
                    "path": f.path,
                    "status": f.status_code,
                    "length": f.content_length,
                    "type": f.content_type,
                    "redirect": f.redirect_url,
                }
                for f in result.findings
            ],
        }
        
        output_file.write_text(json.dumps(data, indent=2))
        log.debug(f"Results saved to {output_file}")
    
    async def bruteforce_many(
        self,
        targets: list[str],
        max_concurrent: int = 2,
        wordlist: Optional[str] = None,
    ) -> dict[str, DirBruteResult]:
        """Bruteforce multiple targets."""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def brute_with_semaphore(target: str) -> tuple[str, DirBruteResult]:
            async with semaphore:
                result = await self.bruteforce(target, wordlist)
                return target, result
        
        tasks = [brute_with_semaphore(t) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        output = {}
        for r in results:
            if isinstance(r, Exception):
                log.error(f"Bruteforce failed: {r}")
            else:
                target, result = r
                output[target] = result
        
        return output

