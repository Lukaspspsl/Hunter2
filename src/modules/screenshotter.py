"""
Screenshot module using gowitness.
"""

import asyncio
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..core.executor import CommandExecutor
from ..core.logger import get_logger
from ..config_loader import HunterConfig
from ..tool_checker import ToolChecker

log = get_logger("screenshotter")


@dataclass
class ScreenshotInfo:
    """Information about a screenshot."""
    url: str
    file_path: str
    response_code: Optional[int] = None
    title: Optional[str] = None
    final_url: Optional[str] = None
    content_length: Optional[int] = None


@dataclass
class ScreenshotResult:
    """Results from screenshot capture."""
    screenshots: list[ScreenshotInfo] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    
    @property
    def success_count(self) -> int:
        return len(self.screenshots)
    
    @property
    def fail_count(self) -> int:
        return len(self.failed)
    
    def add(self, screenshot: ScreenshotInfo) -> None:
        self.screenshots.append(screenshot)
    
    def add_failed(self, url: str) -> None:
        self.failed.append(url)


class Screenshotter:
    """Capture screenshots using gowitness."""
    
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
        self.output_dir = output_dir or Path("./data/screenshots")
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    async def capture(self, targets: list[str], scan_output_dir: Optional[Path] = None) -> ScreenshotResult:
        """
        Capture screenshots of targets.
        
        Args:
            targets: List of URLs to screenshot
            scan_output_dir: Optional scan-specific output directory (if None, uses default)
            
        Returns:
            ScreenshotResult with captured screenshots
        """
        if not self.tools.is_available("gowitness"):
            log.warning("gowitness not available, skipping screenshots")
            return ScreenshotResult()
        
        config = self.config.screenshots.gowitness
        
        if not config.enabled:
            log.info("Screenshots disabled in config")
            return ScreenshotResult()
        
        if not targets:
            log.warning("No targets provided for screenshots")
            return ScreenshotResult()
        
        # Use scan-specific directory if provided, otherwise use default
        output_dir = scan_output_dir if scan_output_dir else self.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        
        log.info(f"Starting screenshot capture for {len(targets)} targets")
        
        result = await self._run_gowitness(
            targets=targets,
            threads=config.threads,
            timeout=config.timeout,
            output_dir=output_dir,
        )
        
        log.info(f"Screenshots complete: {result.success_count} captured, {result.fail_count} failed")
        
        # Save results metadata
        await self._save_results(result, output_dir)
        
        return result
    
    async def _run_gowitness(
        self,
        targets: list[str],
        threads: int = 4,
        timeout: int = 30,
        output_dir: Optional[Path] = None,
    ) -> ScreenshotResult:
        """Run gowitness for screenshot capture."""
        result = ScreenshotResult()
        
        # Use provided output_dir or fall back to instance default
        scan_output_dir = output_dir if output_dir else self.output_dir
        scan_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Ensure all targets have protocol
        urls = []
        for target in targets:
            if not target.startswith(("http://", "https://")):
                urls.append(f"https://{target}")
            else:
                urls.append(target)
        
        # Write targets to file
        targets_file = scan_output_dir / "gowitness_targets.txt"
        targets_file.write_text("\n".join(urls))
        
        # Database for gowitness results
        db_path = scan_output_dir / "gowitness.sqlite3"
        
        args = [
            "gowitness",
            "scan",
            "file",
            "-f", str(targets_file),
            "--screenshot-path", str(scan_output_dir),           # Screenshot path
            "--write-db-uri", f"sqlite://{db_path}",              # Database URI
            "--write-db",                                          # Write to database
            "-q",                                                  # Quiet mode
        ]
        # Note: gowitness v3 doesn't support --threads flag, concurrency is handled internally
        # Note: gowitness doesn't support custom headers directly
        # For bug bounty programs requiring headers, use a proxy (Burp/ZAP) with header injection
        
        bug_bounty_header = getattr(self.config.general, 'bug_bounty_header', None)
        if bug_bounty_header:
            log.warning("gowitness doesn't support custom headers. Consider using a proxy (Burp/ZAP) with header injection for bug bounty compliance.")
        
        log.debug(f"Running: {' '.join(args)}")
        
        cmd_result = await self.executor.run(
            *args,
            timeout=3600,  # 1 hour total timeout
            rate_limit=False,
            module="GOWITNESS",
        )
        
        # Parse results from gowitness database
        if db_path.exists() and db_path.stat().st_size > 0:
            try:
                result = self._parse_gowitness_db(db_path, scan_output_dir)
            except sqlite3.Error as e:
                log.error(f"Failed to parse gowitness database: {e}")
                # Check if command succeeded but database is empty/invalid
                if cmd_result.success:
                    log.info("gowitness completed but database is empty or invalid - no screenshots captured")
                else:
                    error_msg = cmd_result.stderr or cmd_result.stdout or "Unknown error"
                    log.error(f"gowitness failed: {error_msg}")
                    # Mark all targets as failed
                    for url in urls:
                        result.add_failed(url)
        else:
            # Database not created - check if command failed
            if not cmd_result.success:
                error_msg = cmd_result.stderr or cmd_result.stdout or "Database not created"
                log.error(f"gowitness failed: {error_msg}")
            else:
                log.info("gowitness completed but no database was created - no screenshots captured")
            # Mark all targets as failed
            for url in urls:
                result.add_failed(url)
        
        return result
    
    def _parse_gowitness_db(self, db_path: Path, output_dir: Path) -> ScreenshotResult:
        """Parse gowitness SQLite database for results."""
        result = ScreenshotResult()
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Check if urls table exists
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='urls'
            """)
            if not cursor.fetchone():
                log.warning("gowitness database exists but 'urls' table not found - database may be empty or schema changed")
                conn.close()
                return result
            
            # Query the urls table
            cursor.execute("""
                SELECT url, final_url, response_code, title, filename, content_length
                FROM urls
            """)
            
            for row in cursor.fetchall():
                url, final_url, response_code, title, filename, content_length = row
                
                if filename:
                    screenshot = ScreenshotInfo(
                        url=url,
                        file_path=str(output_dir / filename),
                        response_code=response_code,
                        title=title,
                        final_url=final_url,
                        content_length=content_length,
                    )
                    result.add(screenshot)
                else:
                    result.add_failed(url)
            
            conn.close()
            
        except sqlite3.Error as e:
            log.error(f"Failed to parse gowitness database: {e}")
            raise  # Re-raise to be caught by caller
        
        return result
    
    async def _save_results(self, result: ScreenshotResult, output_dir: Optional[Path] = None) -> None:
        """Save screenshot metadata to JSON."""
        save_dir = output_dir if output_dir else self.output_dir
        output_file = save_dir / "screenshot_results.json"
        
        data = {
            "success_count": result.success_count,
            "fail_count": result.fail_count,
            "screenshots": [
                {
                    "url": s.url,
                    "file": s.file_path,
                    "status": s.response_code,
                    "title": s.title,
                    "final_url": s.final_url,
                }
                for s in result.screenshots
            ],
            "failed": result.failed,
        }
        
        output_file.write_text(json.dumps(data, indent=2))
        log.debug(f"Results saved to {output_file}")
    
    async def capture_single(self, url: str, scan_output_dir: Optional[Path] = None) -> Optional[ScreenshotInfo]:
        """Capture screenshot of a single URL."""
        result = await self.capture([url], scan_output_dir=scan_output_dir)
        if result.screenshots:
            return result.screenshots[0]
        return None
    
    async def capture_with_ports(
        self,
        subdomains: list[str],
        ports: list[int],
    ) -> ScreenshotResult:
        """
        Capture screenshots for subdomains on specific ports.
        
        Args:
            subdomains: List of subdomains
            ports: List of ports to try (e.g., [80, 443, 8080])
            
        Returns:
            ScreenshotResult with all captured screenshots
        """
        targets = []
        
        for subdomain in subdomains:
            for port in ports:
                if port == 443:
                    targets.append(f"https://{subdomain}")
                elif port == 80:
                    targets.append(f"http://{subdomain}")
                else:
                    # Try both protocols for non-standard ports
                    targets.append(f"https://{subdomain}:{port}")
                    targets.append(f"http://{subdomain}:{port}")
        
        return await self.capture(targets)

