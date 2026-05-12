"""
Subprocess executor for running external tools.
"""

import asyncio
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .logger import get_logger

log = get_logger("executor")


@dataclass
class CommandResult:
    """Result of a command execution."""
    command: str
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    
    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class CommandExecutor:
    """Execute external commands with timeout and rate limiting."""
    
    def __init__(
        self,
        rate_limit: str = "moderate",
        default_timeout: float = 300.0,
    ):
        self.rate_limit = rate_limit
        self.default_timeout = default_timeout
        self._delays = {
            "aggressive": (0.0, 0.5),
            "moderate": (1.0, 3.0),
            "stealth": (3.0, 10.0),
        }
    
    async def _apply_rate_limit(self) -> None:
        """Apply rate limiting delay."""
        min_delay, max_delay = self._delays.get(self.rate_limit, (1.0, 3.0))
        if max_delay > 0:
            delay = random.uniform(min_delay, max_delay)
            await asyncio.sleep(delay)
    
    async def run(
        self,
        *args: str,
        timeout: Optional[float] = None,
        cwd: Optional[Path] = None,
        rate_limit: bool = True,
        module: str = "EXEC",
    ) -> CommandResult:
        """
        Run a command asynchronously.
        
        Args:
            *args: Command and arguments
            timeout: Timeout in seconds (uses default if None)
            cwd: Working directory
            rate_limit: Apply rate limiting delay
            module: Module name for logging
            
        Returns:
            CommandResult with output
        """
        if timeout is None:
            timeout = self.default_timeout
        
        cmd_str = " ".join(args)
        log.debug(f"Running: {cmd_str}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout,
                )
                
                result = CommandResult(
                    command=cmd_str,
                    returncode=process.returncode or 0,
                    stdout=stdout.decode("utf-8", errors="replace"),
                    stderr=stderr.decode("utf-8", errors="replace"),
                )
                
                if result.success:
                    log.debug(f"Command succeeded: {args[0]}")
                else:
                    log.warning(f"Command failed (code {result.returncode}): {args[0]}")
                    if result.stderr:
                        log.debug(f"stderr: {result.stderr[:500]}")
                
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                log.warning(f"Command timed out after {timeout}s: {args[0]}")
                
                result = CommandResult(
                    command=cmd_str,
                    returncode=-1,
                    stdout="",
                    stderr=f"Timeout after {timeout} seconds",
                    timed_out=True,
                )
        
        except FileNotFoundError:
            log.error(f"Command not found: {args[0]}")
            result = CommandResult(
                command=cmd_str,
                returncode=-1,
                stdout="",
                stderr=f"Command not found: {args[0]}",
            )
        
        except Exception as e:
            log.error(f"Command execution error: {e}")
            result = CommandResult(
                command=cmd_str,
                returncode=-1,
                stdout="",
                stderr=str(e),
            )
        
        # Apply rate limiting after command
        if rate_limit:
            await self._apply_rate_limit()
        
        return result
    
    async def run_with_output_file(
        self,
        *args: str,
        output_file: Path,
        timeout: Optional[float] = None,
        cwd: Optional[Path] = None,
        module: str = "EXEC",
    ) -> CommandResult:
        """
        Run a command that writes to an output file.
        
        Args:
            *args: Command and arguments
            output_file: Expected output file path
            timeout: Timeout in seconds
            cwd: Working directory
            module: Module name for logging
            
        Returns:
            CommandResult with file content in stdout if successful
        """
        result = await self.run(*args, timeout=timeout, cwd=cwd, module=module)
        
        # Try to read output file if command succeeded
        if result.success and output_file.exists():
            try:
                result.stdout = output_file.read_text()
            except Exception as e:
                log.warning(f"Could not read output file: {e}")
        
        return result
    
    async def run_many(
        self,
        commands: list[list[str]],
        timeout: Optional[float] = None,
        max_concurrent: int = 5,
    ) -> list[CommandResult]:
        """
        Run multiple commands with concurrency limit.
        
        Args:
            commands: List of command argument lists
            timeout: Timeout per command
            max_concurrent: Maximum concurrent commands
            
        Returns:
            List of CommandResult objects
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def run_with_semaphore(args: list[str]) -> CommandResult:
            async with semaphore:
                return await self.run(*args, timeout=timeout)
        
        tasks = [run_with_semaphore(cmd) for cmd in commands]
        return await asyncio.gather(*tasks)


# Global executor instance
_executor: Optional[CommandExecutor] = None


def get_executor(rate_limit: str = "moderate") -> CommandExecutor:
    """Get or create the global executor instance."""
    global _executor
    if _executor is None:
        _executor = CommandExecutor(rate_limit=rate_limit)
    return _executor

