"""
Centralized logging setup for Hunter.
Uses loguru for timestamped, colored, rotating logs.
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from loguru import logger

# Module prefix mapping
MODULE_PREFIXES = {
    "main": "MAIN",
    "config_loader": "CONFIG",
    "tool_checker": "TOOLS",
    "subdomain_enum": "SUBDOMAIN",
    "secret_scanner": "SECRETS",
    "dir_bruteforce": "FFUF",
    "port_scanner": "NMAP",
    "vuln_scanner": "NUCLEI",
    "tech_detector": "TECH",
    "screenshotter": "GOWITNESS",
    "diff_engine": "DIFF",
    "email_notifier": "EMAIL",
    "scheduler": "SCHEDULER",
    "database": "DB",
    "executor": "EXEC",
}

# Global state
_configured = False
_current_log_file: Optional[Path] = None


def get_module_prefix(module_name: str) -> str:
    """Get the logging prefix for a module."""
    # Extract the base module name
    base_name = module_name.split(".")[-1]
    return MODULE_PREFIXES.get(base_name, base_name.upper())


def log_format(record: dict) -> str:
    """Custom log format with module prefix."""
    module = record.get("extra", {}).get("module", "HUNTER")
    return (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        f"<cyan>[{module}]</cyan> "
        "<level>{message}</level>\n"
    )


def file_format(record: dict) -> str:
    """Plain text format for log files."""
    module = record.get("extra", {}).get("module", "HUNTER")
    return (
        "{time:YYYY-MM-DD HH:mm:ss.SSS} | "
        "{level: <8} | "
        f"[{module}] "
        "{message}\n"
    )


def setup_logging(
    level: str = "INFO",
    console: bool = True,
    file: bool = True,
    log_dir: Optional[Path] = None,
    retention_days: int = 30,
) -> Path:
    """
    Configure logging for a scan run.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        console: Enable console output
        file: Enable file output
        log_dir: Directory for log files
        retention_days: Days to retain old logs
        
    Returns:
        Path to the current log file
    """
    global _configured, _current_log_file
    
    # Remove default handler
    logger.remove()
    
    # Console handler with colors
    if console:
        logger.add(
            sys.stderr,
            format=log_format,
            level=level,
            colorize=True,
        )
    
    # File handler with rotation
    if file:
        if log_dir is None:
            log_dir = Path("./data/logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create timestamped log file for this run
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        log_file = log_dir / f"scan_{timestamp}.log"
        _current_log_file = log_file
        
        logger.add(
            str(log_file),
            format=file_format,
            level=level,
            rotation=None,  # No rotation, one file per run
            retention=f"{retention_days} days",
            compression="gz",
        )
        
        # Clean up old logs
        _cleanup_old_logs(log_dir, retention_days)
    
    _configured = True
    return _current_log_file


def _cleanup_old_logs(log_dir: Path, retention_days: int) -> None:
    """Remove log files older than retention period."""
    from datetime import timedelta
    
    cutoff = datetime.now() - timedelta(days=retention_days)
    
    for log_file in log_dir.glob("scan_*.log*"):
        try:
            # Parse timestamp from filename
            parts = log_file.stem.replace("scan_", "").split("_")
            if len(parts) >= 2:
                date_str = f"{parts[0]}_{parts[1]}"
                file_date = datetime.strptime(date_str, "%Y-%m-%d_%H%M%S")
                if file_date < cutoff:
                    log_file.unlink()
        except (ValueError, IndexError):
            pass  # Skip files with unexpected naming


def get_logger(module_name: str = "hunter"):
    """
    Get a logger instance for a module.
    
    Args:
        module_name: Name of the calling module
        
    Returns:
        Configured logger with module prefix
    """
    prefix = get_module_prefix(module_name)
    return logger.bind(module=prefix)


def get_current_log_file() -> Optional[Path]:
    """Get the path to the current log file."""
    return _current_log_file


# Convenience functions for quick logging
def debug(message: str, module: str = "HUNTER") -> None:
    """Log a debug message."""
    logger.bind(module=module).debug(message)


def info(message: str, module: str = "HUNTER") -> None:
    """Log an info message."""
    logger.bind(module=module).info(message)


def warning(message: str, module: str = "HUNTER") -> None:
    """Log a warning message."""
    logger.bind(module=module).warning(message)


def error(message: str, module: str = "HUNTER") -> None:
    """Log an error message."""
    logger.bind(module=module).error(message)


def exception(message: str, module: str = "HUNTER") -> None:
    """Log an exception with traceback."""
    logger.bind(module=module).exception(message)

