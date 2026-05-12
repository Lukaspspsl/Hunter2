"""
Port scanning module using nmap.
Two-phase approach: quick scan first, thorough scan on discovered ports.
"""

import asyncio
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..core.executor import CommandExecutor
from ..core.logger import get_logger
from ..config_loader import HunterConfig
from ..tool_checker import ToolChecker

log = get_logger("port_scanner")


@dataclass
class PortInfo:
    """Information about an open port."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    version: Optional[str] = None
    product: Optional[str] = None
    extra_info: Optional[str] = None
    scripts: dict = field(default_factory=dict)


@dataclass
class HostScanResult:
    """Scan results for a single host."""
    host: str
    ip: Optional[str] = None
    ports: list[PortInfo] = field(default_factory=list)
    os_guess: Optional[str] = None
    hostname: Optional[str] = None
    
    @property
    def open_ports(self) -> list[int]:
        return [p.port for p in self.ports if p.state == "open"]


@dataclass
class PortScanResult:
    """Combined port scan results."""
    hosts: dict[str, HostScanResult] = field(default_factory=dict)
    
    @property
    def total_hosts(self) -> int:
        return len(self.hosts)
    
    @property
    def total_ports(self) -> int:
        return sum(len(h.ports) for h in self.hosts.values())
    
    def add_host(self, result: HostScanResult) -> None:
        self.hosts[result.host] = result


class PortScanner:
    """Two-phase port scanner using nmap."""
    
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
        quick_only: bool = False,
    ) -> PortScanResult:
        """
        Perform two-phase port scan.
        
        Phase 1: Quick scan on common ports to find open ports
        Phase 2: Thorough scan on discovered ports for version info
        
        Args:
            targets: List of hostnames/IPs to scan
            quick_only: Only perform quick scan
            
        Returns:
            PortScanResult with all findings
        """
        if not self.tools.is_available("nmap"):
            log.error("nmap not available, cannot perform port scan")
            return PortScanResult()
        
        if not targets:
            log.warning("No targets provided for port scan")
            return PortScanResult()

        # Filter out unresolvable hosts before running nmap
        resolvable = []
        for host in targets:
            if await self._check_host_resolvable(host):
                resolvable.append(host)
            else:
                log.warning(f"Host {host} does not resolve, skipping port scan")

        if not resolvable:
            log.warning("No resolvable hosts, skipping port scan")
            return PortScanResult()

        targets = resolvable
        log.info(f"Starting port scan on {len(targets)} hosts")
        
        config = self.config.port_scan.nmap
        result = PortScanResult()
        
        # Phase 1: Quick scan
        quick_config = config.quick_scan
        log.info(f"Phase 1: Quick scan on ports {quick_config.ports}")
        
        quick_results = await self._run_quick_scan(
            targets=targets,
            ports=quick_config.ports,
            timing=quick_config.timing,
        )
        
        # Collect hosts with open ports for thorough scan
        hosts_with_ports = {}
        for host, host_result in quick_results.items():
            result.add_host(host_result)
            if host_result.open_ports:
                hosts_with_ports[host] = host_result.open_ports
        
        port_summary = {p: 0 for p in [80, 443, 8080, 8443, 8000, 3000]}
        for host_result in quick_results.values():
            for port in host_result.open_ports:
                port_summary[port] = port_summary.get(port, 0) + 1
        
        log.info(f"Quick scan complete: {sum(port_summary.values())} open ports found")
        for port, count in port_summary.items():
            if count > 0:
                log.info(f"  Port {port}: {count} hosts")
        
        # Phase 2: Thorough scan on discovered ports
        if not quick_only and config.thorough_scan.enabled and hosts_with_ports:
            log.info(f"Phase 2: Thorough scan on {len(hosts_with_ports)} hosts")
            
            thorough_results = await self._run_thorough_scan(
                hosts_with_ports=hosts_with_ports,
                timing=config.thorough_scan.timing,
                scripts=config.thorough_scan.scripts,
            )
            
            # Merge thorough results (update port info)
            for host, host_result in thorough_results.items():
                if host in result.hosts:
                    # Update with detailed info
                    result.hosts[host].ports = host_result.ports
                    result.hosts[host].os_guess = host_result.os_guess
                else:
                    result.add_host(host_result)
        
        log.info(f"Port scan complete: {result.total_hosts} hosts, {result.total_ports} ports")
        
        # Save results
        await self._save_results(result)
        
        return result
    
    async def _run_quick_scan(
        self,
        targets: list[str],
        ports: str,
        timing: str = "T3",
    ) -> dict[str, HostScanResult]:
        """Run quick TCP connect scan on specified ports (no root required)."""
        results = {}
        
        # Write targets to file
        targets_file = self.output_dir / "nmap_targets.txt"
        targets_file.write_text("\n".join(targets))
        
        output_file = self.output_dir / "nmap_quick.xml"
        
        args = [
            "nmap",
            "-sT",                    # TCP connect scan (doesn't require root)
            f"-{timing}",             # Timing template
            "-p", ports,              # Port specification
            "--open",                 # Only show open ports
            "-oX", str(output_file),  # XML output
            "-iL", str(targets_file), # Input from file
        ]
        
        cmd_result = await self.executor.run(
            *args,
            timeout=self.config.port_scan.nmap.quick_scan.timeout,
            rate_limit=False,
            module="NMAP",
        )
        
        if output_file.exists():
            results = self._parse_nmap_xml(output_file)
        else:
            log.error(f"nmap quick scan failed: {cmd_result.stderr}")
        
        return results
    
    async def _run_thorough_scan(
        self,
        hosts_with_ports: dict[str, list[int]],
        timing: str = "T2",
        scripts: Optional[list[str]] = None,
    ) -> dict[str, HostScanResult]:
        """Run thorough scan with version detection on discovered ports."""
        results = {}
        
        # Group hosts by their open ports for efficiency
        # For simplicity, scan each host individually
        tasks = []
        
        for host, ports in hosts_with_ports.items():
            tasks.append(self._scan_host_thorough(host, ports, timing, scripts))
        
        # Run with limited concurrency
        semaphore = asyncio.Semaphore(5)
        
        async def scan_with_semaphore(coro):
            async with semaphore:
                return await coro
        
        scan_results = await asyncio.gather(
            *[scan_with_semaphore(t) for t in tasks],
            return_exceptions=True,
        )
        
        for r in scan_results:
            if isinstance(r, Exception):
                log.error(f"Thorough scan failed: {r}")
            elif isinstance(r, HostScanResult):
                results[r.host] = r
        
        return results
    
    async def _scan_host_thorough(
        self,
        host: str,
        ports: list[int],
        timing: str,
        scripts: Optional[list[str]],
    ) -> HostScanResult:
        """Perform thorough scan on a single host."""
        port_str = ",".join(str(p) for p in ports)
        output_file = self.output_dir / f"nmap_thorough_{self._sanitize_host(host)}.xml"
        
        args = [
            "nmap",
            "-sV",                    # Version detection
            "-sC",                    # Default scripts
            f"-{timing}",             # Timing template
            "-p", port_str,           # Specific ports
            "-oX", str(output_file),  # XML output
        ]
        
        # Add custom scripts if specified
        if scripts:
            script_str = ",".join(scripts)
            args.extend(["--script", script_str])
        
        args.append(host)
        
        await self.executor.run(
            *args,
            timeout=self.config.port_scan.nmap.thorough_scan.timeout,
            rate_limit=False,
            module="NMAP",
        )
        
        if output_file.exists():
            results = self._parse_nmap_xml(output_file)
            return results.get(host, HostScanResult(host=host))
        
        return HostScanResult(host=host)
    
    def _parse_nmap_xml(self, xml_file: Path) -> dict[str, HostScanResult]:
        """Parse nmap XML output."""
        results = {}
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host_elem in root.findall(".//host"):
                # Get hostname/IP
                hostname = None
                ip = None
                
                for addr in host_elem.findall("address"):
                    if addr.get("addrtype") == "ipv4":
                        ip = addr.get("addr")
                
                for name in host_elem.findall(".//hostname"):
                    hostname = name.get("name")
                    break
                
                host_key = hostname or ip
                if not host_key:
                    continue
                
                host_result = HostScanResult(
                    host=host_key,
                    ip=ip,
                    hostname=hostname,
                )
                
                # Parse ports
                for port_elem in host_elem.findall(".//port"):
                    state_elem = port_elem.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
                        continue
                    
                    service_elem = port_elem.find("service")
                    
                    port_info = PortInfo(
                        port=int(port_elem.get("portid", 0)),
                        protocol=port_elem.get("protocol", "tcp"),
                        state="open",
                    )
                    
                    if service_elem is not None:
                        port_info.service = service_elem.get("name")
                        port_info.product = service_elem.get("product")
                        port_info.version = service_elem.get("version")
                        port_info.extra_info = service_elem.get("extrainfo")
                    
                    # Parse script output
                    for script_elem in port_elem.findall("script"):
                        script_id = script_elem.get("id")
                        script_output = script_elem.get("output", "")
                        port_info.scripts[script_id] = script_output
                    
                    host_result.ports.append(port_info)
                
                # Parse OS detection if available
                for os_elem in host_elem.findall(".//osmatch"):
                    host_result.os_guess = os_elem.get("name")
                    break
                
                results[host_key] = host_result
                
        except ET.ParseError as e:
            log.error(f"Failed to parse nmap XML: {e}")
        
        return results
    
    async def _check_host_resolvable(self, host: str) -> bool:
        """Check if host DNS resolves (quick pre-flight check)."""
        import socket
        try:
            loop = asyncio.get_event_loop()
            await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname, host),
                timeout=3.0,
            )
            return True
        except (socket.gaierror, asyncio.TimeoutError, OSError) as e:
            log.debug(f"DNS resolution failed for {host}: {type(e).__name__}")
            return False

    def _sanitize_host(self, host: str) -> str:
        """Sanitize hostname for filename."""
        return re.sub(r"[^\w\-.]", "_", host)[:100]
    
    async def _save_results(self, result: PortScanResult) -> None:
        """Save scan results to JSON."""
        output_file = self.output_dir / "port_scan_results.json"
        
        data = {
            "total_hosts": result.total_hosts,
            "total_ports": result.total_ports,
            "hosts": {
                host: {
                    "ip": hr.ip,
                    "hostname": hr.hostname,
                    "os": hr.os_guess,
                    "ports": [
                        {
                            "port": p.port,
                            "protocol": p.protocol,
                            "state": p.state,
                            "service": p.service,
                            "product": p.product,
                            "version": p.version,
                            "scripts": p.scripts,
                        }
                        for p in hr.ports
                    ],
                }
                for host, hr in result.hosts.items()
            },
        }
        
        output_file.write_text(json.dumps(data, indent=2))
        log.debug(f"Results saved to {output_file}")

