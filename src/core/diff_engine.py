"""
Diff engine for comparing scan results between runs.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .database import Database
from .logger import get_logger

log = get_logger("diff_engine")


@dataclass
class ScanDiff:
    """Differences between two scans."""
    current_scan_id: int
    previous_scan_id: Optional[int]
    
    # Subdomain diffs
    new_subdomains: set[str] = field(default_factory=set)
    removed_subdomains: set[str] = field(default_factory=set)
    unchanged_subdomains: set[str] = field(default_factory=set)
    
    # Port diffs (subdomain -> list of new ports)
    new_ports: dict[str, list[int]] = field(default_factory=dict)
    
    # Vulnerability diffs
    new_vulnerabilities: list[dict] = field(default_factory=list)
    
    # Secret diffs
    new_secrets: list[dict] = field(default_factory=list)
    
    @property
    def has_changes(self) -> bool:
        """Check if there are any changes."""
        return bool(
            self.new_subdomains
            or self.removed_subdomains
            or self.new_ports
            or self.new_vulnerabilities
            or self.new_secrets
        )
    
    @property
    def is_first_scan(self) -> bool:
        """Check if this is the first scan (no previous to compare)."""
        return self.previous_scan_id is None
    
    def summary(self) -> dict:
        """Get a summary of changes."""
        return {
            "new_subdomains": len(self.new_subdomains),
            "removed_subdomains": len(self.removed_subdomains),
            "unchanged_subdomains": len(self.unchanged_subdomains),
            "new_ports": sum(len(ports) for ports in self.new_ports.values()),
            "new_vulnerabilities": len(self.new_vulnerabilities),
            "new_secrets": len(self.new_secrets),
            "is_first_scan": self.is_first_scan,
        }


class DiffEngine:
    """Compare scan results between runs."""
    
    def __init__(self, db: Database):
        self.db = db
    
    def compute_diff(
        self,
        current_scan_id: int,
        previous_scan_id: Optional[int] = None,
        project: Optional[str] = None,
    ) -> ScanDiff:
        """
        Compute differences between current and previous scan.
        
        Args:
            current_scan_id: ID of the current scan
            previous_scan_id: ID of the previous scan (auto-detect if None)
            project: Project name - only compare with scans from same project
            
        Returns:
            ScanDiff with all differences
        """
        # Auto-detect previous scan if not specified (same project only)
        if previous_scan_id is None:
            previous_scan = self._get_previous_scan(current_scan_id, project=project)
            previous_scan_id = previous_scan.id if previous_scan else None
        
        diff = ScanDiff(
            current_scan_id=current_scan_id,
            previous_scan_id=previous_scan_id,
        )
        
        if diff.is_first_scan:
            log.info("First scan - no previous data to compare")
            # All current subdomains are "new"
            diff.new_subdomains = self.db.get_all_domains_from_scan(current_scan_id)
            return diff
        
        log.info(f"Computing diff between scan #{current_scan_id} and #{previous_scan_id}")
        
        # Get subdomain sets
        current_domains = self.db.get_all_domains_from_scan(current_scan_id)
        previous_domains = self.db.get_all_domains_from_scan(previous_scan_id)
        
        # Compute subdomain diff
        diff.new_subdomains = current_domains - previous_domains
        diff.removed_subdomains = previous_domains - current_domains
        diff.unchanged_subdomains = current_domains & previous_domains
        
        log.info(f"Subdomains: {len(diff.new_subdomains)} new, "
                f"{len(diff.removed_subdomains)} removed, "
                f"{len(diff.unchanged_subdomains)} unchanged")
        
        # Compute port diff
        diff.new_ports = self._compute_port_diff(current_scan_id, previous_scan_id)
        
        # Compute vulnerability diff
        diff.new_vulnerabilities = self._compute_vuln_diff(current_scan_id, previous_scan_id)
        
        # Compute secret diff
        diff.new_secrets = self._compute_secret_diff(current_scan_id, previous_scan_id)
        
        return diff
    
    def _get_previous_scan(self, current_scan_id: int, project: Optional[str] = None):
        """Get the most recent completed scan before the current one, optionally filtered by project."""
        from sqlalchemy import select
        from .models import Scan
        
        with self.db.session() as session:
            # Get current scan to determine project if not provided
            current_scan = session.get(Scan, current_scan_id)
            if not current_scan:
                return None
            
            # Use current scan's project if project not specified
            if project is None:
                project = current_scan.project
            
            stmt = (
                select(Scan)
                .where(Scan.id < current_scan_id)
                .where(Scan.status == "completed")
                .where(Scan.project == project)  # Only compare within same project
                .order_by(Scan.id.desc())
                .limit(1)
            )
            return session.scalar(stmt)
    
    def _compute_port_diff(
        self,
        current_scan_id: int,
        previous_scan_id: int,
    ) -> dict[str, list[int]]:
        """Compute new ports discovered."""
        from sqlalchemy import select
        from .models import Subdomain, Port
        
        new_ports = {}
        
        with self.db.session() as session:
            # Get current ports by subdomain
            current_ports = {}
            stmt = (
                select(Subdomain.domain, Port.port_number)
                .join(Port)
                .where(Subdomain.scan_id == current_scan_id)
            )
            for domain, port in session.execute(stmt):
                if domain not in current_ports:
                    current_ports[domain] = set()
                current_ports[domain].add(port)
            
            # Get previous ports by subdomain
            previous_ports = {}
            stmt = (
                select(Subdomain.domain, Port.port_number)
                .join(Port)
                .where(Subdomain.scan_id == previous_scan_id)
            )
            for domain, port in session.execute(stmt):
                if domain not in previous_ports:
                    previous_ports[domain] = set()
                previous_ports[domain].add(port)
            
            # Find new ports
            for domain, ports in current_ports.items():
                prev_ports = previous_ports.get(domain, set())
                new = ports - prev_ports
                if new:
                    new_ports[domain] = list(new)
        
        if new_ports:
            total_new = sum(len(p) for p in new_ports.values())
            log.info(f"Found {total_new} new open ports across {len(new_ports)} hosts")
        
        return new_ports
    
    def _compute_vuln_diff(
        self,
        current_scan_id: int,
        previous_scan_id: int,
    ) -> list[dict]:
        """Compute new vulnerabilities discovered."""
        from sqlalchemy import select
        from .models import Subdomain, Vulnerability
        
        new_vulns = []
        
        with self.db.session() as session:
            # Get current vulnerabilities
            current_vulns = set()
            stmt = (
                select(Subdomain.domain, Vulnerability.template_id, Vulnerability.matched_at)
                .join(Vulnerability)
                .where(Subdomain.scan_id == current_scan_id)
            )
            for row in session.execute(stmt):
                current_vulns.add((row[0], row[1], row[2]))
            
            # Get previous vulnerabilities
            previous_vulns = set()
            stmt = (
                select(Subdomain.domain, Vulnerability.template_id, Vulnerability.matched_at)
                .join(Vulnerability)
                .where(Subdomain.scan_id == previous_scan_id)
            )
            for row in session.execute(stmt):
                previous_vulns.add((row[0], row[1], row[2]))
            
            # Find new vulnerabilities
            new_vuln_keys = current_vulns - previous_vulns
            
            if new_vuln_keys:
                # Get full vuln info for new ones
                stmt = (
                    select(Vulnerability, Subdomain.domain)
                    .join(Subdomain)
                    .where(Subdomain.scan_id == current_scan_id)
                )
                for vuln, domain in session.execute(stmt):
                    key = (domain, vuln.template_id, vuln.matched_at)
                    if key in new_vuln_keys:
                        new_vulns.append({
                            "domain": domain,
                            "template_id": vuln.template_id,
                            "name": vuln.name,
                            "severity": vuln.severity,
                            "matched_at": vuln.matched_at,
                        })
        
        if new_vulns:
            log.warning(f"Found {len(new_vulns)} new vulnerabilities")
            for v in new_vulns:
                log.warning(f"  [{v['severity'].upper()}] {v['name']} at {v['domain']}")
        
        return new_vulns
    
    def _compute_secret_diff(
        self,
        current_scan_id: int,
        previous_scan_id: int,
    ) -> list[dict]:
        """Compute new secrets discovered."""
        from sqlalchemy import select
        from .models import Secret
        
        new_secrets = []
        
        with self.db.session() as session:
            # Get current secrets (by unique key)
            current_secrets = set()
            stmt = select(Secret).where(Secret.scan_id == current_scan_id)
            current_secret_objs = list(session.scalars(stmt))
            
            for s in current_secret_objs:
                key = (s.source, s.file_path, s.commit_hash, s.secret_type)
                current_secrets.add(key)
            
            # Get previous secrets
            previous_secrets = set()
            stmt = select(Secret).where(Secret.scan_id == previous_scan_id)
            for s in session.scalars(stmt):
                key = (s.source, s.file_path, s.commit_hash, s.secret_type)
                previous_secrets.add(key)
            
            # Find new secrets
            new_secret_keys = current_secrets - previous_secrets
            
            for s in current_secret_objs:
                key = (s.source, s.file_path, s.commit_hash, s.secret_type)
                if key in new_secret_keys:
                    new_secrets.append({
                        "source": s.source,
                        "type": s.secret_type,
                        "file": s.file_path,
                        "repo": s.repository,
                    })
        
        if new_secrets:
            log.warning(f"Found {len(new_secrets)} new secrets")
        
        return new_secrets
    
    def mark_new_subdomains(
        self,
        current_scan_id: int,
        previous_domains: set[str],
    ) -> None:
        """Mark subdomains as new or not based on previous scan."""
        from sqlalchemy import select, update
        from .models import Subdomain
        
        with self.db.session() as session:
            # Mark all current subdomains
            stmt = select(Subdomain).where(Subdomain.scan_id == current_scan_id)
            for subdomain in session.scalars(stmt):
                subdomain.is_new = subdomain.domain not in previous_domains
    
    def get_targets_for_analysis(self, diff: ScanDiff) -> list[str]:
        """
        Get list of targets that need further analysis.
        
        Returns new subdomains and subdomains with new ports.
        """
        targets = set(diff.new_subdomains)
        targets.update(diff.new_ports.keys())
        
        log.info(f"{len(targets)} targets need analysis")
        return list(targets)

