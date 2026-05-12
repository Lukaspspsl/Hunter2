"""
Certificate Transparency (crt.sh) subdomain discovery module.
Uses crt.sh API to find subdomains via certificate transparency logs.
"""

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

from ..core.logger import get_logger
from ..config_loader import HunterConfig

log = get_logger("crtsh")


@dataclass
class CrtshResult:
    """Result from crt.sh lookup."""
    domain: str
    subdomains: set[str] = field(default_factory=set)
    
    def add(self, subdomain: str) -> None:
        """Add a subdomain."""
        subdomain = subdomain.strip().lower()
        if subdomain and self._is_valid_subdomain(subdomain, self.domain):
            self.subdomains.add(subdomain)
    
    def _is_valid_subdomain(self, subdomain: str, domain: str) -> bool:
        """Check if subdomain is valid for the domain."""
        if not subdomain or not domain:
            return False
        # Remove wildcard prefix
        domain_clean = domain.replace("*.", "")
        # Check if subdomain ends with domain
        return subdomain.endswith(f".{domain_clean}") or subdomain == domain_clean


class CrtshEnumerator:
    """Enumerate subdomains using Certificate Transparency logs via crt.sh."""
    
    def __init__(
        self,
        config: HunterConfig,
        output_dir: Optional[Path] = None,
    ):
        self.config = config
        self.output_dir = output_dir or Path("./data/raw_results")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # HTTP client for crt.sh API
        self.http_client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            verify=True,
        )
    
    async def enumerate(self, target: str) -> CrtshResult:
        """
        Enumerate subdomains using crt.sh.
        
        Args:
            target: Target domain (e.g., example.com or *.example.com)
            
        Returns:
            CrtshResult with discovered subdomains
        """
        # Clean target
        domain = target.replace("*.", "").strip()
        log.info(f"Starting crt.sh lookup for {domain}")
        
        result = CrtshResult(domain=domain)
        config = self.config.subdomain_enum.crtsh
        
        if not config.enabled:
            log.debug("crt.sh enumeration disabled in config")
            return result
        
        try:
            subdomains = await self._query_crtsh(domain)
            for subdomain in subdomains:
                result.add(subdomain)
            
            log.info(f"crt.sh found {len(result.subdomains)} subdomains for {domain}")
            
            # Save results
            await self._save_results(domain, result)
            
        except Exception as e:
            log.error(f"crt.sh enumeration failed for {domain}: {e}")
        
        return result
    
    async def _query_crtsh(self, domain: str) -> set[str]:
        """Query crt.sh API for subdomains."""
        subdomains = set()
        
        # crt.sh API endpoint
        url = "https://crt.sh/"
        params = {
            "q": f"%.{domain}",
            "output": "json",
        }
        
        try:
            log.debug(f"Querying crt.sh: {url}?q=%.{domain}")
            response = await self.http_client.get(url, params=params)
            response.raise_for_status()
            
            data = response.json()
            
            # Extract unique name_value fields
            for entry in data:
                name_value = entry.get("name_value", "")
                if name_value:
                    # Split by newlines and commas (crt.sh can return multiple domains)
                    for name in name_value.replace("\n", ",").split(","):
                        name = name.strip()
                        if name:
                            # Remove wildcard prefix if present
                            if name.startswith("*."):
                                name = name[2:]
                            subdomains.add(name.lower())
            
            log.debug(f"crt.sh returned {len(subdomains)} unique subdomains")
            
        except httpx.TimeoutException:
            log.warning(f"crt.sh timeout for {domain}")
        except httpx.HTTPError as e:
            log.warning(f"crt.sh HTTP error for {domain}: {e}")
        except json.JSONDecodeError as e:
            log.warning(f"crt.sh JSON decode error for {domain}: {e}")
        except Exception as e:
            log.error(f"crt.sh unexpected error for {domain}: {e}")
        
        return subdomains
    
    async def _save_results(self, domain: str, result: CrtshResult) -> None:
        """Save crt.sh results to JSON file."""
        output_file = self.output_dir / f"crtsh_{self._sanitize_filename(domain)}.json"
        
        data = {
            "domain": domain,
            "subdomains": sorted(list(result.subdomains)),
            "count": len(result.subdomains),
        }
        
        output_file.write_text(json.dumps(data, indent=2))
        log.debug(f"Results saved to {output_file}")
    
    def _sanitize_filename(self, domain: str) -> str:
        """Sanitize domain name for filename."""
        return domain.replace(".", "_").replace("*", "wildcard")
    
    async def close(self) -> None:
        """Close HTTP client."""
        await self.http_client.aclose()

