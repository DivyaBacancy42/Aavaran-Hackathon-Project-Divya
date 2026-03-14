import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import dns.asyncresolver
import dns.exception
import dns.reversename

logger = logging.getLogger(__name__)

DNS_TIMEOUT = 8


@dataclass
class ReverseDNSResult:
    """Maps IP addresses to their PTR (reverse DNS) hostnames."""
    ptr_map: Dict[str, str] = field(default_factory=dict)  # {ip: reverse_hostname}
    errors: List[str] = field(default_factory=list)


class ReverseDNSScanner:
    """
    Performs PTR (reverse DNS) lookups for a list of IP addresses.
    Uses asyncio.Semaphore to avoid hammering the resolver.
    """

    def __init__(self, ip_addresses: List[str]):
        self.ip_addresses = list(set(filter(None, ip_addresses)))  # deduplicate, drop None

    @staticmethod
    def _make_resolver() -> dns.asyncresolver.Resolver:
        r = dns.asyncresolver.Resolver()
        r.timeout = DNS_TIMEOUT
        r.lifetime = DNS_TIMEOUT + 2
        return r

    async def run(self) -> ReverseDNSResult:
        result = ReverseDNSResult()
        if not self.ip_addresses:
            return result

        sem = asyncio.Semaphore(15)
        errors: List[str] = []

        async def lookup(ip: str):
            async with sem:
                try:
                    rev_name = dns.reversename.from_address(ip)
                    resolver = self._make_resolver()
                    answers = await resolver.resolve(rev_name, "PTR")
                    for rdata in answers:
                        hostname = str(rdata.target).rstrip(".")
                        result.ptr_map[ip] = hostname
                        logger.debug(f"PTR {ip} → {hostname}")
                        return  # Take first answer
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                        dns.resolver.NoNameservers, dns.exception.Timeout):
                    pass  # No PTR record — normal for many IPs
                except Exception as e:
                    errors.append(f"PTR {ip}: {e}")
                    logger.debug(f"ReverseDNS error for {ip}: {e}")

        tasks = [lookup(ip) for ip in self.ip_addresses]
        await asyncio.gather(*tasks, return_exceptions=True)

        result.errors = errors
        logger.info(
            f"ReverseDNSScanner: resolved {len(result.ptr_map)}/{len(self.ip_addresses)} IPs"
        )
        return result
