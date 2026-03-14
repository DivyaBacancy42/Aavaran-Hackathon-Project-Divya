"""
Feature #8 — Reverse IP Lookup
Discovers other domains hosted on the same IP addresses.
Uses HackerTarget free API (api.hackertarget.com) — no key required.

CDN/shared-infrastructure IPs are automatically skipped — they would return
thousands of unrelated domains (false positives) because CDN edge nodes are
shared by millions of websites.
"""
import asyncio
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Optional, List

import httpx

logger = logging.getLogger(__name__)

# ── Known CDN / shared-infrastructure CIDR ranges ────────────────────────────
# Reverse IP on these will return thousands of unrelated domains (false positive).
# Sources: Cloudflare https://www.cloudflare.com/ips/
#          AWS CloudFront (published IP ranges)
#          Fastly (published IP ranges)
#          Akamai (representative ranges)
_CDN_NETWORKS = [
    # Cloudflare
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # AWS CloudFront
    "13.32.0.0/15", "13.35.0.0/16", "52.84.0.0/15", "54.182.0.0/16",
    "54.192.0.0/16", "54.230.0.0/16", "64.252.64.0/18", "65.8.0.0/16",
    "65.9.0.0/16", "70.132.0.0/18", "99.84.0.0/16", "99.86.0.0/16",
    "204.246.164.0/22", "204.246.168.0/22", "205.251.192.0/19", "216.137.32.0/19",
    # Fastly
    "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "104.156.80.0/20",
    "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17", "172.111.64.0/18",
    "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
    # Akamai
    "23.32.0.0/11", "23.192.0.0/11", "184.24.0.0/13", "184.50.0.0/15",
    "92.122.0.0/15", "95.100.0.0/15",
]

_CDN_NETS = [ipaddress.ip_network(cidr) for cidr in _CDN_NETWORKS]


def _is_shared_cdn_ip(ip: str) -> bool:
    """Return True if this IP belongs to a known CDN/shared-infra range."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _CDN_NETS)
    except ValueError:
        return False


@dataclass
class ReverseIPEntry:
    ip_address: str
    co_hosted_domains: List[str] = field(default_factory=list)
    domain_count: int = 0
    skipped_reason: Optional[str] = None   # set when IP was not queried
    error: Optional[str] = None


@dataclass
class ReverseIPResult:
    entries: List[ReverseIPEntry] = field(default_factory=list)
    error: Optional[str] = None


class ReverseIPScanner:
    """
    Reverse IP lookup: given a list of IPs, finds all other domains on the same server.
    Useful for discovering shared-hosting neighbours, internal apps, and sister domains.

    CDN IPs (Cloudflare, CloudFront, Fastly, Akamai) are skipped — querying them
    produces hundreds of unrelated domains with no actionable signal.

    HackerTarget free tier: ~100 queries/day without a key.
    We cap at MAX_IPS real (non-CDN) IPs to stay well within limits.
    """
    MAX_IPS = 5

    def __init__(self, ips: List[str]):
        seen: set = set()
        self.all_ips: List[str] = []
        for ip in ips:
            if ip and ip not in seen:
                seen.add(ip)
                self.all_ips.append(ip)

    async def _lookup_ip(self, client: httpx.AsyncClient, ip: str) -> ReverseIPEntry:
        try:
            resp = await client.get(
                f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                timeout=20.0,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SHODH/1.0)"},
            )
            text = resp.text.strip()

            if not text or "error" in text[:50].lower() or "API count exceeded" in text:
                return ReverseIPEntry(ip_address=ip, error=text[:200] if text else "empty response")

            domains = [d.strip() for d in text.splitlines() if d.strip() and not d.startswith("#")]
            return ReverseIPEntry(
                ip_address=ip,
                co_hosted_domains=domains,
                domain_count=len(domains),
            )
        except Exception as exc:
            logger.warning(f"ReverseIPScanner: {ip} → {exc}")
            return ReverseIPEntry(ip_address=ip, error=str(exc))

    async def run(self) -> ReverseIPResult:
        if not self.all_ips:
            return ReverseIPResult(error="No IPs provided")

        entries: List[ReverseIPEntry] = []
        queryable: List[str] = []

        for ip in self.all_ips:
            if _is_shared_cdn_ip(ip):
                logger.info(f"ReverseIPScanner: skipping CDN IP {ip}")
                entries.append(ReverseIPEntry(
                    ip_address=ip,
                    skipped_reason="CDN/shared-infrastructure IP — reverse lookup would produce false positives",
                ))
            else:
                queryable.append(ip)

        # Cap queryable IPs
        queryable = queryable[:self.MAX_IPS]

        if not queryable:
            logger.info("ReverseIPScanner: all IPs are CDN — nothing to query")
            return ReverseIPResult(entries=entries)

        try:
            async with httpx.AsyncClient() as client:
                for ip in queryable:
                    entry = await self._lookup_ip(client, ip)
                    entries.append(entry)
                    await asyncio.sleep(0.5)
        except Exception as exc:
            logger.error(f"ReverseIPScanner.run error: {exc}")
            return ReverseIPResult(entries=entries, error=str(exc))

        return ReverseIPResult(entries=entries)
