"""IP Reputation Scanner — DNSBL + URLhaus (abuse.ch)

Feature 32: Reputation Check

Checks every unique public IP address from alive subdomains against:
  1. DNS Blacklists (DNSBL) — Spamhaus ZEN, SpamCop, SORBS
     Pure DNS queries. Zero cost, no API key, 100% free.
  2. URLhaus (abuse.ch) — malware/phishing URL database
     Free REST API, no authentication required.

Method:
  DNSBL: reverse IP → prepend to zone → query A record.
         NXDOMAIN = clean. Any response = blacklisted.
  URLhaus: POST {"host": ip} → check urls_count > 0.

Private / loopback / link-local IPs are always skipped.
"""
import asyncio
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import dns.resolver
import httpx

logger = logging.getLogger(__name__)

TIMEOUT = 10.0
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"

# DNS Blacklist zones — all free, no API key
DNSBL_ZONES: dict = {
    "Spamhaus ZEN": "zen.spamhaus.org",   # spam + exploits + malware
    "SpamCop":      "bl.spamcop.net",     # spam sources
    "SORBS":        "dnsbl.sorbs.net",    # spam + proxy + zombie
}


@dataclass
class ReputationResult:
    ip_address: str
    hostname: Optional[str] = None
    is_blacklisted: bool = False
    blacklists: List[str] = field(default_factory=list)   # DNSBL names that listed this IP
    threat_type: Optional[str] = None                      # "spam", "malware", "botnet", etc.
    urlhaus_status: Optional[str] = None                   # "listed" or "clean"
    urlhaus_tags: List[str] = field(default_factory=list)  # malware categories from URLhaus
    abuse_score: Optional[int] = None                      # 0–100, derived from hit count


class ReputationScanner:
    """
    Checks unique public IPs against DNS blacklists and URLhaus.
    DNSBL lookups run in thread pool (dnspython is sync).
    URLhaus calls run concurrently via httpx async.
    """

    def __init__(self, ips_with_hostnames: List[Tuple[str, Optional[str]]]):
        seen: set = set()
        self.targets: List[Tuple[str, Optional[str]]] = []
        for ip, hostname in ips_with_hostnames:
            if not ip or ip in seen:
                continue
            if _is_private_ip(ip):
                continue
            seen.add(ip)
            self.targets.append((ip, hostname))

    async def run(self) -> List[ReputationResult]:
        if not self.targets:
            logger.info("ReputationScanner: no public IPs to check")
            return []

        sem = asyncio.Semaphore(5)
        results: List[ReputationResult] = []

        async with httpx.AsyncClient(timeout=TIMEOUT) as client:

            async def check(ip: str, hostname: Optional[str]):
                async with sem:
                    try:
                        r = await self._check_ip(client, ip, hostname)
                        results.append(r)
                    except Exception as e:
                        logger.debug(f"ReputationScanner: error for {ip}: {e}")
                        results.append(ReputationResult(ip_address=ip, hostname=hostname))

            await asyncio.gather(
                *[check(ip, h) for ip, h in self.targets],
                return_exceptions=True,
            )

        blacklisted = sum(1 for r in results if r.is_blacklisted)
        logger.info(
            f"ReputationScanner: checked {len(results)} IPs, "
            f"{blacklisted} blacklisted"
        )
        return results

    async def _check_ip(
        self, client: httpx.AsyncClient, ip: str, hostname: Optional[str]
    ) -> ReputationResult:
        result = ReputationResult(ip_address=ip, hostname=hostname)

        # Step 1: DNSBL checks (run synchronous DNS in thread pool concurrently)
        dnsbl_tasks = [
            asyncio.to_thread(_check_dnsbl, ip, name, zone)
            for name, zone in DNSBL_ZONES.items()
        ]
        dnsbl_outcomes = await asyncio.gather(*dnsbl_tasks, return_exceptions=True)
        for i, name in enumerate(DNSBL_ZONES.keys()):
            outcome = dnsbl_outcomes[i]
            if isinstance(outcome, bool) and outcome:
                result.blacklists.append(name)

        # Step 2: URLhaus check
        try:
            urlhaus = await _check_urlhaus(client, ip)
            result.urlhaus_status = "listed" if urlhaus["listed"] else "clean"
            result.urlhaus_tags = urlhaus.get("tags", [])
            if urlhaus["listed"]:
                result.blacklists.append("URLhaus")
        except Exception as e:
            logger.debug(f"ReputationScanner: URLhaus check failed for {ip}: {e}")
            result.urlhaus_status = None

        # Derive final verdict
        if result.blacklists:
            result.is_blacklisted = True
            # Pick most descriptive threat type
            if result.urlhaus_tags:
                result.threat_type = result.urlhaus_tags[0]
            elif "Spamhaus ZEN" in result.blacklists:
                result.threat_type = "spam/exploit"
            elif "SpamCop" in result.blacklists:
                result.threat_type = "spam"
            elif "SORBS" in result.blacklists:
                result.threat_type = "spam/proxy"
            else:
                result.threat_type = "blacklisted"

            # Abuse score: URLhaus = 40 pts, each DNSBL = 25 pts
            raw = sum(40 if bl == "URLhaus" else 25 for bl in result.blacklists)
            result.abuse_score = min(raw, 100)

        return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_private_ip(ip: str) -> bool:
    """Returns True for private, loopback, link-local, or IPv6 addresses.
    DNSBL zones only support IPv4; skip IPv6 entirely."""
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address):
            return True  # DNSBL doesn't support IPv6
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True  # unparseable → skip


def _check_dnsbl(ip: str, name: str, zone: str) -> bool:
    """
    Synchronous DNSBL lookup — wrap with asyncio.to_thread().
    Reverses IP octets, appends DNSBL zone, queries A record.
    NXDOMAIN = clean (expected); any A response = listed.
    """
    try:
        if ":" in ip:  # IPv6 — DNSBL doesn't support it
            return False
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.{zone}"
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 3.0
        answers = resolver.resolve(query, "A")
        return len(answers) > 0
    except dns.resolver.NXDOMAIN:
        return False  # clean — expected response for most IPs
    except Exception:
        return False  # timeout or error → treat as clean


async def _check_urlhaus(client: httpx.AsyncClient, ip: str) -> dict:
    """
    Query URLhaus API (abuse.ch) — free, no key required.
    Uses form-encoded POST (not JSON) as per URLhaus API spec.
    """
    resp = await client.post(URLHAUS_API, data={"host": ip})
    resp.raise_for_status()
    data = resp.json()

    if data.get("query_status") == "no_results":
        return {"listed": False}

    if data.get("urls_count", 0) > 0:
        # Collect unique tags across all malicious URLs for this host
        tags: List[str] = []
        for url_entry in data.get("urls", []):
            for tag in (url_entry.get("tags") or []):
                if tag and tag not in tags:
                    tags.append(tag)
        return {"listed": True, "tags": tags[:5]}

    return {"listed": False}
