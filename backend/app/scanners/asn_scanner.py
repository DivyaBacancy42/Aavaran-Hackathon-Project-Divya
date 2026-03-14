import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import dns.asyncresolver
import dns.exception

logger = logging.getLogger(__name__)

DNS_TIMEOUT = 8


@dataclass
class ASNData:
    """Single ASN record discovered during scan."""
    asn: str               # e.g. "13335"
    prefix: str            # e.g. "104.16.0.0/12"
    country: str           # e.g. "US"
    org_name: str          # e.g. "CLOUDFLARENET"
    sample_ip: str         # which IP triggered this discovery


@dataclass
class ASNScanResult:
    asn_records: List[ASNData] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class ASNScanner:
    """
    Identifies ASN and IP range ownership for a list of IPs using
    Team Cymru's DNS-based lookup service (no API key required).

    Query 1: {reversed_ip}.origin.asn.cymru.com TXT
             → "asn | prefix | country | rir | date"
    Query 2: AS{asn}.asn.cymru.com TXT
             → "asn | country | rir | date | org_name"
    """

    def __init__(self, ip_addresses: List[str]):
        self.ip_addresses = list(set(filter(None, ip_addresses)))

    @staticmethod
    def _make_resolver() -> dns.asyncresolver.Resolver:
        r = dns.asyncresolver.Resolver()
        r.timeout = DNS_TIMEOUT
        r.lifetime = DNS_TIMEOUT + 2
        return r

    @staticmethod
    def _reverse_ip(ip: str) -> Optional[str]:
        """Reverse an IPv4 address for PTR-style lookup. Returns None for non-IPv4."""
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        return ".".join(reversed(parts))

    async def _lookup_origin(self, ip: str) -> Optional[ASNData]:
        """Query Team Cymru origin for a single IP."""
        rev = self._reverse_ip(ip)
        if not rev:
            return None
        host = f"{rev}.origin.asn.cymru.com"
        try:
            resolver = self._make_resolver()
            answers = await resolver.resolve(host, "TXT")
            for rdata in answers:
                txt = "".join(
                    s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                    for s in rdata.strings
                ).strip()
                # Format: "asn | prefix | country | rir | date"
                parts = [p.strip() for p in txt.split("|")]
                if len(parts) >= 3:
                    asn = parts[0].strip()
                    prefix = parts[1].strip()
                    country = parts[2].strip()
                    org_name = await self._lookup_org(asn)
                    return ASNData(
                        asn=asn,
                        prefix=prefix,
                        country=country,
                        org_name=org_name,
                        sample_ip=ip,
                    )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        except Exception as e:
            logger.debug(f"ASN origin lookup error for {ip}: {e}")
        return None

    async def _lookup_org(self, asn: str) -> str:
        """Query Team Cymru for org name of an ASN."""
        host = f"AS{asn}.asn.cymru.com"
        try:
            resolver = self._make_resolver()
            answers = await resolver.resolve(host, "TXT")
            for rdata in answers:
                txt = "".join(
                    s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                    for s in rdata.strings
                ).strip()
                # Format: "asn | country | rir | date | org_name"
                parts = [p.strip() for p in txt.split("|")]
                if len(parts) >= 5:
                    return parts[4].strip()
        except Exception:
            pass
        return "Unknown"

    async def run(self) -> ASNScanResult:
        result = ASNScanResult()
        if not self.ip_addresses:
            return result

        sem = asyncio.Semaphore(10)
        seen_asns: Dict[str, bool] = {}

        async def process(ip: str):
            async with sem:
                data = await self._lookup_origin(ip)
                if data and data.asn not in seen_asns:
                    seen_asns[data.asn] = True
                    result.asn_records.append(data)
                    logger.debug(f"ASN {data.asn} ({data.org_name}) via {ip}")

        tasks = [process(ip) for ip in self.ip_addresses]
        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(
            f"ASNScanner: found {len(result.asn_records)} unique ASNs "
            f"from {len(self.ip_addresses)} IPs"
        )
        return result
