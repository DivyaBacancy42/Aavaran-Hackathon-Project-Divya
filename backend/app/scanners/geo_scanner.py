"""IP Geolocation + Hosting Provider Scanner — ip-api.com

Feature: IP Geolocation
Uses ip-api.com batch API — completely free, no API key, 1000 req/min.
Returns country, region, city, ISP, organization, ASN, and hosting flag
for every unique public IP address discovered during the scan.

Batch endpoint: POST http://ip-api.com/batch (up to 100 IPs per request)
Rate limit: 1000 queries/minute — we batch 100 at a time with no delays needed.
Private/loopback IPs are skipped (same logic as ReputationScanner).
"""
import asyncio
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)

BATCH_URL = "http://ip-api.com/batch"
BATCH_SIZE = 100
TIMEOUT = 15.0

_FIELDS = "status,country,countryCode,regionName,city,isp,org,as,hosting,query"


@dataclass
class GeoData:
    ip_address: str
    hostname: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    is_hosting: Optional[bool] = None


@dataclass
class GeoScanResult:
    locations: List[GeoData] = field(default_factory=list)
    error: Optional[str] = None


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address):
            return True
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True


class GeoScanner:
    """
    Looks up geolocation + hosting info for all unique public IPs via ip-api.com.
    Deduplicates IPs; uses batch endpoint (100 per request) for efficiency.
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

    async def run(self) -> GeoScanResult:
        result = GeoScanResult()
        if not self.targets:
            logger.info("GeoScanner: no public IPs to look up")
            return result

        # Build hostname lookup map: ip → first hostname
        host_map = {ip: hostname for ip, hostname in self.targets}
        ips = list(host_map.keys())

        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                # Process in batches of BATCH_SIZE
                for i in range(0, len(ips), BATCH_SIZE):
                    batch = ips[i : i + BATCH_SIZE]
                    payload = [{"query": ip, "fields": _FIELDS} for ip in batch]
                    try:
                        resp = await client.post(BATCH_URL, json=payload)
                        resp.raise_for_status()
                        rows = resp.json()
                        for row in rows:
                            if not isinstance(row, dict):
                                continue
                            if row.get("status") != "success":
                                continue
                            ip = row.get("query", "")
                            result.locations.append(GeoData(
                                ip_address=ip,
                                hostname=host_map.get(ip),
                                country=row.get("country"),
                                country_code=row.get("countryCode"),
                                region=row.get("regionName"),
                                city=row.get("city"),
                                isp=row.get("isp"),
                                org=row.get("org"),
                                asn=row.get("as"),
                                is_hosting=row.get("hosting"),
                            ))
                    except Exception as e:
                        logger.warning(f"GeoScanner: batch {i//BATCH_SIZE + 1} failed: {e}")

            logger.info(
                f"GeoScanner: resolved {len(result.locations)}/{len(ips)} IPs"
            )
        except Exception as e:
            logger.error(f"GeoScanner failed: {e}")
            result.error = str(e)

        return result
