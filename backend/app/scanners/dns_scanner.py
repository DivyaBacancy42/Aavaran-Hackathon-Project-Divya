import asyncio
import logging
from dataclasses import dataclass, field
from typing import List, Optional

import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

logger = logging.getLogger(__name__)


@dataclass
class DNSRecordData:
    record_type: str
    hostname: str
    value: str
    ttl: Optional[int] = None


@dataclass
class DNSScanResult:
    records: List[DNSRecordData] = field(default_factory=list)
    zone_transfer_successful: bool = False
    nameservers: List[str] = field(default_factory=list)
    error: Optional[str] = None


class DNSScanner:
    """
    Extracts DNS records for a domain and attempts zone transfer (AXFR).
    Zone transfer success is a critical misconfiguration finding.
    """

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]

    def __init__(self, domain: str):
        self.domain = domain

    # Public resolvers — reliable, no rate limits for standard queries
    _NAMESERVERS = ["8.8.8.8", "1.1.1.1", "8.8.4.4", "9.9.9.9"]

    async def run(self) -> DNSScanResult:
        """Run DNS extraction + zone transfer attempt asynchronously."""
        loop = asyncio.get_running_loop()
        try:
            result = await loop.run_in_executor(None, self._run_sync)
        except Exception as e:
            logger.error(f"DNSScanner failed for {self.domain}: {e}")
            result = DNSScanResult(error=str(e))
        return result

    def _make_resolver(self) -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = self._NAMESERVERS
        resolver.timeout = 5
        resolver.lifetime = 15
        return resolver

    def _run_sync(self) -> DNSScanResult:
        result = DNSScanResult()
        resolver = self._make_resolver()

        # ── Step 1: Extract standard DNS records ──────────────────────────
        for rtype in self.RECORD_TYPES:
            answers = None
            for attempt in range(2):  # retry once on timeout
                try:
                    answers = resolver.resolve(self.domain, rtype)
                    break
                except dns.exception.Timeout:
                    if attempt == 0:
                        logger.debug(f"DNS timeout on {rtype} for {self.domain}, retrying…")
                    continue
                except (
                    dns.resolver.NoAnswer,
                    dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers,
                ):
                    break
                except Exception as e:
                    logger.debug(f"DNS query {rtype} for {self.domain} failed: {e}")
                    break

            if answers is None:
                continue
            for rdata in answers:
                record = DNSRecordData(
                    record_type=rtype,
                    hostname=self.domain,
                    value=str(rdata),
                    ttl=int(answers.rrset.ttl),
                )
                result.records.append(record)
                if rtype == "NS":
                    result.nameservers.append(str(rdata).rstrip("."))

        # ── Step 2: Attempt zone transfer (AXFR) against each nameserver ──
        for ns in result.nameservers:
            try:
                xfr = dns.query.xfr(ns, self.domain, timeout=10, lifetime=15)
                zone = dns.zone.from_xfr(xfr)
                result.zone_transfer_successful = True
                logger.warning(
                    f"ZONE TRANSFER SUCCEEDED for {self.domain} via {ns} — "
                    f"critical misconfiguration!"
                )
                # Extract all records from the zone transfer
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        rtype_text = dns.rdatatype.to_text(rdataset.rdtype)
                        for rdata in rdataset:
                            name_str = str(name).rstrip(".")
                            if name_str in ("@", self.domain):
                                fqdn = self.domain
                            elif name_str.endswith(f".{self.domain}"):
                                fqdn = name_str
                            else:
                                fqdn = f"{name_str}.{self.domain}"
                            # Avoid duplicating records already extracted
                            already_exists = any(
                                r.hostname == fqdn
                                and r.record_type == rtype_text
                                and r.value == str(rdata)
                                for r in result.records
                            )
                            if not already_exists:
                                result.records.append(
                                    DNSRecordData(
                                        record_type=rtype_text,
                                        hostname=fqdn,
                                        value=str(rdata),
                                        ttl=int(rdataset.ttl),
                                    )
                                )
                break  # Stop after first successful transfer
            except Exception:
                pass  # Zone transfer refused — expected for secure nameservers

        logger.info(
            f"DNS scan complete for {self.domain}: "
            f"{len(result.records)} records, "
            f"zone_transfer={'SUCCESS' if result.zone_transfer_successful else 'refused'}"
        )
        return result
