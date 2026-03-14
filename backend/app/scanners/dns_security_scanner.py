"""DNS Security Scanner — DNSSEC validation + CAA record analysis

Feature: DNS Security
Checks:
  1. DNSSEC — queries DNSKEY records + checks AD (Authenticated Data) flag
     via Google's 8.8.8.8 resolver with DNSSEC enabled
  2. CAA — Certification Authority Authorization records: which CAs can
     issue certs, wildcard restrictions
  3. NS count — single nameserver is a SPOF (single point of failure)

All checks use dnspython (already installed). No external tools or API keys.
"""
import asyncio
import logging
import socket
from dataclasses import dataclass, field
from typing import List, Optional

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver

logger = logging.getLogger(__name__)

DNS_TIMEOUT = 5.0


@dataclass
class DNSSecurityData:
    dnssec_enabled: bool = False     # DNSKEY record exists
    dnssec_valid: bool = False       # AD flag set by validating resolver
    has_caa: bool = False
    caa_issuers: List[str] = field(default_factory=list)
    caa_wildcard_issuers: List[str] = field(default_factory=list)
    ns_count: int = 0
    issues: List[str] = field(default_factory=list)
    error: Optional[str] = None


class DNSSecurityScanner:
    """
    Performs DNSSEC validation and CAA record analysis for a domain.
    Uses dnspython synchronous API wrapped with asyncio.to_thread.
    """

    def __init__(self, domain: str):
        self.domain = domain

    async def run(self) -> DNSSecurityData:
        return await asyncio.to_thread(self._run_sync)

    def _run_sync(self) -> DNSSecurityData:
        data = DNSSecurityData()
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = DNS_TIMEOUT
            resolver.lifetime = DNS_TIMEOUT + 2

            # ── 1. NS count ────────────────────────────────────────────────
            try:
                ns_answers = resolver.resolve(self.domain, "NS")
                data.ns_count = len(list(ns_answers))
            except Exception:
                data.ns_count = 0

            # ── 2. DNSKEY existence ───────────────────────────────────────
            try:
                resolver.resolve(self.domain, "DNSKEY")
                data.dnssec_enabled = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                data.dnssec_enabled = False
            except Exception:
                data.dnssec_enabled = False

            # ── 3. DNSSEC validation via AD flag ──────────────────────────
            # Send query to 8.8.8.8 with DO (DNSSEC OK) bit set
            # If the resolver validates DNSSEC, it sets the AD flag in the response
            if data.dnssec_enabled:
                try:
                    qname = dns.name.from_text(self.domain)
                    request = dns.message.make_query(qname, dns.rdatatype.A, want_dnssec=True)
                    request.flags |= dns.flags.CD  # don't check locally, let server check
                    google_addr = socket.gethostbyname("8.8.8.8")
                    response = dns.query.udp(request, google_addr, timeout=DNS_TIMEOUT)
                    # AD flag means the resolver has validated the signatures
                    data.dnssec_valid = bool(response.flags & dns.flags.AD)
                except Exception as e:
                    logger.debug(f"DNSSecurityScanner: AD flag check failed for {self.domain}: {e}")
                    data.dnssec_valid = False

            # ── 4. CAA records ────────────────────────────────────────────
            try:
                caa_answers = resolver.resolve(self.domain, "CAA")
                data.has_caa = True
                for rdata in caa_answers:
                    tag = str(rdata.tag).lower()
                    value = str(rdata.value).strip('"')
                    if tag == "issue":
                        if value not in data.caa_issuers:
                            data.caa_issuers.append(value)
                    elif tag == "issuewild":
                        if value not in data.caa_wildcard_issuers:
                            data.caa_wildcard_issuers.append(value)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                data.has_caa = False
            except Exception:
                data.has_caa = False

            # ── 5. Build issues list ──────────────────────────────────────
            if not data.dnssec_enabled:
                data.issues.append("No DNSSEC — zone is not signed; DNS responses can be spoofed")
            elif not data.dnssec_valid:
                data.issues.append("DNSSEC configured but not validated by resolver")

            if not data.has_caa:
                data.issues.append("No CAA record — any CA can issue certificates for this domain")

            if data.ns_count == 1:
                data.issues.append("Single nameserver — creates a single point of failure")
            elif data.ns_count == 0:
                data.issues.append("No NS records found")

            logger.info(
                f"DNSSecurityScanner: {self.domain} — "
                f"DNSSEC={'enabled' if data.dnssec_enabled else 'none'} "
                f"valid={data.dnssec_valid} CAA={data.has_caa} NS={data.ns_count} "
                f"issues={len(data.issues)}"
            )
        except Exception as e:
            logger.error(f"DNSSecurityScanner failed for {self.domain}: {e}")
            data.error = str(e)
        return data
