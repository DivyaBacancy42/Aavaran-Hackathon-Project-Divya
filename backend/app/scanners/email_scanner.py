import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Optional, List

import dns.asyncresolver
import dns.exception

logger = logging.getLogger(__name__)

DNS_TIMEOUT = 10  # Bumped for reliability on slower networks

# Common DKIM selectors to probe (configurable; top 8 for perf)
DKIM_SELECTORS = [
    "default", "google", "s1", "s2", "k1", "mail", "selector1", "sendgrid"
]


@dataclass
class EmailScanResult:
    """Holds DNS scan results for email auth. None values indicate missing/failure."""
    # SPF
    spf_record: Optional[str] = None
    spf_valid: Optional[bool] = None       # True = has -all or ~all, False = missing or +all
    spf_mechanism: Optional[str] = None    # "hard_fail", "soft_fail", "neutral", "open"

    # DKIM
    dkim_found: bool = False
    dkim_selector: Optional[str] = None    # which selector hit
    dkim_record: Optional[str] = None      # full TXT record for debugging

    # DMARC
    dmarc_record: Optional[str] = None
    dmarc_policy: Optional[str] = None     # none | quarantine | reject
    dmarc_pct: Optional[int] = None        # integer 0-100, parsed from pct= tag (default 100)

    # MTA-STS
    mta_sts_mode: Optional[str] = None     # "enforce", "testing", "none", or None if not found

    # Verdict
    is_spoofable: Optional[bool] = None

    # Errors
    errors: List[str] = field(default_factory=list)  # Collect all check errors


class EmailScanner:
    """
    Checks email authentication configuration for a domain:
      - SPF  : TXT record on the apex domain (v=spf1 ...)
      - DKIM : TXT record at {selector}._domainkey.{domain}
      - DMARC: TXT record at _dmarc.{domain}

    Computes a spoofability verdict:
      Spoofable = SPF weak/missing  AND  DMARC missing/none-policy
    """

    def __init__(self, domain: str, selectors: Optional[List[str]] = None):
        # Validate and normalize domain
        domain = domain.strip('.').lower()
        if not domain or not re.match(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$',
            domain
        ):
            raise ValueError(f"Invalid domain: {domain}")
        self.domain = domain

        # Configurable selectors
        self.selectors = selectors or DKIM_SELECTORS

    @staticmethod
    def _make_resolver() -> dns.asyncresolver.Resolver:
        """Each check gets its own resolver to avoid shared-state failures."""
        r = dns.asyncresolver.Resolver()
        r.timeout = DNS_TIMEOUT
        r.lifetime = DNS_TIMEOUT + 2  # Extra headroom for retries
        return r

    async def run(self) -> EmailScanResult:
        """Run all checks in parallel and compute verdict."""
        result = EmailScanResult()
        errors = []

        try:
            # Parallel checks with independent resolvers
            spf, dkim, dmarc, mta_sts = await asyncio.gather(
                self._check_spf(self._make_resolver()),
                self._check_dkim(self._make_resolver()),  # Shared resolver for probes now feasible with fewer
                self._check_dmarc(self._make_resolver()),
                self._check_mta_sts(self._make_resolver()),
                return_exceptions=True,
            )

            # Process SPF
            if isinstance(spf, tuple):
                result.spf_record, result.spf_valid, result.spf_mechanism = spf
                if result.spf_valid is False and result.spf_record:
                    logger.info(f"Weak SPF on {self.domain}: {result.spf_record}")
            else:
                err_msg = f"SPF check failed: {str(spf) if isinstance(spf, Exception) else 'Unknown error'}"
                errors.append(err_msg)
                logger.warning(err_msg)

            # Process DKIM
            if isinstance(dkim, tuple):
                result.dkim_found, result.dkim_selector, result.dkim_record = dkim
                if result.dkim_found:
                    logger.info(f"DKIM found on {self.domain} via selector: {result.dkim_selector}")
            else:
                err_msg = f"DKIM check failed: {str(dkim) if isinstance(dkim, Exception) else 'Unknown error'}"
                errors.append(err_msg)
                logger.warning(err_msg)

            # Process DMARC
            if isinstance(dmarc, tuple):
                result.dmarc_record, result.dmarc_policy, result.dmarc_pct = dmarc
                if result.dmarc_policy == "invalid":
                    errors.append(f"DMARC record malformed on {self.domain}")
            else:
                err_msg = f"DMARC check failed: {str(dmarc) if isinstance(dmarc, Exception) else 'Unknown error'}"
                errors.append(err_msg)
                logger.warning(err_msg)

            # Process MTA-STS (optional — failure does not affect verdict)
            if isinstance(mta_sts, Exception):
                logger.debug(f"MTA-STS check error for {self.domain}: {mta_sts}")
            else:
                result.mta_sts_mode = mta_sts  # str or None

            # Set errors
            result.errors = errors
            if errors:
                logger.error(f"Errors during scan of {self.domain}: {'; '.join(errors)}")
                return result  # Early return: no verdict on major failures

            # Compute verdict only on complete data
            result.is_spoofable = self._compute_spoofable(result)

            logger.info(
                f"EmailScanner for {self.domain}: "
                f"SPF={'ok' if result.spf_valid else 'weak/missing'} (mechanism={result.spf_mechanism}), "
                f"DKIM={'found' if result.dkim_found else 'not found'}, "
                f"DMARC={result.dmarc_policy or 'missing'} (pct={result.dmarc_pct}), "
                f"MTA-STS={result.mta_sts_mode or 'not found'}, "
                f"spoofable={result.is_spoofable}"
            )
        except Exception as e:
            logger.error(f"EmailScanner failed for {self.domain}: {e}")
            result.errors.append(str(e))
        return result

    # ── SPF ───────────────────────────────────────────────────────────────────

    async def _check_spf(self, resolver) -> tuple:
        """Returns (spf_record_str, spf_valid_bool, mechanism_str)."""
        try:
            answers = await resolver.resolve(self.domain, "TXT")
            for rdata in answers:
                txt = "".join(
                    s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                    for s in rdata.strings
                )
                if txt.lower().startswith("v=spf1"):
                    valid = self._spf_is_strong(txt)
                    mechanism = self._spf_mechanism(txt)
                    return txt, valid, mechanism
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            pass  # No record = weak
        except Exception as e:
            logger.debug(f"SPF check error for {self.domain}: {e}")
        return None, None, "open"  # no SPF record found → open

    @staticmethod
    def _spf_is_strong(record: str) -> bool:
        """
        Strong SPF = ends with -all (hard fail) or ~all (soft fail).
        Weak/open = +all, ?all, or no explicit all.
        Heuristic per RFC 7208.
        """
        record_lower = record.lower()
        if "+all" in record_lower:
            return False   # explicitly allows everything — useless
        if "-all" in record_lower or "~all" in record_lower:
            return True
        return False       # missing "all" directive

    @staticmethod
    def _spf_mechanism(record: str) -> str:
        """Return the enforcement mechanism string from an SPF record."""
        r = record.lower()
        if "-all" in r:
            return "hard_fail"
        if "~all" in r:
            return "soft_fail"
        if "?all" in r:
            return "neutral"
        return "open"  # +all or no all directive

    # ── DKIM ─────────────────────────────────────────────────────────────────

    async def _check_dkim(self, resolver) -> tuple:
        """Probe common DKIM selectors. Returns (found_bool, selector_str, record_str).
        Validates v=DKIM1 in record."""
        sem = asyncio.Semaphore(5)  # Throttled concurrency

        async def probe(selector: str):
            async with sem:
                host = f"{selector}._domainkey.{self.domain}"
                try:
                    answers = await resolver.resolve(host, "TXT")
                    for rdata in answers:  # Take first valid
                        txt = "".join(
                            s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                            for s in rdata.strings
                        )
                        if txt.lower().startswith("v=dkim1"):
                            return selector, txt  # Valid DKIM found
                except Exception:
                    pass
            return None, None

        # Probe in parallel
        tasks = [probe(s) for s in self.selectors]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, tuple) and res[0]:
                return True, res[0], res[1]
            elif isinstance(res, Exception):
                logger.debug(f"DKIM probe error for {self.domain} ({res[0] if isinstance(res, tuple) else 'unknown'}): {res}")

        logger.debug(f"No valid DKIM selectors found for {self.domain}; custom may be in use.")
        return False, None, None

    # ── DMARC ─────────────────────────────────────────────────────────────────

    async def _check_dmarc(self, resolver) -> tuple:
        """Returns (dmarc_record_str, policy_str, pct_int)."""
        host = f"_dmarc.{self.domain}"
        try:
            answers = await resolver.resolve(host, "TXT")
            for rdata in answers:
                txt = "".join(
                    s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                    for s in rdata.strings
                )
                if "v=dmarc1" in txt.lower():   # case-insensitive match
                    policy = self._parse_dmarc_policy(txt)
                    if policy is None:
                        policy = "invalid"  # Malformed record
                    pct = self._parse_dmarc_pct(txt)
                    return txt, policy, pct
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        except Exception as e:
            logger.debug(f"DMARC check error for {self.domain}: {e}")
        return None, None, None

    @staticmethod
    def _parse_dmarc_policy(record: str) -> Optional[str]:
        """Extract primary policy (p=) from DMARC record."""
        for part in record.split(";"):
            kv = [p.strip() for p in part.split("=", 1)]
            if len(kv) == 2 and kv[0].lower() == "p":
                return kv[1].lower()
        return None

    @staticmethod
    def _parse_dmarc_pct(record: str) -> int:
        """Extract pct= tag from DMARC record. Returns 0-100 int, defaults to 100 per RFC 7489."""
        for part in record.split(";"):
            kv = [p.strip() for p in part.split("=", 1)]
            if len(kv) == 2 and kv[0].lower() == "pct":
                try:
                    return max(0, min(100, int(kv[1])))
                except ValueError:
                    pass
        return 100  # default per RFC 7489

    # ── MTA-STS ───────────────────────────────────────────────────────────────

    async def _check_mta_sts(self, resolver) -> Optional[str]:
        """Query _mta-sts.{domain} TXT record. Returns mode string or None."""
        host = f"_mta-sts.{self.domain}"
        try:
            answers = await resolver.resolve(host, "TXT")
            for rdata in answers:
                txt = "".join(
                    s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                    for s in rdata.strings
                )
                if txt.lower().startswith("v=stsv1"):
                    # parse mode= tag
                    for part in txt.split(";"):
                        kv = [p.strip() for p in part.split("=", 1)]
                        if len(kv) == 2 and kv[0].lower() == "mode":
                            return kv[1].lower()  # "enforce", "testing", or "none"
                    return "none"  # v=STSv1 present but no mode
        except Exception:
            pass
        return None

    # ── Spoofability verdict ───────────────────────────────────────────────────

    @staticmethod
    def _compute_spoofable(result: EmailScanResult) -> bool:
        """
        A domain is spoofable when an attacker can send email that passes
        basic checks. This happens when:
          - SPF is missing or weak (no -all / ~all)   AND
          - DMARC is missing or set to p=none
        If either SPF is strong OR DMARC enforces quarantine/reject,
        spoofing is much harder.
        DKIM presence noted but not required for non-spoofable (SPF/DMARC suffice).
        """
        spf_weak = not result.spf_valid   # None (missing) also counts as weak
        dmarc_weak = (
            result.dmarc_policy is None       # no DMARC at all
            or result.dmarc_policy == "none"  # monitoring only — no enforcement
            or result.dmarc_policy == "invalid"
        )
        return spf_weak and dmarc_weak