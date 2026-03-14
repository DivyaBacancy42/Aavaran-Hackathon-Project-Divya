import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

# Security headers to check — ordered by importance
SECURITY_HEADERS = [
    {"name": "strict-transport-security",  "label": "HSTS",              "severity": "HIGH"},
    {"name": "content-security-policy",    "label": "CSP",               "severity": "HIGH"},
    {"name": "x-frame-options",            "label": "X-Frame-Options",   "severity": "MEDIUM"},
    {"name": "x-content-type-options",     "label": "X-Content-Type-Options", "severity": "MEDIUM"},
    {"name": "referrer-policy",            "label": "Referrer-Policy",   "severity": "LOW"},
    {"name": "permissions-policy",         "label": "Permissions-Policy","severity": "LOW"},
]

# Score weights per severity (total = 100)
# 2×HIGH=30 + 2×MEDIUM=15 + 2×LOW=5  →  60+30+10 = 100
SEVERITY_WEIGHTS: Dict[str, int] = {"HIGH": 30, "MEDIUM": 15, "LOW": 5}


@dataclass
class HeaderScanResult:
    hostname: str
    # Security header presence & values
    has_hsts: bool = False
    hsts_value: Optional[str] = None
    has_csp: bool = False
    csp_value: Optional[str] = None
    has_x_frame_options: bool = False
    x_frame_options_value: Optional[str] = None
    has_x_content_type_options: bool = False
    has_referrer_policy: bool = False
    referrer_policy_value: Optional[str] = None
    has_permissions_policy: bool = False
    # Info disclosure
    server_banner: Optional[str] = None
    x_powered_by: Optional[str] = None
    # Redirect info
    redirect_count: int = 0
    final_url: Optional[str] = None
    # Computed security score (0–100) and list of missing header labels
    security_score: int = 0
    missing_headers: List[str] = field(default_factory=list)
    error: Optional[str] = None


class HeaderScanner:
    """
    Analyzes HTTP security headers for alive subdomains.
    Probes HTTPS first, falls back to HTTP.
    Computes a 0–100 security score weighted by header criticality.
    Uses httpx — no external tools required.
    """

    def __init__(self, hostnames: List[str], timeout: float = 8.0):
        self.hostnames = list(set(filter(None, hostnames)))
        self.timeout = timeout

    def _analyze(self, hostname: str, resp: httpx.Response) -> HeaderScanResult:
        result = HeaderScanResult(hostname=hostname)
        h = {k.lower(): v for k, v in resp.headers.items()}

        # Security headers
        result.has_hsts = "strict-transport-security" in h
        result.hsts_value = h.get("strict-transport-security")

        result.has_csp = "content-security-policy" in h
        result.csp_value = h.get("content-security-policy")

        result.has_x_frame_options = "x-frame-options" in h
        result.x_frame_options_value = h.get("x-frame-options")

        result.has_x_content_type_options = "x-content-type-options" in h

        result.has_referrer_policy = "referrer-policy" in h
        result.referrer_policy_value = h.get("referrer-policy")

        result.has_permissions_policy = "permissions-policy" in h

        # Info disclosure
        result.server_banner = h.get("server")
        result.x_powered_by = h.get("x-powered-by")

        # Redirect tracking
        result.redirect_count = len(resp.history)
        result.final_url = str(resp.url)

        # Score computation
        present_map = {
            "strict-transport-security": result.has_hsts,
            "content-security-policy":   result.has_csp,
            "x-frame-options":           result.has_x_frame_options,
            "x-content-type-options":    result.has_x_content_type_options,
            "referrer-policy":           result.has_referrer_policy,
            "permissions-policy":        result.has_permissions_policy,
        }
        total = sum(SEVERITY_WEIGHTS.get(entry["severity"], 0) for entry in SECURITY_HEADERS)
        earned = sum(
            SEVERITY_WEIGHTS.get(entry["severity"], 0)
            for entry in SECURITY_HEADERS
            if present_map.get(entry["name"], False)
        )
        result.security_score = int(earned / total * 100) if total > 0 else 0

        result.missing_headers = [
            entry["label"]
            for entry in SECURITY_HEADERS
            if not present_map.get(entry["name"], False)
        ]

        logger.debug(
            f"HeaderScanner: {hostname} → score={result.security_score}, "
            f"missing={result.missing_headers}"
        )
        return result

    async def _probe(self, client: httpx.AsyncClient, hostname: str) -> HeaderScanResult:
        for scheme in ("https", "http"):
            try:
                resp = await client.get(f"{scheme}://{hostname}/", follow_redirects=True)
                return self._analyze(hostname, resp)
            except Exception:
                continue
        return HeaderScanResult(hostname=hostname, error="No response")

    async def run(self) -> List[HeaderScanResult]:
        if not self.hostnames:
            return []

        results: List[HeaderScanResult] = []
        sem = asyncio.Semaphore(10)
        limits = httpx.Limits(max_connections=20, max_keepalive_connections=5)

        async with httpx.AsyncClient(
            timeout=self.timeout,
            limits=limits,
            verify=False,
            follow_redirects=True,
        ) as client:

            async def probe(hostname: str):
                async with sem:
                    try:
                        r = await self._probe(client, hostname)
                        results.append(r)
                    except Exception as e:
                        logger.debug(f"HeaderScanner error for {hostname}: {e}")
                        results.append(HeaderScanResult(hostname=hostname, error=str(e)))

            await asyncio.gather(*[probe(h) for h in self.hostnames], return_exceptions=True)

        logger.info(f"HeaderScanner: analyzed {len(results)} subdomains")
        return results
