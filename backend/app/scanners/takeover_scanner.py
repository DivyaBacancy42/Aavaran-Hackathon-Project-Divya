"""Subdomain Takeover Detection Scanner

Feature 26: Subdomain Takeover Detection

Detects dangling CNAME records that point to unclaimed resources on external
services (GitHub Pages, AWS S3, Heroku, Netlify, Azure, Fastly, etc.).

Method:
  1. Resolve the CNAME chain for each subdomain (via dnspython in a thread)
  2. Check if the CNAME target matches a known cloud/SaaS provider suffix
  3. Fetch HTTP response body and compare against known "not found" fingerprints
  4. Flag as potentially vulnerable if a fingerprint matches

NOTE: These are *potential* takeovers requiring manual confirmation.
"""
import asyncio
import logging
from dataclasses import dataclass
from typing import List, Optional

import dns.resolver
import httpx

logger = logging.getLogger(__name__)

TIMEOUT = 8.0

# Fingerprints derived from:
# - https://github.com/EdOverflow/can-i-take-over-xyz
# - https://github.com/haccer/subjack
# Each entry: cname suffixes to match + HTTP body patterns that confirm unclaimed
FINGERPRINTS = [
    {
        "service": "GitHub Pages",
        "cname_suffixes": ["github.io", "github.com"],
        "body_patterns": [
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        "severity": "high",
    },
    {
        "service": "AWS S3",
        "cname_suffixes": ["s3.amazonaws.com", "s3-website"],
        "body_patterns": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "severity": "critical",
    },
    {
        "service": "Heroku",
        "cname_suffixes": ["herokuapp.com", "herokudns.com"],
        "body_patterns": ["No such app", "herokucdn.com/error-pages/no-such-app"],
        "severity": "high",
    },
    {
        "service": "Netlify",
        "cname_suffixes": ["netlify.app", "netlify.com"],
        "body_patterns": ["Not Found - Request ID", "page not found"],
        "severity": "medium",
    },
    {
        "service": "Shopify",
        "cname_suffixes": ["myshopify.com"],
        "body_patterns": [
            "Sorry, this shop is currently unavailable.",
            "Only one step away from your new Shopify store",
        ],
        "severity": "high",
    },
    {
        "service": "Surge.sh",
        "cname_suffixes": ["surge.sh"],
        "body_patterns": ["project not found", "ERR_NGROK_3200"],
        "severity": "medium",
    },
    {
        "service": "Azure App Service",
        "cname_suffixes": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net"],
        "body_patterns": [
            "404 Web Site not found",
            "does not exist in Windows Azure",
            "Web App - Unavailable",
        ],
        "severity": "high",
    },
    {
        "service": "Fastly",
        "cname_suffixes": ["fastly.net"],
        "body_patterns": [
            "Fastly error: unknown domain",
            "Please check that this domain",
        ],
        "severity": "medium",
    },
    {
        "service": "Ghost",
        "cname_suffixes": ["ghost.io"],
        "body_patterns": [
            "The thing you were looking for is no longer here",
            "404 - Ghost - The Professional Publishing Platform",
        ],
        "severity": "medium",
    },
    {
        "service": "Zendesk",
        "cname_suffixes": ["zendesk.com"],
        "body_patterns": ["Help Center Closed", "Oops, this help center no longer exists"],
        "severity": "low",
    },
    {
        "service": "Bitbucket",
        "cname_suffixes": ["bitbucket.io"],
        "body_patterns": ["Repository not found"],
        "severity": "medium",
    },
    {
        "service": "WordPress.com",
        "cname_suffixes": ["wordpress.com"],
        "body_patterns": ["Do you want to register", "doesn't exist"],
        "severity": "medium",
    },
    {
        "service": "Tumblr",
        "cname_suffixes": ["tumblr.com"],
        "body_patterns": [
            "Whatever you were looking for doesn't currently exist at this address",
        ],
        "severity": "medium",
    },
    {
        "service": "Squarespace",
        "cname_suffixes": ["squarespace.com"],
        "body_patterns": ["No Such Account", "You may have mistyped the address"],
        "severity": "medium",
    },
    {
        "service": "AWS CloudFront",
        "cname_suffixes": ["cloudfront.net"],
        "body_patterns": [
            "ERROR: The request could not be satisfied",
            "The distribution is not configured to allow the HTTP request method",
        ],
        "severity": "medium",
    },
    {
        "service": "Render",
        "cname_suffixes": ["onrender.com"],
        "body_patterns": ["Service not found", "Site Not Found"],
        "severity": "medium",
    },
    {
        "service": "Fly.io",
        "cname_suffixes": ["fly.dev", "fly.io"],
        "body_patterns": ["404 Not Found - fly.io"],
        "severity": "medium",
    },
    {
        "service": "Pantheon",
        "cname_suffixes": ["pantheonsite.io"],
        "body_patterns": ["404 error unknown site!", "The gods are wise"],
        "severity": "medium",
    },
    {
        "service": "WP Engine",
        "cname_suffixes": ["wpengine.com"],
        "body_patterns": [
            "The site you were looking for couldn't be found",
            "destination is misconfigured",
        ],
        "severity": "medium",
    },
    {
        "service": "Help Scout",
        "cname_suffixes": ["helpscoutdocs.com", "helpscout.net"],
        "body_patterns": ["No settings were found for this company:"],
        "severity": "low",
    },
]


@dataclass
class TakeoverResult:
    hostname: str
    is_vulnerable: bool
    service: Optional[str] = None
    cname_target: Optional[str] = None
    fingerprint: Optional[str] = None
    severity: Optional[str] = None


class TakeoverScanner:
    """
    Detects potential subdomain takeovers via CNAME resolution + HTTP body
    fingerprinting against 20+ known cloud/SaaS providers.
    """

    def __init__(self, hostnames: List[str], timeout: float = TIMEOUT):
        self.hostnames = list(set(filter(None, hostnames)))
        self.timeout = timeout

    async def run(self) -> List[TakeoverResult]:
        if not self.hostnames:
            return []

        sem = asyncio.Semaphore(10)
        results: List[TakeoverResult] = []

        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=False,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=5),
        ) as client:

            async def check(hostname: str):
                async with sem:
                    try:
                        r = await self._check(client, hostname)
                        results.append(r)
                    except Exception as e:
                        logger.debug(f"TakeoverScanner: error for {hostname}: {e}")
                        results.append(TakeoverResult(hostname=hostname, is_vulnerable=False))

            await asyncio.gather(*[check(h) for h in self.hostnames], return_exceptions=True)

        vulnerable = sum(1 for r in results if r.is_vulnerable)
        logger.info(
            f"TakeoverScanner: checked {len(results)} hosts, "
            f"{vulnerable} potentially vulnerable"
        )
        return results

    async def _check(self, client: httpx.AsyncClient, hostname: str) -> TakeoverResult:
        # Step 1: resolve CNAME in thread (dnspython is sync)
        cname_target = await asyncio.to_thread(self._resolve_cname, hostname)
        if not cname_target:
            return TakeoverResult(hostname=hostname, is_vulnerable=False)

        # Step 2: find matching fingerprints by CNAME suffix
        matched = [
            fp for fp in FINGERPRINTS
            if any(suffix in cname_target for suffix in fp["cname_suffixes"])
        ]
        if not matched:
            return TakeoverResult(hostname=hostname, is_vulnerable=False)

        # Step 3: fetch HTTP response body (HTTPS first, fall back to HTTP)
        body = ""
        for scheme in ("https", "http"):
            try:
                resp = await client.get(f"{scheme}://{hostname}/")
                body = resp.text
                break
            except Exception:
                continue

        if not body:
            return TakeoverResult(hostname=hostname, is_vulnerable=False)

        # Step 4: match body against fingerprints
        for fp in matched:
            for pattern in fp["body_patterns"]:
                if pattern.lower() in body.lower():
                    return TakeoverResult(
                        hostname=hostname,
                        is_vulnerable=True,
                        service=fp["service"],
                        cname_target=cname_target,
                        fingerprint=pattern,
                        severity=fp["severity"],
                    )

        return TakeoverResult(hostname=hostname, is_vulnerable=False)

    def _resolve_cname(self, hostname: str) -> Optional[str]:
        """Resolve CNAME record for hostname; return final target or None."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 5.0
            answers = resolver.resolve(hostname, "CNAME")
            return str(answers[0].target).rstrip(".")
        except Exception:
            return None
