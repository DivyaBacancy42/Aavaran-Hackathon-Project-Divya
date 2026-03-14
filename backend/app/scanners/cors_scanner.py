"""CORS Misconfiguration Scanner

Tests each alive subdomain for CORS misconfigurations:
  1. Arbitrary origin reflection — sends a forged Origin, checks if server echoes it back
  2. Null origin — sends Origin: null, checks if accepted (sandbox/file bypass)

Severity matrix:
  CRITICAL — arbitrary origin echoed AND Access-Control-Allow-Credentials: true
  HIGH     — arbitrary origin echoed (no credentials)
  MEDIUM   — null origin accepted (with or without credentials)

No API key required. Pure HTTP.
"""
import asyncio
import logging
from dataclasses import dataclass
from typing import List, Optional

import httpx

logger = logging.getLogger(__name__)

TIMEOUT = 10.0
EVIL_ORIGIN = "https://evil-attacker.com"
NULL_ORIGIN = "null"


@dataclass
class CORSResult:
    hostname: str
    is_vulnerable: bool = False
    misconfig_type: Optional[str] = None   # "arbitrary_origin_reflected" | "null_origin"
    allowed_origin: Optional[str] = None   # value of ACAO header the server returned
    allow_credentials: bool = False        # True if ACAC: true
    severity: Optional[str] = None        # critical / high / medium


class CORSScanner:
    """
    Tests alive subdomains for CORS misconfigurations.
    Only stores results for vulnerable hosts.
    """

    def __init__(self, hostnames: List[str]):
        self.hostnames = hostnames

    async def run(self) -> List[CORSResult]:
        if not self.hostnames:
            return []

        sem = asyncio.Semaphore(10)
        results: List[CORSResult] = []

        async with httpx.AsyncClient(
            timeout=TIMEOUT,
            follow_redirects=True,
            verify=False,
        ) as client:

            async def check(hostname: str):
                async with sem:
                    try:
                        r = await _check_cors(client, hostname)
                        if r.is_vulnerable:
                            results.append(r)
                    except Exception as e:
                        logger.debug(f"CORSScanner: error for {hostname}: {e}")

            await asyncio.gather(
                *[check(h) for h in self.hostnames],
                return_exceptions=True,
            )

        logger.info(
            f"CORSScanner: checked {len(self.hostnames)}, "
            f"{len(results)} vulnerable"
        )
        return results


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _check_cors(client: httpx.AsyncClient, hostname: str) -> CORSResult:
    result = CORSResult(hostname=hostname)

    for scheme in ("https", "http"):
        base_url = f"{scheme}://{hostname}"

        # Test 1: arbitrary origin reflection
        try:
            resp = await client.get(
                base_url,
                headers={"Origin": EVIL_ORIGIN},
            )
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").strip().lower() == "true"

            if acao == EVIL_ORIGIN:
                result.is_vulnerable = True
                result.allowed_origin = acao
                result.allow_credentials = acac
                result.misconfig_type = "arbitrary_origin_reflected"
                result.severity = "critical" if acac else "high"
                return result

            # Test 2: null origin
            resp2 = await client.get(
                base_url,
                headers={"Origin": NULL_ORIGIN},
            )
            acao2 = resp2.headers.get("access-control-allow-origin", "")
            acac2 = resp2.headers.get("access-control-allow-credentials", "").strip().lower() == "true"

            if acao2 == "null":
                result.is_vulnerable = True
                result.allowed_origin = "null"
                result.allow_credentials = acac2
                result.misconfig_type = "null_origin"
                result.severity = "high" if acac2 else "medium"
                return result

            # Got a valid response — no need to try HTTP fallback
            break
        except Exception:
            continue  # try next scheme

    return result
