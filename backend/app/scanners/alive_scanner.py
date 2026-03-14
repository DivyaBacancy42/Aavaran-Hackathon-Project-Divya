import asyncio
import logging
import re
from dataclasses import dataclass
from typing import List, Optional

import httpx

logger = logging.getLogger(__name__)

TIMEOUT = 8          # seconds per request
CONCURRENCY = 20     # simultaneous HTTP connections
MAX_BODY = 50_000    # bytes to read for title extraction

TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,200})", re.IGNORECASE)

# Suppress SSL warnings for self-signed certs on internal subdomains
import warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")


@dataclass
class AliveResult:
    hostname: str
    is_alive: bool
    http_status: Optional[int] = None
    page_title: Optional[str] = None


class AliveScanner:
    """
    Probes each subdomain over HTTPS (then HTTP fallback).
    Populates: is_alive, http_status, page_title.
    Runs concurrently with a semaphore to avoid overwhelming the network.
    """

    def __init__(self, hostnames: List[str]):
        self.hostnames = hostnames

    async def run(self) -> List[AliveResult]:
        if not self.hostnames:
            return []

        sem = asyncio.Semaphore(CONCURRENCY)
        tasks = [self._check(sem, h) for h in self.hostnames]
        raw = await asyncio.gather(*tasks, return_exceptions=True)

        results = []
        for r in raw:
            if isinstance(r, AliveResult):
                results.append(r)
            # exceptions are silently dropped — scanner is best-effort

        alive = sum(1 for r in results if r.is_alive)
        logger.info(
            f"AliveScanner: {alive}/{len(self.hostnames)} subdomains responded"
        )
        return results

    async def _check(self, sem: asyncio.Semaphore, hostname: str) -> AliveResult:
        async with sem:
            for scheme in ("https", "http"):
                url = f"{scheme}://{hostname}"
                try:
                    async with httpx.AsyncClient(
                        timeout=TIMEOUT,
                        follow_redirects=True,
                        verify=False,       # accept self-signed certs
                        limits=httpx.Limits(max_connections=1),
                    ) as client:
                        resp = await client.get(
                            url,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; SHODH-Scanner/1.0)"},
                        )
                        # Only read enough HTML to find the title
                        body = resp.text[:MAX_BODY]
                        title = self._extract_title(body)

                        return AliveResult(
                            hostname=hostname,
                            is_alive=True,
                            http_status=resp.status_code,
                            page_title=title,
                        )
                except (httpx.ConnectError, httpx.ConnectTimeout,
                        httpx.ReadTimeout, httpx.RemoteProtocolError):
                    continue   # try next scheme
                except Exception:
                    continue

            # Neither HTTPS nor HTTP responded
            return AliveResult(hostname=hostname, is_alive=False)

    @staticmethod
    def _extract_title(html: str) -> Optional[str]:
        m = TITLE_RE.search(html)
        if m:
            return m.group(1).strip()[:200] or None
        return None
