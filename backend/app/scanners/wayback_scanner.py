"""Wayback Machine CDX API scanner — Historical Endpoint Discovery

Queries the Wayback Machine CDX API for all archived URLs under a domain.
Free, no API key required. Returns up to 500 unique paths categorized
by security relevance (API endpoints, admin panels, config files, backups, etc.).
"""
import asyncio
import logging
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

CDX_URL = (
    "http://web.archive.org/cdx/search/cdx"
    "?url=*.{domain}&output=json&fl=original,statuscode,mimetype,timestamp"
    "&collapse=urlkey&limit=500&filter=statuscode:200"
)
CDX_TIMEOUT = 30.0

# ── Security-relevant path classification ─────────────────────────────────────
_CATEGORY_RULES: List[tuple] = [
    # (category, set_of_path_fragments_any_of_which_match)
    ("api",      {"/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc/"}),
    ("admin",    {"/admin", "/dashboard", "/manager", "/control", "/cp/", "/panel"}),
    ("config",   {".env", ".config", "config.", "/settings", "/configuration", ".yaml", ".yml", ".json", ".xml", ".ini", ".conf"}),
    ("backup",   {".bak", ".backup", ".old", ".orig", ".sql", ".dump", ".tar", ".gz", ".zip", ".rar"}),
    ("auth",     {"/login", "/logout", "/signin", "/signup", "/oauth", "/auth/", "/sso", "/token", "/register"}),
    ("debug",    {"/debug", "/trace", "/test", "/phpinfo", "/.git", "/.svn", "/phpMyAdmin", "/actuator", "/metrics", "/health", "/status", "/__debug__", "/console"}),
    ("upload",   {"/upload", "/uploads", "/files/", "/media/", "/static/"}),
]


def _classify(path: str) -> Optional[str]:
    p = path.lower()
    for category, fragments in _CATEGORY_RULES:
        for frag in fragments:
            if frag in p:
                return category
    return None


@dataclass
class WaybackFindingData:
    url: str
    status_code: Optional[str] = None
    mime_type: Optional[str] = None
    last_seen: Optional[str] = None
    category: Optional[str] = None


@dataclass
class WaybackScanResult:
    findings: List[WaybackFindingData] = field(default_factory=list)
    total_archived: int = 0
    error: Optional[str] = None


class WaybackScanner:
    """
    Fetches up to 500 unique archived URLs for a domain from the Wayback Machine CDX API.
    Filters to HTTP 200 responses and categorizes by security relevance.
    Only security-relevant paths are stored; generic HTML pages are skipped.
    """

    def __init__(self, domain: str):
        self.domain = domain

    async def run(self) -> WaybackScanResult:
        result = WaybackScanResult()
        try:
            url = CDX_URL.format(domain=self.domain)
            async with httpx.AsyncClient(timeout=CDX_TIMEOUT, follow_redirects=True) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                rows = resp.json()

            if not rows or len(rows) < 2:
                logger.info(f"WaybackScanner: no results for {self.domain}")
                return result

            # First row is the header ["original","statuscode","mimetype","timestamp"]
            header = rows[0]
            data_rows = rows[1:]
            result.total_archived = len(data_rows)

            seen_paths: set = set()
            for row in data_rows:
                if len(row) < 4:
                    continue
                orig_url = row[0]
                status_code = row[1]
                mime_type = row[2]
                timestamp = row[3]

                # Normalize to path for deduplication
                try:
                    parsed = urlparse(orig_url)
                    path = parsed.path or "/"
                except Exception:
                    continue

                # Skip if we've seen this path already
                if path in seen_paths:
                    continue
                seen_paths.add(path)

                # Classify — skip generic HTML pages with no security relevance
                category = _classify(path)
                if category is None:
                    # Only include non-categorized if it's not text/html (e.g., JS, JSON, XML)
                    mt = (mime_type or "").lower()
                    if "html" in mt or mt == "":
                        continue
                    category = "other"

                result.findings.append(WaybackFindingData(
                    url=orig_url,
                    status_code=status_code,
                    mime_type=mime_type or None,
                    last_seen=timestamp or None,
                    category=category,
                ))

            # Sort by category priority then URL
            _order = {"debug": 0, "admin": 1, "config": 2, "backup": 3, "api": 4, "auth": 5, "upload": 6, "other": 7}
            result.findings.sort(key=lambda f: (_order.get(f.category or "other", 7), f.url))

            logger.info(
                f"WaybackScanner: {result.total_archived} archived, "
                f"{len(result.findings)} security-relevant for {self.domain}"
            )
        except Exception as e:
            logger.error(f"WaybackScanner failed for {self.domain}: {e}")
            result.error = str(e)
        return result
