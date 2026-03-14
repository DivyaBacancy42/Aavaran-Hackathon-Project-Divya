"""CVE Lookup Scanner — NIST NVD API 2.0

Feature 24: CVE Lookup
Feature 25: CVE Severity Scoring

Queries the free NIST National Vulnerability Database API for CVEs matching
each detected technology + version.

Reliability improvements:
  - Retry with backoff on 403 / 429 / 503 / timeout (NVD is flaky without a key)
  - Flexible relevance filter using name tokens (handles "Apache HTTP Server" → "apache")
  - Tech-name alias map so NVD descriptions are matched correctly
  - Only queries techs with a detected version (no-version searches return noise)

Rate limit (no API key): 5 req / 30 s  →  6 s sequential delay + retry backoff.
"""
import asyncio
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_PER_TECH = 5      # top N CVEs per technology (by CVSS score)
REQUEST_DELAY = 6.5   # seconds between requests (NVD public rate limit: 5/30s)
TIMEOUT = 30.0
MAX_RETRIES = 3       # retry on rate-limit / timeout

# Map tech names (as stored by TechScanner) → search keyword(s) for NVD.
# When a tech name doesn't appear verbatim in NVD descriptions, an alias fixes it.
_TECH_ALIASES: Dict[str, str] = {
    # ── Web Servers ──────────────────────────────────────────────────────────
    "Apache HTTP Server": "apache httpd",
    "Apache":             "apache httpd",
    "Nginx":              "nginx",
    "IIS":                "microsoft iis",
    "Microsoft IIS":      "microsoft iis",
    "LiteSpeed":          "litespeed",
    "Caddy":              "caddy",               # caddyserver/caddy
    "OpenResty":          "openresty",            # nginx + LuaJIT
    "Cherokee":           "cherokee",             # old web server, has CVEs
    "Gunicorn":           "gunicorn",
    "Uvicorn":            "uvicorn",
    # ── Proxy / Cache ────────────────────────────────────────────────────────
    "Varnish":            "varnish",
    "Squid":              "squid",
    "HAProxy":            "haproxy",
    "Traefik":            "traefik",
    # ── Languages & Runtimes ─────────────────────────────────────────────────
    "PHP":                "php",
    "OpenSSL":            "openssl",
    "ASP.NET":            "asp.net",
    # ── Databases ────────────────────────────────────────────────────────────
    "MySQL":              "mysql",
    "MariaDB":            "mariadb",
    "PostgreSQL":         "postgresql",
    "MongoDB":            "mongodb",
    "Redis":              "redis",
    "Elasticsearch":      "elasticsearch",
    "CouchDB":            "couchdb",
    "Memcached":          "memcached",
    # ── Java App Servers & Frameworks ────────────────────────────────────────
    "Tomcat":             "apache tomcat",
    "Apache Tomcat":      "apache tomcat",
    "Spring Framework":   "spring framework",
    "Spring Boot":        "spring boot",
    "WildFly":            "wildfly",              # formerly JBoss
    "Struts":             "apache struts",
    "Apache Struts":      "apache struts",
    "Log4j":              "log4j apache",
    # ── PHP Frameworks & CMS ─────────────────────────────────────────────────
    "WordPress":          "wordpress",
    "Drupal":             "drupal",
    "Joomla":             "joomla",
    "Magento":            "magento",
    "WooCommerce":        "woocommerce",
    "PrestaShop":         "prestashop",
    "OpenCart":           "opencart",
    "Laravel":            "laravel",
    "CodeIgniter":        "codeigniter",
    # ── Python Frameworks ────────────────────────────────────────────────────
    "Django":             "django",
    "Flask":              "flask",
    # ── Node.js Frameworks ───────────────────────────────────────────────────
    "Express.js":         "expressjs",
    "Next.js":            "next.js",
    "Nuxt.js":            "nuxt.js",
    # ── Frontend Frameworks & Libraries ─────────────────────────────────────
    "Angular":            "angular",
    "AngularJS":          "angularjs",
    "React":              "react",
    "Vue.js":             "vue.js",
    "jQuery":             "jquery",
    "Lodash":             "lodash",               # prototype pollution CVEs
    "Moment.js":          "moment.js",            # ReDoS CVEs
    "Axios":              "axios",
    # ── Ruby ─────────────────────────────────────────────────────────────────
    "Ruby on Rails":      "ruby on rails",
    # ── CMS (non-PHP) ────────────────────────────────────────────────────────
    "Ghost":              "ghost",                # Node.js CMS, has RCE CVEs
    # ── Message Queues & Streaming ───────────────────────────────────────────
    "RabbitMQ":           "rabbitmq",
    "Kafka":              "apache kafka",
}


def _search_keyword(name: str, version: str) -> str:
    """Build the NVD keyword search string for this technology."""
    alias = _TECH_ALIASES.get(name)
    base = alias if alias else name
    return f"{base} {version}"


def _relevance_tokens(name: str) -> List[str]:
    """Return lowercase tokens from tech name used to filter CVE descriptions.

    Examples:
      "Apache HTTP Server" → ["apache", "http", "server", "apache http server"]
      "jQuery"             → ["jquery"]
      "Next.js"            → ["next.js", "next", "nextjs"]
    """
    alias = _TECH_ALIASES.get(name, name)
    tokens = set()
    # Full alias (lowered)
    tokens.add(alias.lower())
    # Individual words (len >= 3 to skip noise like "on", "by")
    for word in alias.lower().split():
        if len(word) >= 3:
            tokens.add(word)
    # Original name tokens too
    for word in name.lower().split():
        if len(word) >= 3:
            tokens.add(word)
    # Common normalisation: strip dots/dashes
    tokens.add(name.lower().replace(".", "").replace("-", ""))
    return list(tokens)


def _is_relevant(desc: str, name_tokens: List[str]) -> bool:
    """Return True if any token appears in the CVE description."""
    desc_lower = desc.lower()
    return any(token in desc_lower for token in name_tokens)


@dataclass
class CVEResult:
    cve_id: str
    severity: Optional[str] = None    # critical / high / medium / low / info
    cvss_score: Optional[float] = None
    description: Optional[str] = None


class CVEScanner:
    """
    Looks up CVEs for each unique (technology_name, version) pair using the
    NIST NVD API 2.0. Returns a dict keyed by (name_lower, version_lower).

    Only queries technologies where version is known — results are far more
    accurate and relevant than open-ended name-only keyword searches.
    """

    def __init__(
        self,
        technologies: List[Tuple[str, Optional[str]]],  # (name, version)
        api_key: Optional[str] = None,
    ):
        # Deduplicate; skip entries without version (too generic for NVD search)
        seen: set = set()
        self.targets: List[Tuple[str, str]] = []
        for name, version in technologies:
            if not name or not version:
                continue
            key = (name.strip().lower(), version.strip().lower())
            if key not in seen:
                seen.add(key)
                self.targets.append((name.strip(), version.strip()))
        self.api_key = api_key

    async def run(self) -> Dict[Tuple[str, str], List[CVEResult]]:
        if not self.targets:
            return {}

        results: Dict[Tuple[str, str], List[CVEResult]] = {}
        headers = {"apiKey": self.api_key} if self.api_key else {}

        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            for i, (name, version) in enumerate(self.targets):
                try:
                    cves = await self._lookup_with_retry(client, name, version, headers)
                    results[(name.lower(), version.lower())] = cves
                    logger.debug(f"CVEScanner: {name} {version} → {len(cves)} CVEs")
                except Exception as e:
                    logger.warning(f"CVEScanner: lookup failed for {name} {version}: {e}")
                    results[(name.lower(), version.lower())] = []

                # Rate-limit: pause between requests (skip after last)
                if i < len(self.targets) - 1:
                    await asyncio.sleep(REQUEST_DELAY)

        total = sum(len(v) for v in results.values())
        logger.info(
            f"CVEScanner: found {total} CVEs across {len(self.targets)} unique technologies"
        )
        return results

    async def _lookup_with_retry(
        self,
        client: httpx.AsyncClient,
        name: str,
        version: str,
        headers: dict,
    ) -> List[CVEResult]:
        """Call _lookup with retry on rate-limit / server errors / timeouts."""
        last_exc: Exception = RuntimeError("no attempts made")
        for attempt in range(MAX_RETRIES):
            try:
                return await self._lookup(client, name, version, headers)
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status in (403, 429, 503) and attempt < MAX_RETRIES - 1:
                    wait = 35 * (attempt + 1)   # 35s, 70s
                    logger.warning(
                        f"CVEScanner: NVD returned {status} for {name} {version}, "
                        f"retrying in {wait}s (attempt {attempt + 1}/{MAX_RETRIES})"
                    )
                    await asyncio.sleep(wait)
                    last_exc = exc
                    continue
                raise
            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                if attempt < MAX_RETRIES - 1:
                    wait = 15 * (attempt + 1)
                    logger.warning(
                        f"CVEScanner: timeout/connect error for {name} {version}, "
                        f"retrying in {wait}s"
                    )
                    await asyncio.sleep(wait)
                    last_exc = exc
                    continue
                raise
        raise last_exc

    async def _lookup(
        self,
        client: httpx.AsyncClient,
        name: str,
        version: str,
        headers: dict,
    ) -> List[CVEResult]:
        keyword = _search_keyword(name, version)
        resp = await client.get(
            NVD_BASE,
            params={
                "keywordSearch": keyword,
                "resultsPerPage": 20,
                "startIndex": 0,
            },
            headers=headers,
        )
        resp.raise_for_status()
        data = resp.json()

        name_tokens = _relevance_tokens(name)
        cves: List[CVEResult] = []
        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue

            # English description only
            desc = next(
                (d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"),
                None,
            )

            # Relevance filter: at least one name token must appear in description
            if desc and not _is_relevant(desc, name_tokens):
                continue

            score, sev = _extract_cvss(cve_data.get("metrics", {}))

            cves.append(CVEResult(
                cve_id=cve_id,
                severity=sev,
                cvss_score=score,
                description=desc[:500] if desc else None,
            ))

        # Return top N by CVSS score descending
        cves.sort(key=lambda c: c.cvss_score or 0.0, reverse=True)
        return cves[:MAX_PER_TECH]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _extract_cvss(metrics: dict) -> Tuple[Optional[float], Optional[str]]:
    """Extract CVSS base score + severity (prefers CVSSv3.1 → v3.0 → v2)."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for entry in metrics.get(key, []):
            data = entry.get("cvssData", {})
            score = data.get("baseScore")
            sev = data.get("baseSeverity")
            if score is not None:
                return float(score), _norm_sev(sev)
    for entry in metrics.get("cvssMetricV2", []):
        data = entry.get("cvssData", {})
        score = data.get("baseScore")
        sev = entry.get("baseSeverity")  # v2 severity lives one level up
        if score is not None:
            return float(score), _norm_sev(sev)
    return None, None


def _norm_sev(sev: Optional[str]) -> Optional[str]:
    if not sev:
        return None
    s = sev.upper()
    if s == "CRITICAL":
        return "critical"
    if s == "HIGH":
        return "high"
    if s in ("MEDIUM", "MODERATE"):
        return "medium"
    if s == "LOW":
        return "low"
    return "info"
