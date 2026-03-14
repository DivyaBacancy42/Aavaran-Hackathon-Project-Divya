"""OSV Vulnerability Scanner — api.osv.dev

Queries the OSV (Open Source Vulnerabilities) database for known vulnerabilities
in detected web technologies. OSV specialises in package-level vulnerabilities
across 15+ ecosystems: npm, PyPI, Go, Maven, RubyGems, Packagist, etc.

Key advantage over NVD: works WITHOUT a version number — ideal when HTTP headers
reveal a framework name but not its version (e.g. `X-Powered-By: Express`).

Method:
  1. Map each detected technology name to its OSV ecosystem + package name
  2. Query https://api.osv.dev/v1/query in parallel (no public rate limit)
  3. Parse CVSS vector → numeric base score using the `cvss` library
  4. Prefer CVE-* aliases as the canonical ID (so NVD links still work)
"""
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import httpx
from cvss import CVSS3

logger = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev/v1/query"
MAX_PER_TECH = 10
TIMEOUT = 15.0

# Maps tech name (as stored by TechScanner) → (osv_package_name, osv_ecosystem)
# OSV ecosystem names: https://ossf.github.io/osv-schema/#affectedpackage-field
#
# Ecosystems used:
#   PyPI, npm, Packagist, RubyGems, Go, Maven — package-manager tracked
#   Debian — OS-level server software (apache2, nginx, openssl, etc.)
#            Without a version, OSV returns all Debian DSAs; filtered to
#            CRITICAL/HIGH only to avoid stale low-severity noise.
TECH_TO_OSV: Dict[str, Tuple[str, str]] = {
    # ── Python / PyPI ──────────────────────────────────────────────────────────
    "Uvicorn":           ("uvicorn",                                  "PyPI"),
    "Gunicorn":          ("gunicorn",                                 "PyPI"),
    "Django":            ("Django",                                   "PyPI"),
    "Flask":             ("Flask",                                    "PyPI"),
    "FastAPI":           ("fastapi",                                  "PyPI"),
    "Tornado":           ("tornado",                                  "PyPI"),
    "Celery":            ("celery",                                   "PyPI"),
    "Pillow":            ("Pillow",                                   "PyPI"),
    "Requests":          ("requests",                                 "PyPI"),
    "Cryptography":      ("cryptography",                             "PyPI"),
    "aiohttp":           ("aiohttp",                                  "PyPI"),
    "Starlette":         ("starlette",                                "PyPI"),
    "Werkzeug":          ("Werkzeug",                                 "PyPI"),
    "Jinja2":            ("Jinja2",                                   "PyPI"),
    "SQLAlchemy":        ("SQLAlchemy",                               "PyPI"),
    "PyJWT":             ("PyJWT",                                    "PyPI"),
    "paramiko":          ("paramiko",                                 "PyPI"),

    # ── Node.js / npm ──────────────────────────────────────────────────────────
    "Express.js":        ("express",                                  "npm"),
    "Next.js":           ("next",                                     "npm"),
    "Angular":           ("@angular/core",                            "npm"),
    "AngularJS":         ("angular",                                  "npm"),
    "React":             ("react",                                    "npm"),
    "Vue.js":            ("vue",                                      "npm"),
    "Nuxt.js":           ("nuxt",                                     "npm"),
    "Svelte":            ("svelte",                                   "npm"),
    "Gatsby":            ("gatsby",                                   "npm"),
    "jQuery":            ("jquery",                                   "npm"),
    "Lodash":            ("lodash",                                   "npm"),
    "Moment.js":         ("moment",                                   "npm"),
    "Axios":             ("axios",                                    "npm"),
    "Socket.io":         ("socket.io",                                "npm"),
    "Ghost":             ("ghost",                                    "npm"),
    "Strapi":            ("strapi",                                   "npm"),
    "Passport.js":       ("passport",                                 "npm"),
    "jsonwebtoken":      ("jsonwebtoken",                             "npm"),
    "marked":            ("marked",                                   "npm"),
    "Bootstrap":         ("bootstrap",                                "npm"),

    # ── PHP / Packagist ────────────────────────────────────────────────────────
    "Laravel":           ("laravel/framework",                        "Packagist"),
    "WordPress":         ("wordpress/wordpress",                      "Packagist"),
    "Joomla":            ("joomla/joomla-cms",                        "Packagist"),
    "Drupal":            ("drupal/core",                              "Packagist"),
    "WooCommerce":       ("woocommerce/woocommerce",                  "Packagist"),
    "Magento":           ("magento/product-community-edition",        "Packagist"),
    "PrestaShop":        ("prestashop/prestashop",                    "Packagist"),
    "Symfony":           ("symfony/symfony",                          "Packagist"),
    "Yii":               ("yiisoft/yii2",                             "Packagist"),
    "CodeIgniter":       ("codeigniter4/codeigniter4",                "Packagist"),
    "CakePHP":           ("cakephp/cakephp",                          "Packagist"),
    "Guzzle":            ("guzzlehttp/guzzle",                        "Packagist"),
    "PHPMailer":         ("phpmailer/phpmailer",                      "Packagist"),
    "OpenCart":          ("opencart/opencart",                        "Packagist"),

    # ── Ruby / RubyGems ────────────────────────────────────────────────────────
    "Ruby on Rails":     ("rails",                                    "RubyGems"),
    "Rack":              ("rack",                                     "RubyGems"),

    # ── Go ─────────────────────────────────────────────────────────────────────
    "Caddy":             ("github.com/caddyserver/caddy/v2",          "Go"),
    "Traefik":           ("github.com/traefik/traefik/v2",            "Go"),
    "Gin":               ("github.com/gin-gonic/gin",                 "Go"),
    "Echo":              ("github.com/labstack/echo/v4",              "Go"),

    # ── Java / Maven ───────────────────────────────────────────────────────────
    # Critical high-profile CVEs: Log4Shell, Spring4Shell, Struts RCE, etc.
    "Log4j":             ("org.apache.logging.log4j:log4j-core",       "Maven"),
    "Spring Framework":  ("org.springframework:spring-webmvc",         "Maven"),
    "Spring Boot":       ("org.springframework.boot:spring-boot-autoconfigure", "Maven"),
    "Apache Struts":     ("org.apache.struts:struts2-core",            "Maven"),
    "Struts":            ("org.apache.struts:struts2-core",            "Maven"),
    "Apache Tomcat":     ("org.apache.tomcat.embed:tomcat-embed-core", "Maven"),
    "Tomcat":            ("org.apache.tomcat.embed:tomcat-embed-core", "Maven"),
    "Hibernate":         ("org.hibernate:hibernate-core",              "Maven"),
    "Jackson":           ("com.fasterxml.jackson.core:jackson-databind","Maven"),
    "Shiro":             ("org.apache.shiro:shiro-core",               "Maven"),

    # ── Debian ecosystem — OS-level server software ────────────────────────────
    # No version → returns all Debian DSAs; CRITICAL/HIGH filter applied in _query.
    "Apache":            ("apache2",                                  "Debian"),
    "Nginx":             ("nginx",                                    "Debian"),
    "PHP":               ("php-common",                               "Debian"),
    "OpenSSL":           ("openssl",                                  "Debian"),
    "MySQL":             ("mysql-server",                             "Debian"),
    "MariaDB":           ("mariadb-server",                          "Debian"),
    "PostgreSQL":        ("postgresql",                               "Debian"),
    "Redis":             ("redis",                                    "Debian"),
    "Memcached":         ("memcached",                                "Debian"),
    "Varnish":           ("varnish",                                  "Debian"),
    "Squid":             ("squid",                                    "Debian"),
    "HAProxy":           ("haproxy",                                  "Debian"),
    "Elasticsearch":     ("elasticsearch",                            "Debian"),
    "MongoDB":           ("mongodb",                                  "Debian"),
}


@dataclass
class OSVResult:
    vuln_id: str                         # CVE-* if alias exists, else GHSA-* / PYSEC-*
    summary: str
    severity: Optional[str] = None       # critical / high / medium / low
    cvss_score: Optional[float] = None   # parsed from CVSS vector
    details: Optional[str] = None        # truncated description


@dataclass
class OSVScanResult:
    # keyed by tech_name_lower → list of results
    by_tech: Dict[str, List[OSVResult]] = field(default_factory=dict)


class OSVScanner:
    """
    Queries OSV for each detected technology. Works with or without a version.
    All queries run concurrently — no rate limit like NVD.
    """

    def __init__(self, technologies: List[Tuple[str, Optional[str]]]):
        # Deduplicate (tech_name, version) pairs; only include known OSV mappings.
        # Version-less queries are allowed — OSV returns all known CVEs for the
        # package; we filter to CRITICAL/HIGH only to avoid stale low-severity noise.
        # Version-specific queries return results scoped to the exact release.
        seen: set = set()
        self.queries: List[Tuple[str, Optional[str], str, str]] = []
        for name, version in technologies:
            if not name:
                continue
            osv_info = TECH_TO_OSV.get(name)
            if not osv_info:
                continue
            osv_pkg, osv_eco = osv_info
            key = (osv_pkg.lower(), osv_eco, (version or "").lower())
            if key not in seen:
                seen.add(key)
                self.queries.append((name, version, osv_pkg, osv_eco))

    async def run(self) -> OSVScanResult:
        result = OSVScanResult()
        if not self.queries:
            logger.info("OSVScanner: no mapped technologies to query")
            return result

        sem = asyncio.Semaphore(8)

        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            async def fetch(name: str, version: Optional[str], pkg: str, eco: str):
                async with sem:
                    try:
                        vulns = await self._query(client, version, pkg, eco)
                        result.by_tech[name.lower()] = vulns
                        logger.debug(f"OSVScanner: {name} ({eco}) → {len(vulns)} vulns")
                    except Exception as e:
                        logger.debug(f"OSVScanner: query failed for {name}: {e}")
                        result.by_tech[name.lower()] = []

            await asyncio.gather(
                *[fetch(n, v, p, e) for n, v, p, e in self.queries],
                return_exceptions=True,
            )

        total = sum(len(v) for v in result.by_tech.values())
        logger.info(
            f"OSVScanner: queried {len(self.queries)} packages, "
            f"found {total} vulnerabilities total"
        )
        return result

    async def _query(
        self,
        client: httpx.AsyncClient,
        version: Optional[str],
        pkg: str,
        eco: str,
    ) -> List[OSVResult]:
        payload: dict = {"package": {"name": pkg, "ecosystem": eco}}
        if version:
            payload["version"] = version

        resp = await client.post(OSV_API, json=payload)
        resp.raise_for_status()
        data = resp.json()

        # Without a version the query returns ALL historical CVEs for this package.
        # Restrict to CRITICAL/HIGH only to avoid showing stale low-severity noise
        # from ancient releases that no longer apply.
        severity_filter = {"critical", "high"} if not version else None

        results: List[OSVResult] = []
        seen_ids: set = set()
        for vuln in data.get("vulns", []):
            vuln_id = _canonical_id(vuln)
            if not vuln_id or vuln_id in seen_ids:
                continue  # deduplicate
            seen_ids.add(vuln_id)

            summary = vuln.get("summary", "")
            if not summary:
                continue

            details_raw = vuln.get("details", "") or ""
            details = details_raw[:500] if details_raw else None

            cvss_score, severity = _extract_severity(vuln)

            # Skip low/medium/unknown when version is unknown (reduces false positives)
            if severity_filter and severity not in severity_filter:
                continue

            results.append(OSVResult(
                vuln_id=vuln_id,
                summary=summary,
                severity=severity,
                cvss_score=cvss_score,
                details=details,
            ))

        # Sort by score descending, keep top N
        results.sort(key=lambda r: r.cvss_score or 0.0, reverse=True)
        return results[:MAX_PER_TECH]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _canonical_id(vuln: dict) -> str:
    """Return CVE-* alias if present, otherwise the OSV / GHSA ID."""
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return vuln["id"]


def _extract_severity(vuln: dict) -> Tuple[Optional[float], Optional[str]]:
    """
    Parse CVSS vector → (base_score, severity_label).
    Falls back to database_specific.severity label if CVSS parse fails.
    """
    # Try CVSS_V3 / CVSS_V4 vector
    for entry in vuln.get("severity", []):
        vector = entry.get("score", "")
        if not vector:
            continue
        try:
            c = CVSS3(vector)
            score = float(c.base_score)
            sev = _score_to_severity(score)
            return score, sev
        except Exception:
            continue

    # Fall back to label from database_specific
    label = vuln.get("database_specific", {}).get("severity", "")
    return None, _label_to_severity(label)


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _label_to_severity(label: str) -> Optional[str]:
    s = label.upper()
    if s == "CRITICAL":
        return "critical"
    if s == "HIGH":
        return "high"
    if s in ("MODERATE", "MEDIUM"):
        return "medium"
    if s == "LOW":
        return "low"
    return None
