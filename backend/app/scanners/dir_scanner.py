"""Directory / Content Discovery Scanner

Brute-forces common paths on each alive subdomain using a built-in wordlist.
Identifies exposed admin panels, git repos, backup files, API docs, debug
endpoints, and other sensitive resources.

No external tools — pure async httpx.

Severity:
  CRITICAL — source code / secrets exposed (.env, .git/config, DB dumps, backups)
  HIGH     — admin panels, database UIs, actuator/env, webshells
  MEDIUM   — API docs, debug tools, server-status, Spring actuator endpoints
  LOW      — informational paths (robots.txt, health, sitemap)
"""
import asyncio
import logging
from dataclasses import dataclass
from typing import List, Optional

import httpx

logger = logging.getLogger(__name__)

TIMEOUT = 8.0
SEMAPHORE_LIMIT = 20    # concurrent requests across all subdomains
MAX_FINDINGS_PER_HOST = 30

# ── Wordlist ──────────────────────────────────────────────────────────────────
WORDLIST: List[str] = [
    # ── Secrets / source code exposure (CRITICAL) ─────────────────────────────
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.backup",
    "/.env.old",
    "/.git/config",
    "/.git/HEAD",
    "/.git/COMMIT_EDITMSG",
    "/.svn/entries",
    "/.svn/wc.db",
    "/database.sql",
    "/db.sql",
    "/dump.sql",
    "/backup.sql",
    "/backup.zip",
    "/backup.tar.gz",
    "/.htpasswd",
    "/config.php",
    "/config.php.bak",
    "/config.php.old",
    "/wp-config.php.bak",
    # ── Admin panels (HIGH) ───────────────────────────────────────────────────
    "/admin",
    "/admin/",
    "/admin/login",
    "/administrator",
    "/administrator/",
    "/phpmyadmin",
    "/phpmyadmin/",
    "/adminer.php",
    "/cpanel",
    "/manager/html",
    "/wp-admin",
    "/wp-admin/",
    "/wp-login.php",
    "/xmlrpc.php",
    "/wp-json/wp/v2/users",
    "/actuator/env",
    "/actuator/mappings",
    "/actuator/beans",
    "/console",
    "/jenkins",
    "/jenkins/",
    "/h2-console",
    "/h2-console/",
    # ── API documentation / GraphQL (MEDIUM) ──────────────────────────────────
    "/api",
    "/api/",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/graphql",
    "/graphiql",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs/",
    "/v1",
    "/v2",
    # ── Debug / dev tools (MEDIUM) ────────────────────────────────────────────
    "/debug",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/_debug_toolbar",
    "/profiler",
    "/server-status",
    "/server-info",
    "/debug/vars",
    "/debug/pprof",
    # ── Spring Boot actuator (MEDIUM) ─────────────────────────────────────────
    "/actuator",
    "/actuator/health",
    "/actuator/info",
    "/actuator/metrics",
    "/actuator/loggers",
    "/actuator/threaddump",
    # ── Kibana / Grafana / Prometheus ─────────────────────────────────────────
    "/kibana",
    "/kibana/",
    "/grafana",
    "/grafana/",
    "/prometheus",
    "/_cat/indices",
    "/_cluster/health",
    # ── Logs (MEDIUM) ─────────────────────────────────────────────────────────
    "/error.log",
    "/access.log",
    "/app.log",
    "/debug.log",
    "/logs/error.log",
    "/log/error.log",
    # ── Dependency manifests — information disclosure (MEDIUM) ────────────────
    "/package.json",
    "/package-lock.json",
    "/composer.json",
    "/composer.lock",
    "/requirements.txt",
    "/Gemfile",
    "/.idea/workspace.xml",
    "/.DS_Store",
    "/web.config",
    # ── Informational / LOW ───────────────────────────────────────────────────
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/health",
    "/metrics",
    "/status",
    "/ping",
    "/favicon.ico",
]

# ── Severity classification ───────────────────────────────────────────────────
_CRITICAL_PATHS = {p.lower() for p in {
    "/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.old",
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/.svn/entries", "/.svn/wc.db",
    "/database.sql", "/db.sql", "/dump.sql", "/backup.sql",
    "/backup.zip", "/backup.tar.gz", "/.htpasswd",
    "/config.php", "/config.php.bak", "/config.php.old", "/wp-config.php.bak",
}}

_HIGH_PATHS = {p.lower() for p in {
    "/phpmyadmin", "/phpmyadmin/", "/adminer.php", "/cpanel",
    "/manager/html", "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/xmlrpc.php", "/wp-json/wp/v2/users",
    "/actuator/env", "/actuator/mappings", "/actuator/beans",
    "/console", "/jenkins", "/jenkins/", "/h2-console", "/h2-console/",
    "/admin", "/admin/", "/admin/login", "/administrator", "/administrator/",
}}

_MEDIUM_PATHS = {p.lower() for p in {
    "/swagger.json", "/swagger.yaml", "/swagger-ui.html", "/swagger-ui/",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/api-docs/",
    "/graphql", "/graphiql", "/phpinfo.php", "/info.php", "/test.php",
    "/debug", "/_debug_toolbar", "/profiler", "/server-status", "/server-info",
    "/actuator", "/actuator/health", "/actuator/info",
    "/actuator/metrics", "/actuator/loggers", "/actuator/threaddump",
    "/kibana", "/kibana/", "/grafana", "/grafana/", "/prometheus",
    "/_cat/indices", "/_cluster/health",
    "/error.log", "/access.log", "/app.log", "/debug.log",
    "/logs/error.log", "/log/error.log",
    "/package.json", "/package-lock.json", "/composer.json",
    "/composer.lock", "/requirements.txt", "/Gemfile",
    "/.idea/workspace.xml", "/.DS_Store", "/web.config", "/debug/vars",
    "/debug/pprof",
}}

# ── Finding type classification ───────────────────────────────────────────────
def _classify(path: str) -> tuple[str, str]:
    """Returns (finding_type, severity)."""
    p = path.lower()
    if p in _CRITICAL_PATHS:
        severity = "critical"
    elif p in _HIGH_PATHS:
        severity = "high"
    elif p in _MEDIUM_PATHS:
        severity = "medium"
    else:
        severity = "low"

    if ".git" in p or ".svn" in p or ".hg" in p:
        ftype = "git_exposure"
    elif ".env" in p or "config.php" in p or ".htpasswd" in p or "wp-config" in p:
        ftype = "env_file"
    elif any(x in p for x in ("phpmyadmin", "adminer", "cpanel", "manager/html", "h2-console")):
        ftype = "admin_panel"
    elif any(x in p for x in ("wp-admin", "wp-login", "xmlrpc", "wp-json", "joomla", "typo3")):
        ftype = "cms_admin"
    elif any(x in p for x in ("swagger", "openapi", "api-docs", "graphql", "graphiql")):
        ftype = "api_docs"
    elif any(x in p for x in ("actuator", "kibana", "grafana", "prometheus", "_cat", "_cluster")):
        ftype = "devops_panel"
    elif any(x in p for x in (".sql", "backup", "dump")):
        ftype = "database_dump"
    elif any(x in p for x in ("error.log", "access.log", "app.log", "debug.log")):
        ftype = "log_file"
    elif any(x in p for x in ("phpinfo", "server-status", "server-info", "debug", "profiler")):
        ftype = "debug_endpoint"
    elif any(x in p for x in ("package.json", "composer.json", "requirements.txt", "gemfile")):
        ftype = "dependency_file"
    elif p in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
        ftype = "informational"
    elif p in ("/health", "/metrics", "/status", "/ping"):
        ftype = "health_check"
    else:
        ftype = "other"

    return ftype, severity


_SEVERITY_DOWNGRADE = {
    "critical": "high",
    "high":     "medium",
    "medium":   "low",
    "low":      "low",
}


def _adjust_severity_by_status(severity: str, status_code: int) -> str:
    """Adjust finding severity based on the HTTP response code.

    200 / 201  — content is actually readable → keep original severity.
    403 / 401  — path EXISTS but server blocks access → downgrade one level.
                 (The misconfiguration is still worth noting — git dir deployed
                  to web root is bad practice even if 403'd — but it is NOT
                  exploitable without further bypass.)
    301 / 302  — redirect, likely to login page → always 'low'.
    Anything else (206, 400, etc.) — keep original severity.
    """
    if status_code in (301, 302, 303, 307, 308):
        return "low"
    if status_code in (401, 403):
        return _SEVERITY_DOWNGRADE.get(severity, severity)
    return severity  # 200, 201, etc. → unchanged


@dataclass
class DirectoryFinding:
    subdomain_hostname: str
    path: str
    status_code: int
    content_length: Optional[int]
    finding_type: str
    severity: str


class DirScanner:
    """
    Brute-forces common paths on each alive subdomain.
    Only records paths that return a non-404 response.
    Skips 429 (rate-limited) gracefully.
    """

    def __init__(self, hostnames: List[str]):
        self.hostnames = hostnames

    async def run(self) -> List[DirectoryFinding]:
        if not self.hostnames:
            return []

        sem = asyncio.Semaphore(SEMAPHORE_LIMIT)
        all_findings: List[DirectoryFinding] = []

        async with httpx.AsyncClient(
            timeout=TIMEOUT,
            follow_redirects=False,   # don't follow redirects — 301/302 is a finding itself
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
                "Accept": "*/*",
            },
        ) as client:

            tasks = [
                _probe_host(client, sem, hostname)
                for hostname in self.hostnames
            ]
            host_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in host_results:
                if isinstance(result, list):
                    all_findings.extend(result)

        logger.info(
            f"DirScanner: checked {len(self.hostnames)} hosts, "
            f"{len(all_findings)} paths found"
        )
        return all_findings


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _probe_host(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    hostname: str,
) -> List[DirectoryFinding]:
    """Probe all wordlist paths for a single hostname."""
    findings: List[DirectoryFinding] = []

    # Determine working scheme
    base_url: Optional[str] = None
    for scheme in ("https", "http"):
        try:
            test = await client.get(f"{scheme}://{hostname}/", timeout=6.0)
            if test.status_code < 500:
                base_url = f"{scheme}://{hostname}"
                break
        except Exception:
            continue

    if not base_url:
        return findings

    async def probe(path: str):
        async with sem:
            try:
                resp = await client.get(f"{base_url}{path}")
                code = resp.status_code

                # Skip 404, 410 (gone), and server errors
                if code in (404, 410) or code >= 500:
                    return

                # Skip 429 (rate limiting) — just ignore
                if code == 429:
                    return

                content_length = None
                if "content-length" in resp.headers:
                    try:
                        content_length = int(resp.headers["content-length"])
                    except ValueError:
                        pass
                # For small responses read actual length
                if content_length is None and resp.content:
                    content_length = len(resp.content)

                ftype, severity = _classify(path)
                severity = _adjust_severity_by_status(severity, code)
                findings.append(DirectoryFinding(
                    subdomain_hostname=hostname,
                    path=path,
                    status_code=code,
                    content_length=content_length,
                    finding_type=ftype,
                    severity=severity,
                ))
            except Exception:
                pass  # timeout or connection error → skip

    await asyncio.gather(*[probe(path) for path in WORDLIST], return_exceptions=True)

    # Cap per-host findings, prioritise by severity
    _SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 4))
    return findings[:MAX_FINDINGS_PER_HOST]
