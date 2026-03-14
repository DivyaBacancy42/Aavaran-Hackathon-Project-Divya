import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import dns.asyncresolver
import dns.exception
import httpx

logger = logging.getLogger(__name__)

CRT_SH_URL = "https://crt.sh/?q={domain}&output=json"
CRT_SH_TIMEOUT = 20  # seconds
DNS_TIMEOUT = 3       # seconds per query
DNS_CONCURRENCY = 40  # simultaneous DNS lookups

# ── Wordlist — ~300 common subdomain prefixes ─────────────────────────────────
# Covers: web, mail, infra, dev/staging, APIs, auth, admin, services, DBs, CI/CD
WORDLIST = [
    # Web
    "www", "www2", "www3", "web", "web1", "web2", "website",
    # Mail
    "mail", "mail1", "mail2", "mx", "mx1", "mx2", "smtp", "smtp1", "smtp2",
    "pop", "pop3", "imap", "email", "webmail", "owa", "exchange", "autodiscover",
    # Admin / control panels
    "admin", "administrator", "portal", "dashboard", "console", "panel",
    "manage", "management", "cp", "cpanel", "whm", "plesk", "phpmyadmin",
    "backend", "bo", "backoffice",
    # Dev / staging environments
    "dev", "dev1", "dev2", "development", "local",
    "staging", "stage", "stg", "stg1",
    "test", "test1", "test2", "testing",
    "qa", "qa1", "qa2", "uat",
    "beta", "alpha", "demo", "sandbox",
    "preprod", "pre-prod", "preview", "canary",
    # APIs & services
    "api", "api1", "api2", "api3", "api-v1", "api-v2", "api-v3",
    "api-dev", "api-staging", "api-prod",
    "rest", "graphql", "grpc", "ws", "websocket", "rpc", "endpoint",
    # Infrastructure / DNS
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    # File transfer / remote access
    "ftp", "ftp1", "sftp", "ssh", "rdp", "vnc",
    "vpn", "vpn1", "vpn2", "remote", "citrix", "gateway2",
    # CDN / static assets
    "cdn", "cdn1", "cdn2", "cdn3",
    "static", "assets", "asset", "media", "img", "images", "image",
    "video", "videos", "audio", "files", "file",
    "upload", "uploads", "download", "downloads",
    "s3", "storage", "blob",
    # Apps / mobile
    "app", "app1", "app2", "apps",
    "mobile", "m", "mobi", "ios", "android",
    # Content / marketing
    "blog", "news", "press", "media2",
    "forum", "community", "discuss",
    "shop", "store", "ecommerce", "cart", "checkout",
    "landing", "lp", "campaign", "promo", "go",
    # Documentation / support
    "docs", "doc", "wiki", "help", "support", "kb", "knowledge",
    "faq", "guides", "learn",
    # Status / monitoring
    "status", "uptime", "ping", "health",
    "monitor", "monitoring", "nagios", "zabbix",
    "grafana", "prometheus", "metrics", "alerts",
    "kibana", "elastic", "elasticsearch", "logstash",
    "datadog", "newrelic", "sentry",
    # Auth / identity
    "auth", "login", "signin", "sso", "oauth", "saml",
    "id", "identity", "iam", "accounts", "account",
    "secure", "security", "signup", "register",
    # Databases / caches (internal-facing but often exposed)
    "db", "db1", "db2", "database",
    "mysql", "postgres", "postgresql", "mongo", "mongodb",
    "redis", "cache", "memcache", "memcached",
    "rabbitmq", "kafka", "queue", "broker", "mq",
    # Search
    "search", "solr", "sphinx",
    # DevOps / CI-CD
    "ci", "cd", "jenkins", "travis", "circleci",
    "gitlab", "github", "bitbucket", "git", "svn",
    "registry", "docker", "artifactory", "nexus",
    "sonar", "sonarqube",
    "k8s", "kubernetes", "openshift", "rancher",
    "vault", "consul", "terraform",
    # Communication / collaboration
    "chat", "slack", "mattermost", "rocketchat", "teams",
    "jira", "confluence", "notion", "trello",
    "zoom", "meet",
    # Business systems
    "crm", "erp", "hr", "hris", "ats",
    "billing", "pay", "payment", "payments", "invoice",
    "finance", "accounting",
    "legal", "compliance",
    "sales", "marketing", "analytics", "track", "pixel",
    "data", "bi", "report", "reports", "insight", "insights",
    # Misc infra
    "proxy", "lb", "load", "waf", "firewall", "nat", "router",
    "internal", "intranet", "extranet", "corp", "office",
    "node", "node1", "node2", "worker", "job", "cron", "scheduler",
    "server", "server1", "server2", "host", "host1",
    # Versioned / lifecycle
    "v1", "v2", "v3", "new", "old",
    "prod", "production", "live",
    "backup", "bak", "archive", "legacy",
    "deprecated", "retired",
]


@dataclass
class SubdomainData:
    hostname: str
    source: str = "crt.sh"
    ip_address: Optional[str] = None


@dataclass
class SubdomainScanResult:
    subdomains: List[SubdomainData] = field(default_factory=list)
    crtsh_count: int = 0
    brute_count: int = 0
    error: Optional[str] = None


class SubdomainScanner:
    """
    Discovers subdomains using two independent methods run in parallel:
      1. crt.sh  — Certificate Transparency log passive lookup (no API key)
      2. DNS brute force — resolves common prefixes against the domain using dnspython
    Results are merged and deduplicated. Source is labelled per-record.
    """

    def __init__(self, domain: str):
        self.domain = domain

    async def run(self) -> SubdomainScanResult:
        result = SubdomainScanResult()
        try:
            # Run both sources concurrently
            crtsh_task = asyncio.create_task(self._run_crtsh())
            brute_task = asyncio.create_task(self._run_brute_force())
            crtsh_found, brute_found = await asyncio.gather(
                crtsh_task, brute_task, return_exceptions=True
            )

            if isinstance(crtsh_found, Exception):
                logger.warning(f"crt.sh lookup failed for {self.domain}: {crtsh_found}")
                crtsh_found = {}

            if isinstance(brute_found, Exception):
                logger.warning(f"DNS brute force failed for {self.domain}: {brute_found}")
                brute_found = {}

            result.crtsh_count = len(crtsh_found)
            result.brute_count = len(brute_found)
            result.subdomains = self._merge(crtsh_found, brute_found)

            logger.info(
                f"SubdomainScanner complete for {self.domain}: "
                f"crt.sh={result.crtsh_count}, brute={result.brute_count}, "
                f"merged={len(result.subdomains)}"
            )
        except Exception as e:
            logger.error(f"SubdomainScanner failed for {self.domain}: {e}")
            result.error = str(e)
        return result

    # ── Source 1: crt.sh ──────────────────────────────────────────────────────

    async def _run_crtsh(self) -> Dict[str, Optional[str]]:
        """Returns {hostname: None} — crt.sh doesn't give us IPs."""
        url = CRT_SH_URL.format(domain=self.domain)
        async with httpx.AsyncClient(timeout=CRT_SH_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(url, headers={"Accept": "application/json"})
            resp.raise_for_status()
            entries = resp.json()

        found: Dict[str, Optional[str]] = {}
        for entry in entries:
            for name in (entry.get("name_value") or "").splitlines():
                hostname = name.strip().lower().lstrip("*.")
                if self._is_valid_subdomain(hostname):
                    found[hostname] = None  # no IP from crt.sh
        return found

    # ── Source 2: DNS brute force ─────────────────────────────────────────────

    async def _run_brute_force(self) -> Dict[str, Optional[str]]:
        """Returns {hostname: ip_address} for every prefix that resolves."""
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT + 1

        sem = asyncio.Semaphore(DNS_CONCURRENCY)
        tasks = [
            self._resolve(resolver, sem, f"{prefix}.{self.domain}")
            for prefix in WORDLIST
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        found: Dict[str, Optional[str]] = {}
        for hostname, ip in results:
            if hostname and self._is_valid_subdomain(hostname):
                found[hostname] = ip
        return found

    async def _resolve(
        self,
        resolver: dns.asyncresolver.Resolver,
        sem: asyncio.Semaphore,
        hostname: str,
    ):
        """Try to resolve a single hostname. Returns (hostname, ip) or (None, None)."""
        async with sem:
            try:
                answers = await resolver.resolve(hostname, "A")
                ip = str(answers[0])
                return hostname, ip
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ):
                return None, None
            except Exception:
                return None, None

    # ── Merge + dedup ─────────────────────────────────────────────────────────

    def _merge(
        self,
        crtsh: Dict[str, Optional[str]],
        brute: Dict[str, Optional[str]],
    ) -> List[SubdomainData]:
        merged: Dict[str, SubdomainData] = {}

        for hostname in crtsh:
            merged[hostname] = SubdomainData(
                hostname=hostname,
                source="crt.sh",
                ip_address=None,
            )

        for hostname, ip in brute.items():
            if hostname in merged:
                # Found by both — upgrade source label and add IP
                merged[hostname].source = "crt.sh+dns"
                merged[hostname].ip_address = ip
            else:
                merged[hostname] = SubdomainData(
                    hostname=hostname,
                    source="dns-brute",
                    ip_address=ip,
                )

        result = sorted(merged.values(), key=lambda x: x.hostname)
        return result

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _is_valid_subdomain(self, hostname: str) -> bool:
        if not hostname:
            return False
        if hostname == self.domain:
            return False
        if not hostname.endswith(f".{self.domain}"):
            return False
        return True
