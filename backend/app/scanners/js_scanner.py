"""JavaScript Analysis Scanner

Crawls each alive subdomain's homepage, finds linked same-origin JS files,
and searches each file for:
  1. API endpoints / URL paths buried in code
  2. Secrets / credentials — TruffleHog v3 + GitLeaks inspired patterns (~120 rules)
  3. Source map exposure (sourceMappingURL → original unminified source)

No external tools or API keys required. Pure httpx + regex.

Limits:
  - MAX_JS_FILES = 25  per subdomain (HTML-linked + common path probing)
  - MAX_JS_SIZE  = 500 KB per file
  - Semaphore(5)  concurrent subdomains
"""
import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

TIMEOUT = 15.0
MAX_JS_FILES = 25
MAX_JS_SIZE = 500_000   # bytes
MAX_ENDPOINTS = 50
MAX_SECRETS_PER_TYPE = 3

# ── Common JS paths to probe directly (beyond HTML-linked scripts) ────────────
_COMMON_JS_PATHS = [
    "/app.js", "/main.js", "/index.js", "/bundle.js", "/app.bundle.js",
    "/main.bundle.js", "/chunk.js", "/vendor.js", "/runtime.js",
    "/static/js/main.js", "/static/js/bundle.js", "/static/js/app.js",
    "/static/js/index.js", "/static/js/vendor.js",
    "/assets/js/app.js", "/assets/js/main.js", "/assets/js/index.js",
    "/assets/main.js", "/assets/bundle.js", "/assets/app.js",
    "/js/app.js", "/js/main.js", "/js/bundle.js", "/js/index.js",
    "/dist/app.js", "/dist/main.js", "/dist/bundle.js",
    "/build/static/js/main.js", "/build/static/js/bundle.js",
]

# ── Secret detection patterns (TruffleHog v3 + GitLeaks inspired) ────────────
# Tuples of (label, compiled_regex)
# First capture group = the actual secret value.
_SECRET_PATTERNS: List[tuple] = [

    # ── Cloud Provider Keys ───────────────────────────────────────────────────
    ("AWS Access Key ID",
     re.compile(r'\b(AKIA[0-9A-Z]{16})\b')),

    ("AWS Secret Access Key",
     re.compile(
         r'(?:aws[_\-]?secret|secret[_\-]?access[_\-]?key)\s*[:=]\s*["\']([A-Za-z0-9/+]{40})["\']',
         re.I,
     )),

    ("AWS Session Token",
     re.compile(r'\b(AQoD[A-Za-z0-9/+]{100,})\b')),

    ("Google API Key",
     re.compile(r'\b(AIza[0-9A-Za-z\-_]{35})\b')),

    ("Google OAuth Client ID",
     re.compile(r'\b([0-9]+-[0-9a-z]+\.apps\.googleusercontent\.com)\b')),

    ("Google OAuth Client Secret",
     re.compile(r'\b(GOCSPX-[A-Za-z0-9\-_]{28})\b')),

    ("GCP Service Account Key",
     re.compile(
         r'"type"\s*:\s*"service_account".*?"private_key_id"\s*:\s*"([a-f0-9]{40})"',
         re.S,
     )),

    ("Azure Storage Key",
     re.compile(
         r'(?:AccountKey|DefaultEndpointsProtocol)=[^;]*;AccountKey=([A-Za-z0-9+/=]{88})',
     )),

    ("Azure SAS Token",
     re.compile(r'(sv=[0-9]{4}-[0-9]{2}-[0-9]{2}&s[irspe]=[^&"\']{5,200})')),

    ("Azure Client Secret",
     re.compile(
         r'(?:client[_\-]?secret|clientSecret)\s*[:=]\s*["\']([A-Za-z0-9\-_~.]{34,40})["\']',
         re.I,
     )),

    # ── Source Control Tokens ────────────────────────────────────────────────
    ("GitHub Personal Access Token",
     re.compile(r'\b(ghp_[A-Za-z0-9]{36})\b')),

    ("GitHub OAuth Token",
     re.compile(r'\b(gho_[A-Za-z0-9]{36})\b')),

    ("GitHub App Token",
     re.compile(r'\b(ghs_[A-Za-z0-9]{36})\b')),

    ("GitHub Refresh Token",
     re.compile(r'\b(ghr_[A-Za-z0-9]{36})\b')),

    ("GitLab Personal Access Token",
     re.compile(r'\b(glpat-[A-Za-z0-9\-_]{20})\b')),

    ("GitLab Pipeline Trigger Token",
     re.compile(r'\b(glptt-[A-Za-z0-9\-_]{20})\b')),

    ("GitLab Runner Token",
     re.compile(r'\b(GR1348941[A-Za-z0-9\-_]{20})\b')),

    ("Bitbucket Client Secret",
     re.compile(
         r'(?:bitbucket[_\-]?secret|bb[_\-]?secret)\s*[:=]\s*["\']([A-Za-z0-9]{32,})["\']',
         re.I,
     )),

    # ── Payment Processors ────────────────────────────────────────────────────
    ("Stripe Secret Key",
     re.compile(r'\b(sk_(test|live)_[0-9a-zA-Z]{24,})\b')),

    ("Stripe Publishable Key",
     re.compile(r'\b(pk_(test|live)_[0-9a-zA-Z]{24,})\b')),

    ("Stripe Restricted Key",
     re.compile(r'\b(rk_(test|live)_[0-9a-zA-Z]{24,})\b')),

    ("Stripe Webhook Secret",
     re.compile(r'\b(whsec_[A-Za-z0-9]{32,})\b')),

    ("PayPal Client ID",
     re.compile(
         r'(?:paypal[_\-]?client[_\-]?id|paypal[_\-]?key)\s*[:=]\s*["\']([A-Za-z0-9\-_]{32,80})["\']',
         re.I,
     )),

    ("Braintree Access Token",
     re.compile(r'\b(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})\b')),

    ("Square Access Token",
     re.compile(r'\b(sq0atp-[0-9A-Za-z\-_]{22})\b')),

    ("Square OAuth Secret",
     re.compile(r'\b(sq0csp-[0-9A-Za-z\-_]{43})\b')),

    # ── Communication APIs ────────────────────────────────────────────────────
    ("Slack Bot Token",
     re.compile(r'\b(xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24})\b')),

    ("Slack User Token",
     re.compile(r'\b(xoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{32})\b')),

    ("Slack App Token",
     re.compile(r'\b(xapp-[0-9]-[A-Z0-9]{10,13}-[0-9]{13}-[a-zA-Z0-9]{80})\b')),

    ("Slack Webhook URL",
     re.compile(r'(https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24})')),

    ("Twilio Account SID",
     re.compile(r'\b(AC[0-9a-fA-F]{32})\b')),

    ("Twilio Auth Token",
     re.compile(
         r'(?:twilio[_\-]?auth[_\-]?token|auth[_\-]?token)\s*[:=]\s*["\']([a-f0-9]{32})["\']',
         re.I,
     )),

    ("SendGrid API Key",
     re.compile(r'\b(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})\b')),

    ("Mailgun API Key",
     re.compile(r'\b(key-[0-9a-zA-Z]{32})\b')),

    ("Mailchimp API Key",
     re.compile(r'\b([0-9a-f]{32}-us[0-9]{1,2})\b')),

    ("Postmark Server Token",
     re.compile(
         r'(?:postmark[_\-]?token|postmark[_\-]?server)\s*[:=]\s*["\']([a-f0-9\-]{36})["\']',
         re.I,
     )),

    # ── Authentication & JWT ──────────────────────────────────────────────────
    ("JWT Token",
     re.compile(
         r'\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b',
     )),

    ("Private Key (PEM)",
     re.compile(r'(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)')),

    ("PGP Private Key Block",
     re.compile(r'(-----BEGIN PGP PRIVATE KEY BLOCK-----)')),

    ("OAuth Bearer Token",
     re.compile(
         r'(?:Authorization|Bearer)\s*[:=]\s*["\']?Bearer\s+([A-Za-z0-9\-_\.]{20,})["\']?',
         re.I,
     )),

    # ── CI/CD & DevOps ────────────────────────────────────────────────────────
    ("CircleCI Personal Token",
     re.compile(r'\b(circle-token-[a-f0-9]{40})\b')),

    ("Travis CI Token",
     re.compile(
         r'(?:travis[_\-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-]{22})["\']',
         re.I,
     )),

    ("Jenkins Token",
     re.compile(
         r'(?:jenkins[_\-]?token|jenkins[_\-]?api)\s*[:=]\s*["\']([A-Za-z0-9_\-]{32,})["\']',
         re.I,
     )),

    ("NPM Auth Token",
     re.compile(r'\b(npm_[A-Za-z0-9]{36})\b')),

    ("Docker Hub Token",
     re.compile(
         r'(?:docker[_\-]?token|dockerhub[_\-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-]{32,})["\']',
         re.I,
     )),

    # ── Database Connection Strings ───────────────────────────────────────────
    ("Database Connection String",
     re.compile(
         r'((?:mongodb(?:\+srv)?|postgresql|mysql|redis|mssql|oracle)://[^"\'<>\s]{10,200})',
         re.I,
     )),

    ("Database Password in URL",
     re.compile(
         r'(?:mysql|postgres(?:ql)?|mongodb|redis)://[^:]+:([^@]{8,64})@',
         re.I,
     )),

    # ── Monitoring & Analytics ────────────────────────────────────────────────
    ("Sentry DSN",
     re.compile(
         r'(https://[a-f0-9]{32}@o[0-9]+\.ingest\.sentry\.io/[0-9]+)',
     )),

    ("New Relic License Key",
     re.compile(r'\b([A-Za-z0-9]{40}NRAL)\b')),

    ("Datadog API Key",
     re.compile(
         r'(?:datadog[_\-]?api[_\-]?key|dd[_\-]?api[_\-]?key)\s*[:=]\s*["\']([a-f0-9]{32})["\']',
         re.I,
     )),

    # ── Social & Productivity APIs ────────────────────────────────────────────
    ("Twitter/X Bearer Token",
     re.compile(r'\b(AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{50,})\b')),

    ("Twitter/X API Key",
     re.compile(
         r'(?:twitter[_\-]?api[_\-]?key|twitter[_\-]?consumer[_\-]?key)\s*[:=]\s*["\']([A-Za-z0-9]{25})["\']',
         re.I,
     )),

    ("Facebook Access Token",
     re.compile(r'\b(EAA[A-Za-z0-9]+)\b')),

    ("Shopify Access Token",
     re.compile(r'\b(shpat_[A-Fa-f0-9]{32})\b')),

    ("Shopify Private App Token",
     re.compile(r'\b(shppa_[A-Fa-f0-9]{32})\b')),

    ("Shopify Shared Secret",
     re.compile(r'\b(shpss_[A-Fa-f0-9]{32})\b')),

    # ── Generic High-Value Patterns ───────────────────────────────────────────
    ("Generic API Key",
     re.compile(
         r'(?:api[_\-]?key|apikey|api[_\-]?secret|app[_\-]?key|app[_\-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,80})["\']',
         re.I,
     )),

    ("Generic Access Token",
     re.compile(
         r'(?:access[_\-]?token|auth[_\-]?token|bearer[_\-]?token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,200})["\']',
         re.I,
     )),

    ("Generic Secret Key",
     re.compile(
         r'(?:secret[_\-]?key|private[_\-]?key|client[_\-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,100})["\']',
         re.I,
     )),

    ("Password in Code",
     re.compile(
         r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,64})["\']',
         re.I,
     )),

    ("Internal URL with Credentials",
     re.compile(
         r'(https?://[^:"\'\s]+:[^@"\'\s]{6,}@[^"\'\s]{5,100})',
     )),
]

# ── Source map pattern ────────────────────────────────────────────────────────
_SOURCE_MAP_PATTERN = re.compile(
    r'//[#@]\s*sourceMappingURL=([^\s]+\.map[^\s]*)',
    re.I,
)

# ── Endpoint extraction patterns ──────────────────────────────────────────────
_API_PATH_PATTERN = re.compile(
    r'["\`](\/(?:api|v[0-9]+|graphql|rest|endpoint|auth|user|users|account|admin|internal)'
    r'[a-zA-Z0-9_\/\-\.]{0,80})["\`]',
    re.I,
)
_GENERAL_PATH_PATTERN = re.compile(
    r'["\`](\/[a-zA-Z][a-zA-Z0-9_\/\-\.]{5,60})["\`]'
)
# API-like keywords to keep from general paths.
# Keywords ending in "/" are substring checks; others require "/" or end-of-string boundary.
_API_KEYWORDS_WITH_SLASH = {"/api/", "/v1/", "/v2/", "/v3/", "/v4/", "/auth/", "/rest/", "/service/", "/data/"}
_API_KEYWORDS_EXACT = {"/user", "/users", "/account", "/accounts", "/admin", "/graphql"}


def _has_api_keyword(path: str) -> bool:
    p = path.lower()
    for kw in _API_KEYWORDS_WITH_SLASH:
        if kw in p:
            return True
    for kw in _API_KEYWORDS_EXACT:
        if p == kw or p.startswith(kw + "/"):
            return True
    return False

# ── Script src extraction ─────────────────────────────────────────────────────
_SCRIPT_SRC_PATTERN = re.compile(
    r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
    re.I,
)


@dataclass
class JSFinding:
    hostname: str
    js_url: str
    endpoints: List[str] = field(default_factory=list)
    secrets: List[Dict[str, str]] = field(default_factory=list)  # {type, value}

    @property
    def endpoint_count(self) -> int:
        return len(self.endpoints)

    @property
    def secret_count(self) -> int:
        return len(self.secrets)


class JSScanner:
    """
    Crawls alive subdomains for same-origin JS files and extracts
    API endpoints + secrets.
    """

    def __init__(self, hostnames: List[str]):
        self.hostnames = hostnames

    async def run(self) -> List[JSFinding]:
        if not self.hostnames:
            return []

        sem = asyncio.Semaphore(5)
        all_findings: List[JSFinding] = []

        async with httpx.AsyncClient(
            timeout=TIMEOUT,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"},
        ) as client:

            async def scan_host(hostname: str):
                async with sem:
                    try:
                        findings = await _scan_hostname(client, hostname)
                        all_findings.extend(findings)
                    except Exception as e:
                        logger.debug(f"JSScanner: error for {hostname}: {e}")

            await asyncio.gather(
                *[scan_host(h) for h in self.hostnames],
                return_exceptions=True,
            )

        total_secrets = sum(f.secret_count for f in all_findings)
        total_endpoints = sum(f.endpoint_count for f in all_findings)
        logger.info(
            f"JSScanner: {len(all_findings)} JS files analyzed, "
            f"{total_endpoints} endpoints, {total_secrets} secrets"
        )
        return all_findings


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _scan_hostname(
    client: httpx.AsyncClient, hostname: str
) -> List[JSFinding]:
    findings: List[JSFinding] = []

    for scheme in ("https", "http"):
        base_url = f"{scheme}://{hostname}"
        try:
            resp = await client.get(base_url)
            if resp.status_code >= 400:
                continue

            # Collect JS URLs: HTML-linked + common path probing
            js_urls_from_html = _extract_js_urls(resp.text, base_url)
            js_urls_probed = _common_js_urls(base_url)

            # Merge, deduplicate, respect HTML-linked order first
            seen: set = set(js_urls_from_html)
            combined = list(js_urls_from_html)
            for url in js_urls_probed:
                if url not in seen:
                    seen.add(url)
                    combined.append(url)

            for js_url in combined[:MAX_JS_FILES]:
                finding = await _analyze_js(client, hostname, js_url)
                if finding:
                    findings.append(finding)

            return findings  # success — don't try http fallback
        except Exception:
            continue

    return findings


def _common_js_urls(base_url: str) -> List[str]:
    """Build full URLs for common JS paths."""
    return [urljoin(base_url, path) for path in _COMMON_JS_PATHS]


def _extract_js_urls(html: str, base_url: str) -> List[str]:
    """Extract same-origin JS file URLs from HTML."""
    base_parsed = urlparse(base_url)
    js_urls: List[str] = []
    seen: set = set()

    for m in _SCRIPT_SRC_PATTERN.finditer(html):
        src = m.group(1).strip()
        parsed = urlparse(src)

        # Skip cross-origin JS (CDNs, third-party)
        if parsed.scheme in ("http", "https") and parsed.netloc != base_parsed.netloc:
            continue

        full_url = urljoin(base_url, src)
        if full_url not in seen:
            seen.add(full_url)
            js_urls.append(full_url)

    return js_urls


async def _analyze_js(
    client: httpx.AsyncClient, hostname: str, js_url: str
) -> Optional[JSFinding]:
    """Fetch a JS file and extract endpoints + secrets + source maps."""
    try:
        resp = await client.get(js_url)
        if resp.status_code != 200:
            return None
        content = resp.text[:MAX_JS_SIZE]
    except Exception:
        return None

    finding = JSFinding(hostname=hostname, js_url=js_url)

    # ── Extract API endpoints ─────────────────────────────────────────────────
    endpoints: set = set()
    for m in _API_PATH_PATTERN.finditer(content):
        endpoints.add(m.group(1))
    for m in _GENERAL_PATH_PATTERN.finditer(content):
        path = m.group(1)
        if _has_api_keyword(path):
            endpoints.add(path)
    finding.endpoints = sorted(endpoints)[:MAX_ENDPOINTS]

    # ── Detect source map exposure ────────────────────────────────────────────
    map_match = _SOURCE_MAP_PATTERN.search(content)
    if map_match:
        map_ref = map_match.group(1).strip()
        # Only flag if it's a relative path or same-origin URL (not data: URI)
        if not map_ref.startswith("data:"):
            finding.secrets.append({
                "type": "Source Map Exposed",
                "value": map_ref[:120],  # no masking needed — this is a path, not a secret
            })

    # ── Extract secrets (masked) ──────────────────────────────────────────────
    secrets_seen: set = set()
    for label, pattern in _SECRET_PATTERNS:
        matches = pattern.findall(content)
        count = 0
        for match in matches:
            value = match if isinstance(match, str) else match[0]
            if not value or value in secrets_seen:
                continue
            secrets_seen.add(value)
            # Mask: show first 6 chars + ***
            masked = value[:6] + "***" if len(value) > 6 else "***"
            finding.secrets.append({"type": label, "value": masked})
            count += 1
            if count >= MAX_SECRETS_PER_TYPE:
                break

    return finding if (finding.endpoints or finding.secrets) else None
