"""
Technology Detection Scanner

Primary:  Wappalyzer fingerprint database (~3,000 technologies).
          Downloaded from enthec/webappanalyzer on first run, cached for 7 days.
          Covers headers, cookies, HTML, scripts, meta tags, and implies chains.

Fallback: Built-in regex signatures for edge cases — CDN URL version extraction,
          custom server-header rules, etc.

Result: 10x more detections with accurate version extraction and category labels.
"""
import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

# ── Wappalyzer fingerprint loader ─────────────────────────────────────────────

_WAPP_CACHE_FILE = Path("/tmp/shodh_wappalyzer.json")
_WAPP_CACHE_TTL  = 7 * 86400          # re-download after 7 days
_WAPP_DATA: Optional[dict] = None     # module-level in-memory cache

# Wappalyzer category ID → human-readable name
_WAPP_CAT: Dict[int, str] = {
    1:  "CMS",
    2:  "Message Board",
    6:  "Database Manager",
    7:  "E-Commerce",
    10: "Analytics",
    11: "Blog",
    12: "JavaScript Framework",
    13: "Visualization",
    14: "JavaScript Plugin",
    18: "Web Framework",
    19: "Miscellaneous",
    22: "Web Server",
    25: "CDN",
    26: "Document Management",
    27: "Database",
    28: "Search Engine",
    31: "SSL/TLS",
    32: "Marketing Automation",
    34: "Message Queue",
    41: "Payment Processor",
    46: "Network Management",
    47: "CRM",
    49: "Authentication",
    52: "Security",
    62: "CDN",
    64: "PaaS",
    65: "Issue Tracker",
    67: "Hosting Panel",
    68: "Static Site Generator",
}

_WAPP_TECH_URLS = [
    f"https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/{c}.json"
    for c in list("abcdefghijklmnopqrstuvwxyz") + ["_"]
]


async def _load_wappalyzer() -> dict:
    """
    Return the Wappalyzer technology fingerprint dict.
    Checks in-memory cache → disk cache → downloads fresh if needed.
    Returns {} on failure so built-in signatures still work.
    """
    global _WAPP_DATA
    if _WAPP_DATA is not None:
        return _WAPP_DATA

    # Disk cache
    if _WAPP_CACHE_FILE.exists():
        age = time.time() - _WAPP_CACHE_FILE.stat().st_mtime
        if age < _WAPP_CACHE_TTL:
            try:
                _WAPP_DATA = json.loads(_WAPP_CACHE_FILE.read_text())
                logger.info(f"Wappalyzer: {len(_WAPP_DATA)} fingerprints loaded from cache")
                return _WAPP_DATA
            except Exception:
                pass

    # Download 27 files in parallel (~300 ms on a fast connection)
    merged: dict = {}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            responses = await asyncio.gather(
                *[client.get(url) for url in _WAPP_TECH_URLS],
                return_exceptions=True,
            )
        for resp in responses:
            if isinstance(resp, Exception) or resp.status_code != 200:
                continue
            try:
                merged.update(resp.json())
            except Exception:
                pass

        if merged:
            try:
                _WAPP_CACHE_FILE.write_text(json.dumps(merged))
            except Exception:
                pass
            logger.info(f"Wappalyzer: downloaded {len(merged)} fingerprints")
        else:
            logger.warning("Wappalyzer download returned no data — using built-in signatures only")

    except Exception as exc:
        logger.warning(f"Wappalyzer download failed ({exc}) — using built-in signatures only")

    _WAPP_DATA = merged
    return merged


def _parse_wapp_pattern(raw: str):
    """
    Split a Wappalyzer pattern string into (regex, version_group).

    Wappalyzer embeds metadata after \\; separators:
      "nginx(?:/([\\d.]+))?\\;version:\\1"  →  ("nginx(?:/([\\d.]+))?", 1)
      "WordPress\\;confidence:75"           →  ("WordPress", None)
    """
    parts = raw.split("\\;")
    regex = parts[0]
    ver_group: Optional[int] = None
    for part in parts[1:]:
        if part.startswith("version:"):
            ref = part[8:]
            if ref.startswith("\\") and ref[1:].isdigit():
                ver_group = int(ref[1:])
    return regex, ver_group


def _wapp_match(pattern_raw: str, text: str):
    """
    Match a Wappalyzer pattern against text.
    Returns (matched: bool, version: Optional[str]).
    """
    if not pattern_raw:
        return True, None
    try:
        regex, ver_group = _parse_wapp_pattern(pattern_raw)
        m = re.search(regex, text, re.IGNORECASE)
        if not m:
            return False, None
        version: Optional[str] = None
        if ver_group and ver_group <= (m.lastindex or 0):
            v = m.group(ver_group)
            version = v.strip() if v else None
        return True, version
    except re.error:
        return False, None


def _wapp_detect(resp: httpx.Response, wapp_data: dict, hostname: str) -> List["DetectedTechnology"]:
    """
    Apply Wappalyzer fingerprints to a single HTTP response.
    Detection order: headers → cookies → html/scripts/url → meta → implies.
    """
    seen: Dict[str, "DetectedTechnology"] = {}
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    cookie_str = " ".join(
        v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"
    )
    html = ""
    if resp.status_code < 400:
        try:
            html = resp.text[:100_000]
        except Exception:
            pass

    def add(name: str, version: Optional[str], cat: str):
        if name not in seen:
            seen[name] = DetectedTechnology(hostname=hostname, name=name, version=version, category=cat)
        elif version and not seen[name].version:
            seen[name].version = version

    for tech_name, tech_info in wapp_data.items():
        if not isinstance(tech_info, dict):
            continue

        cats = tech_info.get("cats") or []
        cat = _WAPP_CAT.get(cats[0], "Technology") if cats else "Technology"

        matched = False
        found_version: Optional[str] = None

        # ── 1. Response headers ────────────────────────────────────────────────
        header_pats = tech_info.get("headers") or {}
        if isinstance(header_pats, dict):
            for h_name, h_pat in header_pats.items():
                val = headers_lower.get(h_name.lower(), "")
                if not val:
                    continue
                ok, ver = _wapp_match(str(h_pat), val)
                if ok:
                    matched = True
                    found_version = found_version or ver
                    break

        if matched:
            add(tech_name, found_version, cat)
            continue

        # ── 2. Cookies (key is itself a regex in Wappalyzer) ──────────────────
        cookie_pats = tech_info.get("cookies") or {}
        if isinstance(cookie_pats, dict) and cookie_str:
            for c_key_pat, c_val_pat in cookie_pats.items():
                try:
                    if re.search(c_key_pat, cookie_str, re.IGNORECASE):
                        ok, ver = _wapp_match(str(c_val_pat), cookie_str) if c_val_pat else (True, None)
                        if ok:
                            matched = True
                            found_version = found_version or ver
                            break
                except re.error:
                    continue

        if matched:
            add(tech_name, found_version, cat)
            continue

        # ── 3. HTML body, script src, page URL ────────────────────────────────
        if html:
            for key in ("html", "scripts", "url"):
                pat = tech_info.get(key)
                if not pat:
                    continue
                pats = pat if isinstance(pat, list) else [pat]
                for p in pats:
                    ok, ver = _wapp_match(str(p), html)
                    if ok:
                        matched = True
                        found_version = found_version or ver
                        break
                if matched:
                    break

        if matched:
            add(tech_name, found_version, cat)
            continue

        # ── 4. Meta tags ───────────────────────────────────────────────────────
        meta_pats = tech_info.get("meta") or {}
        if isinstance(meta_pats, dict) and html:
            for meta_name, meta_pat in meta_pats.items():
                # Try name= before content= and content= before name= orders
                for tmpl in (
                    rf'<meta[^>]+(?:name|property)=["\']?{re.escape(meta_name)}["\']?[^>]+content=["\']([^"\']+)',
                    rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:name|property)=["\']?{re.escape(meta_name)}',
                ):
                    m = re.search(tmpl, html, re.IGNORECASE)
                    if m:
                        ok, ver = _wapp_match(str(meta_pat), m.group(1)) if meta_pat else (True, None)
                        if ok:
                            add(tech_name, ver, cat)
                            matched = True
                            break
                if matched:
                    break

    # ── 5. Resolve "implies" chains ───────────────────────────────────────────
    # e.g., detecting WordPress implies PHP; WooCommerce implies WordPress + PHP
    to_imply: List[str] = []
    for tech_name in list(seen):
        tech_info = wapp_data.get(tech_name, {})
        implies = tech_info.get("implies") or []
        if isinstance(implies, str):
            implies = [implies]
        for imp in implies:
            imp_name = imp.split("\\;")[0].strip()
            if imp_name and imp_name not in seen:
                to_imply.append(imp_name)

    for imp_name in to_imply:
        imp_info = wapp_data.get(imp_name, {})
        imp_cats = imp_info.get("cats") or []
        imp_cat = _WAPP_CAT.get(imp_cats[0], "Technology") if imp_cats else "Technology"
        seen[imp_name] = DetectedTechnology(hostname=hostname, name=imp_name, version=None, category=imp_cat)

    return list(seen.values())


# ── Built-in fallback signatures ───────────────────────────────────────────────
# Used to supplement Wappalyzer where it misses version info from CDN URLs,
# custom header rules, or niche infrastructure headers.

HEADER_SIGS: Dict[str, List[tuple]] = {
    "Server": [
        (r"nginx(?:/([\d.]+))?", "Nginx", "Web Server"),
        # Catch PHP version embedded in Apache Server header
        (r"Apache(?:/[\d.]+)?.*?PHP/([\d.]+)", "PHP", "Language"),
        (r"Apache(?:/([\d.]+))?", "Apache", "Web Server"),
        (r"Microsoft-IIS(?:/([\d.]+))?", "IIS", "Web Server"),
        (r"LiteSpeed", "LiteSpeed", "Web Server"),
        (r"Caddy", "Caddy", "Web Server"),
        (r"gunicorn(?:/([\d.]+))?", "Gunicorn", "WSGI Server"),
        (r"uvicorn", "Uvicorn", "ASGI Server"),
        (r"cloudflare", "Cloudflare", "CDN"),
        (r"openresty", "OpenResty", "Web Server"),
        (r"cherokee", "Cherokee", "Web Server"),
    ],
    "X-Powered-By": [
        (r"PHP(?:/([\d.]+))?", "PHP", "Language"),
        (r"ASP\.NET", "ASP.NET", "Web Framework"),
        (r"Express", "Express.js", "Web Framework"),
        (r"Next\.js", "Next.js", "Web Framework"),
        (r"Undertow", "WildFly", "App Server"),
    ],
    "X-Generator": [
        (r"Drupal\s*([\d.]+)?", "Drupal", "CMS"),
        (r"WordPress", "WordPress", "CMS"),
        (r"Joomla", "Joomla", "CMS"),
        (r"Wix", "Wix", "Website Builder"),
    ],
    "X-Drupal-Cache":        [(r".*", "Drupal",      "CMS")],
    "X-WP-Total":            [(r".*", "WordPress",   "CMS")],
    "X-Shopify-Stage":       [(r".*", "Shopify",     "E-Commerce")],
    "CF-Cache-Status":       [(r".*", "Cloudflare",  "CDN")],
    "Via":                   [(r"varnish", "Varnish", "Cache"), (r"squid", "Squid", "Cache")],
    "X-Varnish":             [(r".*", "Varnish",     "Cache")],
    "X-Amz-Cf-Id":          [(r".*", "CloudFront",  "CDN")],
    "X-Fastly-Request-ID":  [(r".*", "Fastly",      "CDN")],
    "X-Vercel-Id":          [(r".*", "Vercel",      "PaaS")],
    "X-Netlify-Cache-Tag":  [(r".*", "Netlify",     "PaaS")],
    "Fly-Request-Id":       [(r".*", "Fly.io",      "PaaS")],
    "X-Azure-Ref":          [(r".*", "Azure CDN",   "CDN")],
    "X-Cache": [
        (r"cloudfront", "CloudFront", "CDN"),
        (r"fastly",     "Fastly",     "CDN"),
    ],
}

COOKIE_SIGS: List[tuple] = [
    (r"PHPSESSID",          "PHP",              "Language"),
    (r"JSESSIONID",         "Java",             "Language"),
    (r"laravel_session",    "Laravel",          "Web Framework"),
    (r"ci_session",         "CodeIgniter",      "Web Framework"),
    (r"django",             "Django",           "Web Framework"),
    (r"wordpress_",         "WordPress",        "CMS"),
    (r"ASP\.NET_SessionId", "ASP.NET",          "Web Framework"),
    (r"shopify",            "Shopify",          "E-Commerce"),
    (r"_ga|_gid|_gat",     "Google Analytics", "Analytics"),
    (r"__stripe",           "Stripe",           "Payment Processor"),
    (r"_hjid|_hj",          "Hotjar",           "Analytics"),
    (r"intercom",           "Intercom",         "Customer Support"),
]

HTML_SIGS: List[tuple] = [
    # ── PHP version hints ──────────────────────────────────────────────────────
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*PHP[/ ]([\d.]+)', "PHP", "Language"),
    (r'Powered by.*?PHP[/ ]([\d.]+)', "PHP", "Language"),
    # ── CMS ────────────────────────────────────────────────────────────────────
    (r"/wp-content/",  "WordPress", "CMS"),
    (r"/wp-includes/", "WordPress", "CMS"),
    (r'<meta[^>]+generator[^>]+WordPress\s*([\d.]+)?', "WordPress", "CMS"),
    (r'<meta[^>]+generator[^>]+Joomla',  "Joomla", "CMS"),
    (r'<meta[^>]+generator[^>]+Drupal',  "Drupal", "CMS"),
    (r"Drupal\.settings",                "Drupal", "CMS"),
    (r'<meta[^>]+generator[^>]+Ghost\s*([\d.]+)?', "Ghost", "CMS"),
    # ── Builders ───────────────────────────────────────────────────────────────
    (r'<meta[^>]+generator[^>]+Wix', "Wix", "Website Builder"),
    (r"webflow\.com|\.webflow\.", "Webflow", "Website Builder"),
    (r"static\.squarespace\.com|squarespace-cdn", "Squarespace", "Website Builder"),
    # ── Frameworks ─────────────────────────────────────────────────────────────
    (r'ng-version="([\d.]+)"', "Angular",        "JavaScript Framework"),
    (r'angular\.js',            "AngularJS",      "JavaScript Framework"),
    (r"__nuxt",                 "Nuxt.js",        "JavaScript Framework"),
    (r'id="__NEXT_DATA__"',     "Next.js",        "JavaScript Framework"),
    (r"react(?:-dom)?\.(?:min\.)?js|data-reactroot", "React", "JavaScript Framework"),
    (r'vue(?:@([\d.]+))?(?:\.min)?\.js', "Vue.js", "JavaScript Framework"),
    (r"svelte",                 "Svelte",         "JavaScript Framework"),
    (r"gatsby",                 "Gatsby",         "Static Site Generator"),
    (r"__RAILS_|rails-ujs",     "Ruby on Rails",  "Web Framework"),
    # ── E-Commerce ─────────────────────────────────────────────────────────────
    (r"shopify\.com",                        "Shopify",    "E-Commerce"),
    (r"woocommerce",                         "WooCommerce","E-Commerce"),
    (r"Mage\.Config|mage/bootstrap|mage2\.js","Magento",   "E-Commerce"),
    (r"prestashop|PrestaShop",               "PrestaShop", "E-Commerce"),
    (r"route=common|opencart",               "OpenCart",   "E-Commerce"),
    (r"bigcommerce\.com",                    "BigCommerce","E-Commerce"),
    # ── CSS Frameworks ─────────────────────────────────────────────────────────
    (r"bootstrap(?:\.min)?\.(?:css|js)", "Bootstrap",   "CSS Framework"),
    (r"tailwindcss",                     "Tailwind CSS","CSS Framework"),
    # ── jQuery — CDN URL version extraction (most accurate) ────────────────────
    (r"ajax\.googleapis\.com/ajax/libs/jquery/([\d.]+)/",      "jQuery", "JavaScript Library"),
    (r"cdnjs\.cloudflare\.com/ajax/libs/jquery/([\d.]+)/",     "jQuery", "JavaScript Library"),
    (r"cdn\.jsdelivr\.net/npm/jquery@([\d.]+)",                "jQuery", "JavaScript Library"),
    (r"code\.jquery\.com/jquery-([\d.]+)(?:\.min)?\.js",       "jQuery", "JavaScript Library"),
    # ── Vue.js CDN version extraction ──────────────────────────────────────────
    (r"cdn\.jsdelivr\.net/npm/vue@([\d.]+)",                   "Vue.js", "JavaScript Framework"),
    (r"unpkg\.com/vue@([\d.]+)",                               "Vue.js", "JavaScript Framework"),
    (r"cdnjs\.cloudflare\.com/ajax/libs/vue/([\d.]+)/",        "Vue.js", "JavaScript Framework"),
    # ── React CDN version extraction ───────────────────────────────────────────
    (r"cdn\.jsdelivr\.net/npm/react@([\d.]+)",                 "React",  "JavaScript Framework"),
    (r"unpkg\.com/react@([\d.]+)",                             "React",  "JavaScript Framework"),
    # ── Bootstrap CDN version extraction ───────────────────────────────────────
    (r"cdn\.jsdelivr\.net/npm/bootstrap@([\d.]+)",             "Bootstrap", "CSS Framework"),
    (r"stackpath\.bootstrapcdn\.com/bootstrap/([\d.]+)/",      "Bootstrap", "CSS Framework"),
    (r"maxcdn\.bootstrapcdn\.com/bootstrap/([\d.]+)/",         "Bootstrap", "CSS Framework"),
    (r"cdnjs\.cloudflare\.com/ajax/libs/twitter-bootstrap/([\d.]+)/", "Bootstrap", "CSS Framework"),
    # ── Other library CDN versions ─────────────────────────────────────────────
    (r"cdn\.jsdelivr\.net/npm/lodash@([\d.]+)",                "Lodash",    "JavaScript Library"),
    (r"cdn\.jsdelivr\.net/npm/moment@([\d.]+)",                "Moment.js", "JavaScript Library"),
    (r"cdn\.jsdelivr\.net/npm/axios@([\d.]+)",                 "Axios",     "JavaScript Library"),
    # ── Generic inline fallbacks ───────────────────────────────────────────────
    (r"jQuery(?:\s+v)?([\d.]+)?",    "jQuery",    "JavaScript Library"),
    (r"lodash(?:\.min)?\.js",        "Lodash",    "JavaScript Library"),
    (r"moment(?:\.min)?\.js",        "Moment.js", "JavaScript Library"),
    (r"axios(?:\.min)?\.js",         "Axios",     "JavaScript Library"),
    # ── Analytics & Tag Managers ───────────────────────────────────────────────
    (r"google-analytics\.com/analytics\.js|gtag\('config'", "Google Analytics",   "Analytics"),
    (r"googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]{4,}",    "Google Tag Manager", "Analytics"),
    (r"hotjar\.com|hj\('create'",                           "Hotjar",             "Analytics"),
    (r"mixpanel\.com|mixpanel\.init",                       "Mixpanel",           "Analytics"),
    (r"segment\.com/analytics\.js|analytics\.load\(",      "Segment",            "Analytics"),
    (r"plausible\.io/js",                                   "Plausible",          "Analytics"),
    (r"clarity\.ms/tag",                                    "Microsoft Clarity",  "Analytics"),
    # ── Customer Support & Marketing ───────────────────────────────────────────
    (r"intercom\.io|window\.intercomSettings", "Intercom", "Customer Support"),
    (r"hs-scripts\.com|hubspot\.com/hs/hsstatic", "HubSpot", "Marketing Automation"),
    # ── Payments ───────────────────────────────────────────────────────────────
    (r"js\.stripe\.com|stripe\.com/v3",       "Stripe",    "Payment Processor"),
    (r"paypal\.com/sdk/js|paypalobjects\.com", "PayPal",   "Payment Processor"),
    (r"js\.braintreegateway\.com",            "Braintree", "Payment Processor"),
    (r"js\.squareup\.com|checkout\.square\.link", "Square","Payment Processor"),
    # ── CDN & Infrastructure ───────────────────────────────────────────────────
    (r"cloudfront\.net",             "CloudFront", "CDN"),
    (r"fastly\.net",                 "Fastly",     "CDN"),
    (r"jsdelivr\.net",               "jsDelivr",   "CDN"),
    (r"akamaized\.net|akamai\.com",  "Akamai",     "CDN"),
    # ── Security ───────────────────────────────────────────────────────────────
    (r"google\.com/recaptcha|grecaptcha\.execute", "reCAPTCHA", "Security"),
    (r"hcaptcha\.com",  "hCaptcha",  "Security"),
    (r"datadome\.co",   "DataDome",  "Bot Protection"),
    # ── Monitoring & Error Tracking ────────────────────────────────────────────
    (r"sentry\.io|Sentry\.init|\.sentry-cdn\.com", "Sentry",    "Monitoring"),
    (r"newrelic\.com|NREUM\.",                      "New Relic", "Monitoring"),
    (r"datadoghq\.com",                             "Datadog",   "Monitoring"),
    (r"bugsnag\.com",                               "Bugsnag",   "Monitoring"),
    # ── Fonts & Icons ──────────────────────────────────────────────────────────
    (r"fonts\.googleapis\.com|fonts\.gstatic\.com", "Google Fonts", "Font"),
    (r"font-awesome|fontawesome",                   "Font Awesome", "Icon Library"),
]


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class DetectedTechnology:
    hostname: str
    name: str
    version: Optional[str] = None
    category: str = ""


@dataclass
class TechScanResult:
    technologies: List[DetectedTechnology] = field(default_factory=list)


# ── Scanner ───────────────────────────────────────────────────────────────────

class TechScanner:
    """
    Detects web technologies from HTTP response headers, cookies, and HTML body.

    Primary detection engine: Wappalyzer fingerprint database.
    Fallback / supplement: built-in regex signatures (CDN URL versions, etc.).
    """

    def __init__(self, hostnames: List[str], timeout: float = 8.0):
        self.hostnames = list(set(filter(None, hostnames)))
        self.timeout = timeout

    def _parse_response(
        self, hostname: str, resp: httpx.Response
    ) -> List[DetectedTechnology]:
        """Built-in regex fallback — supplements Wappalyzer results."""
        seen: Dict[str, DetectedTechnology] = {}

        def add(name: str, version: Optional[str] = None, category: str = ""):
            if name not in seen:
                seen[name] = DetectedTechnology(
                    hostname=hostname, name=name, version=version, category=category
                )
            elif version and not seen[name].version:
                seen[name].version = version

        # Headers
        for header_name, sigs in HEADER_SIGS.items():
            val = resp.headers.get(header_name, "")
            if not val:
                continue
            for pattern, name, cat in sigs:
                m = re.search(pattern, val, re.IGNORECASE)
                if m:
                    # Last non-None group — multi-group patterns (Apache.*PHP/ver)
                    version = None
                    if m.lastindex:
                        for g in range(m.lastindex, 0, -1):
                            if m.group(g) is not None:
                                version = m.group(g)
                                break
                    add(name, version, cat)

        # Cookies
        cookie_str = " ".join(
            v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"
        )
        for pattern, name, cat in COOKIE_SIGS:
            if re.search(pattern, cookie_str, re.IGNORECASE):
                add(name, category=cat)

        # HTML body (first 60 KB only)
        if resp.status_code < 400:
            try:
                html = resp.text[:61440]
                for pattern, name, cat in HTML_SIGS:
                    m = re.search(pattern, html, re.IGNORECASE)
                    if m:
                        version = m.group(1) if m.lastindex else None
                        add(name, version, cat)
            except Exception:
                pass

        return list(seen.values())

    async def _probe(
        self,
        client: httpx.AsyncClient,
        hostname: str,
        wapp_data: dict,
    ) -> List[DetectedTechnology]:
        for scheme in ("https", "http"):
            try:
                resp = await client.get(
                    f"{scheme}://{hostname}/",
                    follow_redirects=True,
                )

                # Primary: Wappalyzer fingerprint database
                merged: Dict[str, DetectedTechnology] = {}
                if wapp_data:
                    for t in _wapp_detect(resp, wapp_data, hostname):
                        merged[t.name] = t

                # Supplement: built-in signatures fill gaps / add CDN versions
                for t in self._parse_response(hostname, resp):
                    if t.name not in merged:
                        merged[t.name] = t
                    elif t.version and not merged[t.name].version:
                        merged[t.name].version = t.version

                techs = list(merged.values())
                logger.debug(f"TechScanner: {hostname} → {[t.name for t in techs]}")
                return techs
            except Exception:
                continue
        return []

    async def run(self) -> TechScanResult:
        result = TechScanResult()
        if not self.hostnames:
            return result

        # Load Wappalyzer fingerprints (in-memory after first scan)
        wapp_data = await _load_wappalyzer()

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
                        techs = await self._probe(client, hostname, wapp_data)
                        result.technologies.extend(techs)
                    except Exception as e:
                        logger.debug(f"TechScanner error for {hostname}: {e}")

            await asyncio.gather(
                *[probe(h) for h in self.hostnames], return_exceptions=True
            )

        logger.info(
            f"TechScanner: {len(result.technologies)} detections "
            f"across {len(self.hostnames)} hosts"
        )
        return result
