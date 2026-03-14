"""WHOIS Scanner — RDAP-first approach

Primary:  RDAP (Registration Data Access Protocol) via IANA bootstrap
          HTTP/JSON-based — works without port 43 or the `whois` CLI tool.
Fallback: python-whois library (port 43 TCP)
Fallback: system `whois` CLI
"""
import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

_WHOIS_TIMEOUT = 20.0

# ── RDAP bootstrap ────────────────────────────────────────────────────────────
# Common TLDs hardcoded for zero-latency lookup on the most frequent cases.
_RDAP_KNOWN: Dict[str, str] = {
    "com":    "https://rdap.verisign.com/com/v1/",
    "net":    "https://rdap.verisign.com/net/v1/",
    "org":    "https://rdap.publicinterestregistry.org/rdap/",
    "edu":    "https://rdap.educause.edu/",
    "gov":    "https://rdap.dotgov.gov/",
    "io":     "https://rdap.nic.io/",
    "co":     "https://rdap.nic.co/",
    "uk":     "https://rdap.nominet.uk/uk/",
    "co.uk":  "https://rdap.nominet.uk/uk/",
    "de":     "https://rdap.denic.de/",
    "fr":     "https://rdap.nic.fr/",
    "nl":     "https://rdap.sidn.nl/",
    "eu":     "https://rdap.eu/",
    "au":     "https://rdap.auda.org.au/",
    "com.au": "https://rdap.auda.org.au/",
    "in":     "https://rdap.registry.in/",
    "us":     "https://rdap.iana.org/",
    "info":   "https://rdap.afilias.net/rdap/info/",
    "biz":    "https://rdap.afilias.net/rdap/biz/",
    "app":    "https://rdap.nic.google/",
    "dev":    "https://rdap.nic.google/",
}

_RDAP_BOOTSTRAP: Dict[str, str] = {}   # loaded once from IANA
_BOOTSTRAP_LOADED = False

IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"


async def _ensure_bootstrap(client: httpx.AsyncClient) -> None:
    global _RDAP_BOOTSTRAP, _BOOTSTRAP_LOADED
    if _BOOTSTRAP_LOADED:
        return
    try:
        resp = await client.get(IANA_BOOTSTRAP_URL, timeout=8.0)
        if resp.status_code == 200:
            for entry in resp.json().get("services", []):
                tlds, urls = entry[0], entry[1]
                if urls:
                    base = urls[0] if urls[0].endswith("/") else urls[0] + "/"
                    for tld in tlds:
                        _RDAP_BOOTSTRAP[tld.lower()] = base
            _BOOTSTRAP_LOADED = True
    except Exception as exc:
        logger.debug(f"RDAP bootstrap fetch failed: {exc}")


def _rdap_base(domain: str) -> Optional[str]:
    """Return the RDAP base URL for this domain's TLD."""
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return None
    # Try 2-part TLD (e.g. co.uk)
    if len(parts) >= 3:
        two = f"{parts[-2]}.{parts[-1]}"
        if two in _RDAP_KNOWN:
            return _RDAP_KNOWN[two]
        if two in _RDAP_BOOTSTRAP:
            return _RDAP_BOOTSTRAP[two]
    tld = parts[-1]
    return _RDAP_KNOWN.get(tld) or _RDAP_BOOTSTRAP.get(tld)


# ── RDAP JSON parser ──────────────────────────────────────────────────────────

def _parse_date(s: str) -> Optional[datetime]:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d"):
        try:
            # Return naive UTC datetime — DB column is TIMESTAMP WITHOUT TIME ZONE
            return datetime.strptime(s.strip(), fmt).replace(tzinfo=None)
        except ValueError:
            continue
    return None


def _vcard_field(vcard_entries: list, field_name: str) -> Optional[str]:
    """Extract a field value from a vcardArray entries list."""
    for item in vcard_entries:
        if isinstance(item, list) and item and item[0] == field_name:
            val = item[-1]
            if isinstance(val, list):
                # adr type: ["", pobox, street, city, state, postal, country]
                val = val[-1] if val else None
            if val and str(val).strip():
                return str(val).strip()
    return None


def _parse_rdap(data: dict) -> "WhoisScanResult":
    result = WhoisScanResult()

    # Dates from events
    for event in data.get("events", []):
        action = event.get("eventAction", "").lower()
        date_str = event.get("eventDate", "")
        if not date_str:
            continue
        dt = _parse_date(date_str)
        if action == "registration" and not result.creation_date:
            result.creation_date = dt
        elif action == "expiration" and not result.expiry_date:
            result.expiry_date = dt
        elif action in ("last changed", "last update") and not result.updated_date:
            result.updated_date = dt

    # Nameservers
    for ns in data.get("nameservers", []):
        name = ns.get("ldhName") or ns.get("unicodeName")
        if name:
            result.name_servers.append(name.lower())

    # Domain status
    statuses = data.get("status", [])
    if statuses:
        result.status = "; ".join(str(s) for s in statuses[:4])

    # DNSSEC
    secure_dns = data.get("secureDNS", {})
    if secure_dns.get("delegationSigned"):
        result.dnssec = "signedDelegation"
    elif "delegationSigned" in secure_dns:
        result.dnssec = "unsigned"

    # Entities (registrar + registrant)
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        vcard_raw = entity.get("vcardArray", [])
        vcard_entries = vcard_raw[1] if len(vcard_raw) > 1 else []

        if "registrar" in roles and not result.registrar:
            result.registrar = _vcard_field(vcard_entries, "fn")

        if "registrant" in roles:
            if not result.registrant_name:
                result.registrant_name = _vcard_field(vcard_entries, "fn")
            if not result.registrant_org:
                result.registrant_org = _vcard_field(vcard_entries, "org")
            if not result.registrant_email:
                result.registrant_email = _vcard_field(vcard_entries, "email")
            if not result.registrant_country:
                result.registrant_country = _vcard_field(vcard_entries, "adr")

    return result


# ── python-whois fallback helpers ─────────────────────────────────────────────

def _extract_date(val) -> Optional[datetime]:
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    if isinstance(val, datetime):
        # Strip timezone — DB column is TIMESTAMP WITHOUT TIME ZONE
        return val.replace(tzinfo=None)
    return None


def _extract_str(val) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    return str(val).strip() if val else None


def _extract_list(val) -> List[str]:
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v).strip().lower() for v in val if v]
    return [str(val).strip().lower()]


# ── Raw WHOIS text parser (CLI fallback) ──────────────────────────────────────

_DATE_PATTERNS = [
    re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)'),
    re.compile(r'(\d{2}-\w{3}-\d{4})'),
    re.compile(r'(\d{4}\.\d{2}\.\d{2}\s+\d{2}:\d{2}:\d{2})'),
    re.compile(r'(\d{2}/\d{2}/\d{4})'),
]
_DATE_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
    "%d-%b-%Y", "%Y.%m.%d %H:%M:%S", "%m/%d/%Y", "%Y-%m-%d",
]


def _parse_date_str(s: str) -> Optional[datetime]:
    s = s.strip().rstrip("Z")
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _parse_raw_whois(text: str) -> "WhoisScanResult":
    result = WhoisScanResult(raw=text[:4000])
    name_servers: list = []
    statuses: list = []

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("%") or stripped.startswith("#"):
            continue
        lower = stripped.lower()

        def _val(l: str) -> str:
            return l.split(":", 1)[1].strip() if ":" in l else ""

        v = _val(stripped)
        if not v:
            continue

        if lower.startswith("registrar:") and not result.registrar:
            result.registrar = v
        elif any(lower.startswith(p) for p in (
            "creation date:", "created:", "registered on:",
            "registration time:", "created on:", "commencement date:",
        )) and not result.creation_date:
            for pat in _DATE_PATTERNS:
                m = pat.search(v)
                if m:
                    result.creation_date = _parse_date_str(m.group(1))
                    if result.creation_date:
                        break
        elif any(lower.startswith(p) for p in (
            "registry expiry date:", "expiry date:", "expiration date:",
            "expires:", "expires on:", "expiration time:", "paid-till:",
        )) and not result.expiry_date:
            for pat in _DATE_PATTERNS:
                m = pat.search(v)
                if m:
                    result.expiry_date = _parse_date_str(m.group(1))
                    if result.expiry_date:
                        break
        elif any(lower.startswith(p) for p in (
            "updated date:", "last modified:", "last updated:", "modified:",
        )) and not result.updated_date:
            for pat in _DATE_PATTERNS:
                m = pat.search(v)
                if m:
                    result.updated_date = _parse_date_str(m.group(1))
                    if result.updated_date:
                        break
        elif any(lower.startswith(p) for p in (
            "registrant name:", "registrant:", "registrant contact name:",
        )) and not result.registrant_name:
            result.registrant_name = v
        elif any(lower.startswith(p) for p in (
            "registrant organization:", "registrant org:", "org:",
            "registrant organisation:",
        )) and not result.registrant_org:
            result.registrant_org = v
        elif any(lower.startswith(p) for p in (
            "registrant email:", "admin email:",
        )) and not result.registrant_email:
            result.registrant_email = v
        elif any(lower.startswith(p) for p in (
            "registrant country:", "country:",
        )) and not result.registrant_country:
            if len(v) <= 50:
                result.registrant_country = v
        elif any(lower.startswith(p) for p in (
            "name server:", "nameserver:", "nserver:",
        )):
            ns = v.lower().split()[0] if v else ""
            if ns and ns not in name_servers:
                name_servers.append(ns)
        elif lower.startswith("dnssec:") and not result.dnssec:
            result.dnssec = v
        elif lower.startswith("domain status:") or lower.startswith("status:"):
            sv = v.split("https://")[0].strip()
            if sv and len(statuses) < 4:
                statuses.append(sv)

    result.name_servers = name_servers[:8]
    if statuses:
        result.status = "; ".join(statuses[:3])
    return result


# ── Data class ────────────────────────────────────────────────────────────────

@dataclass
class WhoisScanResult:
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    registrant_name: Optional[str] = None
    registrant_org: Optional[str] = None
    registrant_email: Optional[str] = None
    registrant_country: Optional[str] = None
    name_servers: List[str] = field(default_factory=list)
    status: Optional[str] = None
    dnssec: Optional[str] = None
    raw: Optional[str] = None
    error: Optional[str] = None

    def has_useful_data(self) -> bool:
        return any([
            self.registrar,
            self.creation_date,
            self.expiry_date,
            self.registrant_org,
            self.name_servers,
        ])


# ── Main scanner ──────────────────────────────────────────────────────────────

class WhoisScanner:
    """
    Fetches WHOIS/registration data for a domain.

    Strategy (fastest-first):
      1. RDAP via IANA bootstrap (HTTP/JSON — no port 43, no CLI needed)
      2. python-whois library (port 43 TCP)
      3. system `whois` CLI
    """

    def __init__(self, domain: str):
        self.domain = domain

    async def run(self) -> WhoisScanResult:
        # ── Attempt 1: RDAP ───────────────────────────────────────────────────
        result = await self._try_rdap()
        if result.has_useful_data():
            logger.info(
                f"WhoisScanner (RDAP): {self.domain} → "
                f"registrar={result.registrar}, expiry={result.expiry_date}"
            )
            return result

        # ── Attempt 2: python-whois ───────────────────────────────────────────
        result2 = await self._try_python_whois()
        if result2.has_useful_data():
            logger.info(
                f"WhoisScanner (python-whois): {self.domain} → "
                f"registrar={result2.registrar}, expiry={result2.expiry_date}"
            )
            return result2

        # ── Attempt 3: system CLI ─────────────────────────────────────────────
        result3 = await self._try_cli_whois()
        if result3.has_useful_data():
            logger.info(
                f"WhoisScanner (cli): {self.domain} → "
                f"registrar={result3.registrar}, expiry={result3.expiry_date}"
            )
            return result3

        # All failed
        best = next((r for r in [result3, result2, result] if r.raw or r.error), result)
        if not best.error:
            best.error = f"No WHOIS/RDAP data found for {self.domain}"
        return best

    async def _try_rdap(self) -> WhoisScanResult:
        result = WhoisScanResult()
        try:
            async with httpx.AsyncClient(follow_redirects=True) as client:
                # Load bootstrap if needed
                await _ensure_bootstrap(client)

                base = _rdap_base(self.domain)
                if not base:
                    result.error = "No RDAP server known for this TLD"
                    return result

                url = f"{base}domain/{self.domain}"
                resp = await client.get(
                    url,
                    timeout=12.0,
                    headers={"Accept": "application/rdap+json, application/json"},
                )
                if resp.status_code == 404:
                    result.error = "Domain not found in RDAP"
                    return result
                if resp.status_code != 200:
                    result.error = f"RDAP returned HTTP {resp.status_code}"
                    return result

                data = resp.json()
                result = _parse_rdap(data)

        except asyncio.TimeoutError:
            result.error = "RDAP timed out"
        except Exception as exc:
            result.error = str(exc)
            logger.debug(f"WhoisScanner RDAP failed for {self.domain}: {exc}")

        return result

    async def _try_python_whois(self) -> WhoisScanResult:
        result = WhoisScanResult()
        try:
            data = await asyncio.wait_for(
                asyncio.to_thread(self._sync_whois, self.domain),
                timeout=_WHOIS_TIMEOUT,
            )
            if data is None:
                result.error = "python-whois returned None"
                return result

            result.registrar = _extract_str(getattr(data, "registrar", None))
            result.creation_date = _extract_date(getattr(data, "creation_date", None))
            result.expiry_date = _extract_date(getattr(data, "expiration_date", None))
            result.updated_date = _extract_date(getattr(data, "updated_date", None))
            result.registrant_name = _extract_str(getattr(data, "name", None))
            result.registrant_org = _extract_str(getattr(data, "org", None))
            result.registrant_email = _extract_str(getattr(data, "emails", None))
            result.registrant_country = _extract_str(getattr(data, "country", None))
            result.name_servers = _extract_list(getattr(data, "name_servers", None))
            result.dnssec = _extract_str(getattr(data, "dnssec", None))
            status_raw = getattr(data, "status", None)
            if isinstance(status_raw, list):
                result.status = "; ".join(str(s).split("https://")[0].strip() for s in status_raw[:3])
            elif status_raw:
                result.status = str(status_raw).split("https://")[0].strip()
        except asyncio.TimeoutError:
            result.error = "python-whois timed out"
        except Exception as exc:
            result.error = str(exc)
            logger.debug(f"WhoisScanner python-whois failed for {self.domain}: {exc}")
        return result

    async def _try_cli_whois(self) -> WhoisScanResult:
        result = WhoisScanResult()
        try:
            proc = await asyncio.create_subprocess_exec(
                "whois", self.domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=_WHOIS_TIMEOUT)
            except asyncio.TimeoutError:
                proc.kill()
                result.error = "whois CLI timed out"
                return result
            text = stdout.decode("utf-8", errors="replace")
            if text.strip():
                result = _parse_raw_whois(text)
        except FileNotFoundError:
            result.error = "whois command not found"
            logger.warning("WhoisScanner: system `whois` command not available")
        except Exception as exc:
            result.error = str(exc)
        return result

    @staticmethod
    def _sync_whois(domain: str):
        import whois
        return whois.whois(domain)
