import asyncio
import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

logger = logging.getLogger(__name__)

TIMEOUT = 8.0


@dataclass
class SSLScanResult:
    hostname: str
    # Feature 16 — Certificate details
    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    is_expired: bool = False
    is_self_signed: bool = False
    san_domains: List[str] = field(default_factory=list)
    is_wildcard: bool = False
    # Feature 17 — Protocol support & grading
    # e.g. {"TLS 1.3": True, "TLS 1.2": True, "TLS 1.1": False, "TLS 1.0": False}
    protocols: Dict[str, bool] = field(default_factory=dict)
    # Inferred vulnerabilities: {"BEAST": False, "Weak Protocols": True}
    vulnerabilities: Dict[str, bool] = field(default_factory=dict)
    grade: Optional[str] = None
    error: Optional[str] = None


class SSLScanner:
    """
    Analyzes SSL/TLS configuration for alive subdomains.
    Feature 16: Certificate info — issuer, expiry, SANs, wildcard, self-signed.
    Feature 17: Protocol support (TLS 1.0–1.3), vulnerability inference, A+/A/B/C/D/F grade.
    Uses Python stdlib ssl + cryptography library only — no extra pip installs needed.
    """

    def __init__(self, hostnames: List[str], timeout: float = TIMEOUT):
        self.hostnames = list(set(filter(None, hostnames)))
        self.timeout = timeout

    # ── Public entry point ──────────────────────────────────────────────────────

    async def run(self) -> List[SSLScanResult]:
        if not self.hostnames:
            return []

        sem = asyncio.Semaphore(5)  # SSL handshakes are heavy; limit concurrency

        async def scan_one(hostname: str) -> SSLScanResult:
            async with sem:
                try:
                    return await asyncio.to_thread(self._scan_sync, hostname)
                except Exception as e:
                    logger.debug(f"SSLScanner error for {hostname}: {e}")
                    return SSLScanResult(hostname=hostname, error=str(e))

        results = await asyncio.gather(
            *[scan_one(h) for h in self.hostnames], return_exceptions=True
        )

        final: List[SSLScanResult] = []
        for r in results:
            if isinstance(r, SSLScanResult):
                final.append(r)

        logger.info(f"SSLScanner: completed {len(final)} hosts")
        return final

    # ── Synchronous helpers (executed in thread pool via asyncio.to_thread) ─────

    def _scan_sync(self, hostname: str) -> SSLScanResult:
        result = SSLScanResult(hostname=hostname)

        # Step 1: certificate info (abort on failure — no cert = no further data)
        try:
            self._get_cert_info(hostname, result)
        except Exception as e:
            result.error = f"cert: {e}"
            return result

        # Step 2: probe which TLS versions the server accepts
        self._test_protocols(hostname, result)

        # Step 3: infer vulnerabilities from observed protocol support
        self._infer_vulnerabilities(result)

        # Step 4: compute A+–F grade
        result.grade = self._compute_grade(result)

        logger.debug(
            f"SSLScanner: {hostname} grade={result.grade} "
            f"protocols={result.protocols} expired={result.is_expired}"
        )
        return result

    def _get_cert_info(self, hostname: str, result: SSLScanResult) -> None:
        """Connect to port 443 and parse the DER certificate."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)

        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        # Issuer (prefer CN, fall back to O)
        try:
            result.issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            try:
                result.issuer = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
            except (IndexError, Exception):
                result.issuer = str(cert.issuer)

        # Subject CN
        try:
            result.subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            result.subject = str(cert.subject)

        # Validity — cryptography ≥42 uses *_utc (timezone-aware); older uses naive UTC
        try:
            result.valid_from = cert.not_valid_before_utc  # type: ignore[attr-defined]
            result.valid_until = cert.not_valid_after_utc   # type: ignore[attr-defined]
        except AttributeError:
            # cryptography <42: naive datetimes, assumed UTC
            result.valid_from = cert.not_valid_before.replace(tzinfo=timezone.utc)   # type: ignore[attr-defined]
            result.valid_until = cert.not_valid_after.replace(tzinfo=timezone.utc)    # type: ignore[attr-defined]

        result.is_expired = datetime.now(timezone.utc) > result.valid_until
        result.is_self_signed = cert.issuer == cert.subject

        # Subject Alternative Names
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            result.san_domains = [
                n if isinstance(n, str) else n.value
                for n in san_ext.value.get_values_for_type(x509.DNSName)
            ]
            result.is_wildcard = any(n.startswith("*.") for n in result.san_domains)
        except x509.ExtensionNotFound:
            result.san_domains = []

    def _test_protocol(
        self,
        hostname: str,
        min_ver: "ssl.TLSVersion",
        max_ver: "ssl.TLSVersion",
    ) -> bool:
        """Return True if server negotiates a TLS connection limited to [min_ver, max_ver]."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = min_ver
            ctx.maximum_version = max_ver
            with socket.create_connection((hostname, 443), timeout=3.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    return True
        except Exception:
            return False

    def _test_protocols(self, hostname: str, result: SSLScanResult) -> None:
        """Test TLS 1.3, 1.2, 1.1, 1.0 — skip versions not available in this Python build."""
        always_available = [
            ("TLS 1.3", "TLSv1_3"),
            ("TLS 1.2", "TLSv1_2"),
        ]
        optional = [
            ("TLS 1.1", "TLSv1_1"),
            ("TLS 1.0", "TLSv1"),
        ]

        for label, attr in always_available:
            ver = getattr(ssl.TLSVersion, attr)
            result.protocols[label] = self._test_protocol(hostname, ver, ver)

        for label, attr in optional:
            ver = getattr(ssl.TLSVersion, attr, None)
            if ver is not None:
                result.protocols[label] = self._test_protocol(hostname, ver, ver)
            else:
                result.protocols[label] = False  # disabled in this OpenSSL build

    def _infer_vulnerabilities(self, result: SSLScanResult) -> None:
        """
        Infer common vulnerabilities from protocol support:
        - BEAST  : exploits TLS 1.0 CBC — flag if TLS 1.0 accepted
        - Weak Protocols: TLS 1.0 or TLS 1.1 accepted (deprecated RFC 8996)
        """
        tls10 = result.protocols.get("TLS 1.0", False)
        tls11 = result.protocols.get("TLS 1.1", False)
        result.vulnerabilities["BEAST"] = tls10
        result.vulnerabilities["Weak Protocols"] = tls10 or tls11

    def _compute_grade(self, result: SSLScanResult) -> str:
        """
        Grade SSL/TLS configuration:
          A+ : TLS 1.2+ only, TLS 1.3 supported, cert valid, not self-signed
          A  : TLS 1.2+ only, cert valid
          B  : TLS 1.1 also accepted (deprecated but not dangerous)
          C  : TLS 1.0 also accepted (BEAST-susceptible)
          D  : No TLS 1.2 or 1.3 (TLS 1.0/1.1 only)
          F  : Expired cert, self-signed cert, or no working SSL
        """
        if result.is_expired or result.is_self_signed:
            return "F"

        has_tls12 = result.protocols.get("TLS 1.2", False)
        has_tls13 = result.protocols.get("TLS 1.3", False)

        if not has_tls12 and not has_tls13:
            return "D"  # only deprecated versions

        tls10 = result.protocols.get("TLS 1.0", False)
        tls11 = result.protocols.get("TLS 1.1", False)

        if tls10:
            return "C"
        if tls11:
            return "B"
        if has_tls13:
            return "A+"
        return "A"
