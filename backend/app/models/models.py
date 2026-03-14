import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime,
    ForeignKey, Text, JSON, Enum as SQLEnum
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from app.core.database import Base
import enum


# ── Enums ──────────────────────────────────────────────

class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ── Scan (Top-level entity) ────────────────────────────

class Scan(Base):
    """A single scan job. One domain = one scan."""
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain = Column(String(255), nullable=False, index=True)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING)
    risk_score = Column(Float, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    error_message = Column(Text, nullable=True)
    zone_transfer_successful = Column(Boolean, nullable=True, default=False)

    # Relationships
    subdomains = relationship("Subdomain", back_populates="scan", cascade="all, delete-orphan")
    dns_records = relationship("DNSRecord", back_populates="scan", cascade="all, delete-orphan")


# ── Subdomain ──────────────────────────────────────────

class Subdomain(Base):
    """Discovered subdomain for a scan."""
    __tablename__ = "subdomains"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    hostname = Column(String(512), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    is_alive = Column(Boolean, default=False)
    http_status = Column(Integer, nullable=True)
    page_title = Column(String(512), nullable=True)
    source = Column(String(100), nullable=True)  # how it was discovered
    reverse_hostname = Column(String(512), nullable=True)  # PTR record
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="subdomains")
    ports = relationship("Port", back_populates="subdomain", cascade="all, delete-orphan")
    technologies = relationship("Technology", back_populates="subdomain", cascade="all, delete-orphan")
    waf = relationship("WAFResult", back_populates="subdomain", uselist=False, cascade="all, delete-orphan")
    ssl_info = relationship("SSLInfo", back_populates="subdomain", uselist=False, cascade="all, delete-orphan")
    header_analysis = relationship("HeaderAnalysis", back_populates="subdomain", uselist=False, cascade="all, delete-orphan")
    takeover = relationship("SubdomainTakeover", back_populates="subdomain", uselist=False, cascade="all, delete-orphan")


# ── Port ───────────────────────────────────────────────

class Port(Base):
    """Open port on a subdomain/IP."""
    __tablename__ = "ports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subdomain_id = Column(UUID(as_uuid=True), ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False)
    port_number = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")
    service = Column(String(100), nullable=True)
    version = Column(String(200), nullable=True)
    banner = Column(Text, nullable=True)

    # Relationships
    subdomain = relationship("Subdomain", back_populates="ports")


# ── Technology ─────────────────────────────────────────

class Technology(Base):
    """Detected technology on a subdomain."""
    __tablename__ = "technologies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subdomain_id = Column(UUID(as_uuid=True), ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(200), nullable=False)
    version = Column(String(100), nullable=True)
    category = Column(String(100), nullable=True)  # CMS, Framework, Server, etc.

    # Relationships
    subdomain = relationship("Subdomain", back_populates="technologies")
    cves = relationship("CVE", back_populates="technology", cascade="all, delete-orphan")


# ── WAF Result ─────────────────────────────────────────

class WAFResult(Base):
    """WAF/CDN detection result for a subdomain."""
    __tablename__ = "waf_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subdomain_id = Column(UUID(as_uuid=True), ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False, unique=True)
    detected = Column(Boolean, default=False)
    waf_name = Column(String(200), nullable=True)
    manufacturer = Column(String(200), nullable=True)

    # Relationships
    subdomain = relationship("Subdomain", back_populates="waf")


# ── SSL Info ───────────────────────────────────────────

class SSLInfo(Base):
    """SSL/TLS certificate and security info."""
    __tablename__ = "ssl_info"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subdomain_id = Column(UUID(as_uuid=True), ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False, unique=True)
    issuer = Column(String(300), nullable=True)
    subject = Column(String(300), nullable=True)
    valid_from = Column(DateTime, nullable=True)
    valid_until = Column(DateTime, nullable=True)
    is_expired = Column(Boolean, default=False)
    san_domains = Column(JSONB, nullable=True)  # List of Subject Alternative Names
    grade = Column(String(5), nullable=True)    # A+, A, B, C, D, F
    protocols = Column(JSONB, nullable=True)     # TLS versions supported
    vulnerabilities = Column(JSONB, nullable=True)  # Heartbleed, POODLE, etc.

    # Relationships
    subdomain = relationship("Subdomain", back_populates="ssl_info")


# ── DNS Record ─────────────────────────────────────────

class DNSRecord(Base):
    """DNS records for the domain."""
    __tablename__ = "dns_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    record_type = Column(String(10), nullable=False)  # A, AAAA, MX, NS, TXT, CNAME, SOA
    hostname = Column(String(512), nullable=False)
    value = Column(Text, nullable=False)
    ttl = Column(Integer, nullable=True)

    # Relationships
    scan = relationship("Scan", back_populates="dns_records")


# ── CVE ────────────────────────────────────────────────

class CVE(Base):
    """Known vulnerability linked to a detected technology."""
    __tablename__ = "cves"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    technology_id = Column(UUID(as_uuid=True), ForeignKey("technologies.id", ondelete="CASCADE"), nullable=False)
    cve_id = Column(String(20), nullable=False)   # CVE-2024-XXXX
    severity = Column(SQLEnum(Severity), nullable=True)
    cvss_score = Column(Float, nullable=True)
    description = Column(Text, nullable=True)

    # Relationships
    technology = relationship("Technology", back_populates="cves")


# ── Email Security ─────────────────────────────────────

class EmailSecurity(Base):
    """SPF, DKIM, DMARC analysis."""
    __tablename__ = "email_security"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True)
    spf_record = Column(Text, nullable=True)
    spf_valid = Column(Boolean, nullable=True)
    dkim_found = Column(Boolean, nullable=True)
    dkim_selector = Column(String(100), nullable=True)
    dmarc_record = Column(Text, nullable=True)
    dmarc_policy = Column(String(20), nullable=True)  # none, quarantine, reject
    is_spoofable = Column(Boolean, nullable=True)
    spf_mechanism = Column(String(20), nullable=True)   # "hard_fail", "soft_fail", "neutral", "open"
    dmarc_pct = Column(Integer, nullable=True)           # 0-100; None means record absent
    mta_sts_mode = Column(String(20), nullable=True)     # "enforce", "testing", "none"
    # NOTE: If email_security table already exists in Postgres, run:
    # ALTER TABLE email_security ADD COLUMN IF NOT EXISTS spf_mechanism VARCHAR(20);
    # ALTER TABLE email_security ADD COLUMN IF NOT EXISTS dmarc_pct INTEGER;
    # ALTER TABLE email_security ADD COLUMN IF NOT EXISTS mta_sts_mode VARCHAR(20);


# ── Cloud Bucket ───────────────────────────────────────

class CloudBucket(Base):
    """Discovered cloud storage bucket."""
    __tablename__ = "cloud_buckets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String(20), nullable=False)   # aws, gcp, azure
    bucket_name = Column(String(255), nullable=False)
    url = Column(String(512), nullable=True)
    is_public = Column(Boolean, default=False)
    permissions = Column(String(50), nullable=True)  # read, write, list
    severity = Column(SQLEnum(Severity), nullable=True)


# ── WHOIS Info ─────────────────────────────────────────

class WhoisInfo(Base):
    """Domain WHOIS registration data."""
    __tablename__ = "whois_info"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True)
    registrar = Column(String(300), nullable=True)
    creation_date = Column(DateTime, nullable=True)
    expiry_date = Column(DateTime, nullable=True)
    updated_date = Column(DateTime, nullable=True)
    registrant_name = Column(String(300), nullable=True)
    registrant_org = Column(String(300), nullable=True)
    registrant_email = Column(String(300), nullable=True)
    registrant_country = Column(String(10), nullable=True)
    name_servers = Column(JSONB, nullable=True)   # List[str]
    status = Column(Text, nullable=True)
    dnssec = Column(String(100), nullable=True)
    error = Column(Text, nullable=True)


# ── ASN Info ───────────────────────────────────────────

class ASNInfo(Base):
    """ASN / IP range record discovered from subdomain IPs."""
    __tablename__ = "asn_info"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    asn = Column(String(20), nullable=False)          # e.g. "13335"
    prefix = Column(String(50), nullable=True)        # e.g. "104.16.0.0/12"
    country = Column(String(10), nullable=True)       # e.g. "US"
    org_name = Column(String(300), nullable=True)     # e.g. "CLOUDFLARENET"
    sample_ip = Column(String(45), nullable=True)     # IP that triggered discovery


# ── HTTP Header Analysis ───────────────────────────────

class HeaderAnalysis(Base):
    """HTTP security header analysis result for a subdomain."""
    __tablename__ = "header_analysis"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subdomain_id = Column(UUID(as_uuid=True), ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False, unique=True)

    # Security header presence & values
    has_hsts = Column(Boolean, nullable=True)
    hsts_value = Column(String(500), nullable=True)
    has_csp = Column(Boolean, nullable=True)
    csp_value = Column(Text, nullable=True)
    has_x_frame_options = Column(Boolean, nullable=True)
    x_frame_options_value = Column(String(100), nullable=True)
    has_x_content_type_options = Column(Boolean, nullable=True)
    has_referrer_policy = Column(Boolean, nullable=True)
    referrer_policy_value = Column(String(200), nullable=True)
    has_permissions_policy = Column(Boolean, nullable=True)

    # Info disclosure headers
    server_banner = Column(String(500), nullable=True)
    x_powered_by = Column(String(200), nullable=True)

    # Redirect info
    redirect_count = Column(Integer, nullable=True)
    final_url = Column(String(512), nullable=True)

    # Security score (0–100) and missing header labels
    security_score = Column(Integer, nullable=True)
    missing_headers = Column(JSONB, nullable=True)   # List[str]

    # Relationship
    subdomain = relationship("Subdomain", back_populates="header_analysis")


# ── Subdomain Takeover ─────────────────────────────────

class SubdomainTakeover(Base):
    """Subdomain takeover vulnerability detection result."""
    __tablename__ = "subdomain_takeovers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subdomain_id = Column(
        UUID(as_uuid=True),
        ForeignKey("subdomains.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    is_vulnerable = Column(Boolean, default=False)
    service = Column(String(100), nullable=True)       # "GitHub Pages", "AWS S3", etc.
    cname_target = Column(String(512), nullable=True)  # dangling CNAME target
    fingerprint = Column(Text, nullable=True)          # matched body pattern
    severity = Column(SQLEnum(Severity), nullable=True)

    # Relationship
    subdomain = relationship("Subdomain", back_populates="takeover")


# ── IP Reputation ───────────────────────────────────────

class IPReputation(Base):
    """IP reputation check result — DNSBL + URLhaus (Feature 32)."""
    __tablename__ = "ip_reputation"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ip_address = Column(String(45), nullable=False)
    hostname = Column(String(512), nullable=True)     # subdomain that resolved to this IP
    is_blacklisted = Column(Boolean, default=False)
    blacklists = Column(JSONB, nullable=True)          # ["Spamhaus ZEN", "URLhaus", ...]
    threat_type = Column(String(100), nullable=True)   # "spam", "malware", "spam/exploit"
    urlhaus_status = Column(String(20), nullable=True) # "listed" / "clean"
    urlhaus_tags = Column(JSONB, nullable=True)        # malware categories from URLhaus
    abuse_score = Column(Integer, nullable=True)       # 0–100


# ── CORS Misconfiguration ──────────────────────────────

class CORSResult(Base):
    """CORS misconfiguration result per subdomain."""
    __tablename__ = "cors_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subdomain_id = Column(
        UUID(as_uuid=True),
        ForeignKey("subdomains.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    hostname = Column(String(512), nullable=True)          # denormalized for display
    is_vulnerable = Column(Boolean, default=False)
    misconfig_type = Column(String(50), nullable=True)     # "arbitrary_origin_reflected", "null_origin"
    allowed_origin = Column(String(200), nullable=True)    # echoed back origin value
    allow_credentials = Column(Boolean, default=False)     # ACAC: true (critical indicator)
    severity = Column(SQLEnum(Severity), nullable=True)


# ── JavaScript Findings ────────────────────────────────

class JSFinding(Base):
    """JS file analysis result — extracted API endpoints + secrets."""
    __tablename__ = "js_findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    subdomain_hostname = Column(String(512), nullable=False)
    js_url = Column(String(1024), nullable=False)
    endpoints = Column(JSONB, nullable=True)    # List[str] — extracted API paths
    secrets = Column(JSONB, nullable=True)       # List[{type, value}] — masked
    endpoint_count = Column(Integer, default=0)
    secret_count = Column(Integer, default=0)


# ── Directory / Path Discovery ─────────────────────────

class DirectoryFinding(Base):
    """Directory/path brute-force discovery result."""
    __tablename__ = "dir_findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    subdomain_hostname = Column(String(512), nullable=False)
    path = Column(String(512), nullable=False)
    status_code = Column(Integer, nullable=False)
    content_length = Column(Integer, nullable=True)
    finding_type = Column(String(50), nullable=True)    # "admin_panel", "git_exposure", etc.
    severity = Column(SQLEnum(Severity), nullable=True)


# ── Wayback Machine Findings ────────────────────────────

class WaybackFinding(Base):
    """Historical URL discovered via Wayback Machine CDX API."""
    __tablename__ = "wayback_findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    url = Column(String(2048), nullable=False)
    status_code = Column(String(10), nullable=True)     # stored as string from CDX
    mime_type = Column(String(100), nullable=True)
    last_seen = Column(String(20), nullable=True)        # "20231205123456" CDX timestamp
    category = Column(String(50), nullable=True)         # "api", "admin", "config", "backup", etc.


# ── DNS Security ────────────────────────────────────────

class DNSSecurity(Base):
    """DNSSEC validation + CAA record analysis per scan."""
    __tablename__ = "dns_security"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    dnssec_enabled = Column(Boolean, default=False)      # DNSKEY record exists
    dnssec_valid = Column(Boolean, default=False)        # AD flag set in resolver response
    has_caa = Column(Boolean, default=False)             # CAA record present
    caa_issuers = Column(JSONB, nullable=True)           # ["letsencrypt.org", ...]
    caa_wildcard_issuers = Column(JSONB, nullable=True)  # issuewild tags
    ns_count = Column(Integer, nullable=True)
    issues = Column(JSONB, nullable=True)                # ["No DNSSEC", "No CAA record", ...]


# ── IP Geolocation ──────────────────────────────────────

class IPGeoLocation(Base):
    """IP geolocation + hosting provider data from ip-api.com (free, no key)."""
    __tablename__ = "ip_geolocation"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ip_address = Column(String(45), nullable=False)
    hostname = Column(String(512), nullable=True)        # associated subdomain
    country = Column(String(100), nullable=True)
    country_code = Column(String(5), nullable=True)      # ISO 3166-1 alpha-2
    region = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)
    isp = Column(String(255), nullable=True)             # Internet Service Provider
    org = Column(String(255), nullable=True)             # Organization / hosting provider
    asn = Column(String(100), nullable=True)             # "AS13335 Amazon.com, Inc."
    is_hosting = Column(Boolean, nullable=True)          # True if datacenter/hosting


# ── Reverse IP Lookup ────────────────────────────────────

class ReverseIPResult(Base):
    """Co-hosted domains discovered via reverse IP lookup (HackerTarget)."""
    __tablename__ = "reverse_ip_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ip_address = Column(String(45), nullable=False)
    co_hosted_domains = Column(JSONB, nullable=True)   # List[str]
    domain_count = Column(Integer, default=0)
    skipped_reason = Column(Text, nullable=True)       # set when IP was skipped (e.g. CDN)
    error = Column(Text, nullable=True)


# ── AlienVault OTX Threat Intel ──────────────────────────

class OTXResult(Base):
    """AlienVault OTX threat intelligence result per scan."""
    __tablename__ = "otx_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    pulse_count = Column(Integer, default=0)
    threat_types = Column(JSONB, nullable=True)       # List[str]
    malware_families = Column(JSONB, nullable=True)   # List[str]
    adversaries = Column(JSONB, nullable=True)         # List[str]
    country = Column(String(100), nullable=True)
    first_seen = Column(String(50), nullable=True)
    alexa_rank = Column(Integer, nullable=True)
    is_known_malicious = Column(Boolean, default=False)
    error = Column(Text, nullable=True)

