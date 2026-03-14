from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from uuid import UUID
from enum import Enum


# ── Enums ──────────────────────────────────────────────

class ScanStatusEnum(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityEnum(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ── Scan ───────────────────────────────────────────────

class ScanCreate(BaseModel):
    """Request body to start a new scan."""
    domain: str = Field(..., min_length=3, max_length=255, examples=["example.com"])


class ScanResponse(BaseModel):
    """Scan summary returned by API."""
    id: UUID
    domain: str
    status: ScanStatusEnum
    risk_score: Optional[float] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    error_message: Optional[str] = None
    subdomain_count: int = 0

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """List of scans."""
    scans: List[ScanResponse]
    total: int


# ── Subdomain ──────────────────────────────────────────

class SubdomainResponse(BaseModel):
    id: UUID
    hostname: str
    ip_address: Optional[str] = None
    is_alive: bool
    http_status: Optional[int] = None
    page_title: Optional[str] = None
    source: Optional[str] = None
    reverse_hostname: Optional[str] = None
    waf_detected: Optional[bool] = None
    waf_name: Optional[str] = None
    ports: List["PortResponse"] = []
    technologies: List["TechnologyResponse"] = []
    header_analysis: Optional["HeaderAnalysisResponse"] = None
    ssl_info: Optional["SSLInfoResponse"] = None

    class Config:
        from_attributes = True


# ── DNS Record ─────────────────────────────────────────

class DNSRecordResponse(BaseModel):
    record_type: str
    hostname: str
    value: str
    ttl: Optional[int] = None

    class Config:
        from_attributes = True


# ── Port ───────────────────────────────────────────────

class PortResponse(BaseModel):
    port_number: int
    protocol: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None

    class Config:
        from_attributes = True


# ── Technology ─────────────────────────────────────────

class TechnologyResponse(BaseModel):
    name: str
    version: Optional[str] = None
    category: Optional[str] = None

    class Config:
        from_attributes = True


# ── Email Security ─────────────────────────────────────

class EmailSecurityResponse(BaseModel):
    spf_record: Optional[str] = None
    spf_valid: Optional[bool] = None
    spf_mechanism: Optional[str] = None
    dkim_found: Optional[bool] = None
    dkim_selector: Optional[str] = None
    dmarc_record: Optional[str] = None
    dmarc_policy: Optional[str] = None
    dmarc_pct: Optional[int] = None
    mta_sts_mode: Optional[str] = None
    is_spoofable: Optional[bool] = None

    class Config:
        from_attributes = True


# ── WHOIS Info ─────────────────────────────────────────

class WhoisInfoResponse(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    registrant_name: Optional[str] = None
    registrant_org: Optional[str] = None
    registrant_email: Optional[str] = None
    registrant_country: Optional[str] = None
    name_servers: Optional[List[str]] = None
    status: Optional[str] = None
    dnssec: Optional[str] = None
    error: Optional[str] = None

    class Config:
        from_attributes = True


# ── ASN Info ───────────────────────────────────────────

class ASNInfoResponse(BaseModel):
    asn: str
    prefix: Optional[str] = None
    country: Optional[str] = None
    org_name: Optional[str] = None
    sample_ip: Optional[str] = None

    class Config:
        from_attributes = True


# ── HTTP Header Analysis ───────────────────────────────

class HeaderAnalysisResponse(BaseModel):
    has_hsts: Optional[bool] = None
    hsts_value: Optional[str] = None
    has_csp: Optional[bool] = None
    csp_value: Optional[str] = None
    has_x_frame_options: Optional[bool] = None
    x_frame_options_value: Optional[str] = None
    has_x_content_type_options: Optional[bool] = None
    has_referrer_policy: Optional[bool] = None
    referrer_policy_value: Optional[str] = None
    has_permissions_policy: Optional[bool] = None
    server_banner: Optional[str] = None
    x_powered_by: Optional[str] = None
    redirect_count: Optional[int] = None
    final_url: Optional[str] = None
    security_score: Optional[int] = None
    missing_headers: Optional[List[str]] = None

    class Config:
        from_attributes = True


# ── SSL / TLS Info ─────────────────────────────────────

class SSLInfoResponse(BaseModel):
    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    is_expired: Optional[bool] = None
    san_domains: Optional[List[str]] = None
    grade: Optional[str] = None
    protocols: Optional[dict] = None       # {"TLS 1.3": True, "TLS 1.2": True, ...}
    vulnerabilities: Optional[dict] = None  # {"BEAST": False, "Weak Protocols": True}

    class Config:
        from_attributes = True


# ── CVE ────────────────────────────────────────────────

class CVEResponse(BaseModel):
    cve_id: str
    severity: Optional[str] = None      # critical / high / medium / low / info
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    technology_name: str
    technology_version: Optional[str] = None

    class Config:
        from_attributes = True


# ── Subdomain Takeover ─────────────────────────────────

class SubdomainTakeoverResponse(BaseModel):
    hostname: str
    is_vulnerable: bool
    service: Optional[str] = None       # "GitHub Pages", "AWS S3", etc.
    cname_target: Optional[str] = None  # dangling CNAME target
    fingerprint: Optional[str] = None   # matched body pattern
    severity: Optional[str] = None      # critical / high / medium / low

    class Config:
        from_attributes = True


# ── IP Reputation ──────────────────────────────────────

class IPReputationResponse(BaseModel):
    ip_address: str
    hostname: Optional[str] = None
    is_blacklisted: bool
    blacklists: Optional[List[str]] = None    # ["Spamhaus ZEN", "URLhaus", ...]
    threat_type: Optional[str] = None         # "spam", "malware", etc.
    urlhaus_status: Optional[str] = None      # "listed" or "clean"
    urlhaus_tags: Optional[List[str]] = None  # malware categories
    abuse_score: Optional[int] = None         # 0–100

    class Config:
        from_attributes = True


# ── CORS Result ────────────────────────────────────────

class CORSResultResponse(BaseModel):
    hostname: str
    is_vulnerable: bool
    misconfig_type: Optional[str] = None    # "arbitrary_origin_reflected", "null_origin"
    allowed_origin: Optional[str] = None
    allow_credentials: bool = False
    severity: Optional[str] = None          # critical / high / medium

    class Config:
        from_attributes = True


# ── JS Finding ─────────────────────────────────────────

class JSFindingResponse(BaseModel):
    subdomain_hostname: str
    js_url: str
    endpoints: Optional[List[str]] = None
    secrets: Optional[List[dict]] = None    # [{type, value}] masked
    endpoint_count: int = 0
    secret_count: int = 0

    class Config:
        from_attributes = True


# ── Directory Finding ──────────────────────────────────

class DirectoryFindingResponse(BaseModel):
    subdomain_hostname: str
    path: str
    status_code: int
    content_length: Optional[int] = None
    finding_type: Optional[str] = None     # "admin_panel", "git_exposure", etc.
    severity: Optional[str] = None         # critical / high / medium / low

    class Config:
        from_attributes = True


# ── WAF Result ─────────────────────────────────────────

class WAFResultResponse(BaseModel):
    subdomain_id: UUID
    detected: bool
    waf_name: Optional[str] = None
    manufacturer: Optional[str] = None

    class Config:
        from_attributes = True


# ── Wayback Finding ─────────────────────────────────────

class WaybackFindingResponse(BaseModel):
    url: str
    status_code: Optional[str] = None
    mime_type: Optional[str] = None
    last_seen: Optional[str] = None
    category: Optional[str] = None

    class Config:
        from_attributes = True


# ── DNS Security ────────────────────────────────────────

class DNSSecurityResponse(BaseModel):
    dnssec_enabled: bool = False
    dnssec_valid: bool = False
    has_caa: bool = False
    caa_issuers: Optional[List[str]] = None
    caa_wildcard_issuers: Optional[List[str]] = None
    ns_count: Optional[int] = None
    issues: Optional[List[str]] = None

    class Config:
        from_attributes = True


# ── IP Geolocation ──────────────────────────────────────

class IPGeoLocationResponse(BaseModel):
    ip_address: str
    hostname: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    is_hosting: Optional[bool] = None

    class Config:
        from_attributes = True


# ── Reverse IP Result ───────────────────────────────────

class ReverseIPEntryResponse(BaseModel):
    ip_address: str
    co_hosted_domains: Optional[List[str]] = None
    domain_count: int = 0
    skipped_reason: Optional[str] = None
    error: Optional[str] = None

    class Config:
        from_attributes = True


# ── OTX Threat Intel ────────────────────────────────────

class OTXResultResponse(BaseModel):
    pulse_count: int = 0
    threat_types: Optional[List[str]] = None
    malware_families: Optional[List[str]] = None
    adversaries: Optional[List[str]] = None
    country: Optional[str] = None
    first_seen: Optional[str] = None
    alexa_rank: Optional[int] = None
    is_known_malicious: bool = False
    error: Optional[str] = None

    class Config:
        from_attributes = True


# ── Scan Detail (full scan with all nested data) ──────

class ScanDetailResponse(BaseModel):
    """Full scan result with all nested data."""
    id: UUID
    domain: str
    status: ScanStatusEnum
    risk_score: Optional[float] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    zone_transfer_successful: Optional[bool] = None
    subdomains: List[SubdomainResponse] = []
    dns_records: List[DNSRecordResponse] = []
    email_security: Optional[EmailSecurityResponse] = None
    whois_info: Optional[WhoisInfoResponse] = None
    asn_info: List[ASNInfoResponse] = []
    cves: List[CVEResponse] = []
    takeovers: List[SubdomainTakeoverResponse] = []
    ip_reputation: List[IPReputationResponse] = []
    cors_results: List[CORSResultResponse] = []
    js_findings: List[JSFindingResponse] = []
    dir_findings: List[DirectoryFindingResponse] = []
    wayback_findings: List[WaybackFindingResponse] = []
    dns_security: Optional[DNSSecurityResponse] = None
    geo_locations: List[IPGeoLocationResponse] = []
    reverse_ip: List[ReverseIPEntryResponse] = []
    otx_result: Optional[OTXResultResponse] = None

    class Config:
        from_attributes = True
