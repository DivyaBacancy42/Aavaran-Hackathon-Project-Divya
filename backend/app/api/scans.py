from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from uuid import UUID
from datetime import datetime

from app.core.database import get_db
from app.models.models import ASNInfo, CVE, CORSResult, DirectoryFinding, DNSRecord, DNSSecurity, EmailSecurity, HeaderAnalysis, IPGeoLocation, IPReputation, JSFinding, OTXResult as OTXResultModel, Port, ReverseIPResult as ReverseIPResultModel, Scan, ScanStatus, SSLInfo, Subdomain, SubdomainTakeover, Technology, WAFResult, WaybackFinding, WhoisInfo
from app.schemas.schemas import ScanCreate, ScanResponse, ScanListResponse, ScanDetailResponse, SubdomainResponse, PortResponse, TechnologyResponse, HeaderAnalysisResponse, SSLInfoResponse, CVEResponse, IPGeoLocationResponse, IPReputationResponse, SubdomainTakeoverResponse, CORSResultResponse, JSFindingResponse, DirectoryFindingResponse, WaybackFindingResponse, DNSSecurityResponse, ReverseIPEntryResponse, OTXResultResponse
from app.services.scan_pipeline import run_scan_pipeline

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("/", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Start a new scan for a domain."""
    # Clean domain input
    domain = scan_data.domain.strip().lower()
    domain = domain.replace("http://", "").replace("https://", "").rstrip("/")

    # Create scan record and commit immediately so the background task can find it
    scan = Scan(domain=domain, status=ScanStatus.PENDING)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Launch scan pipeline as a background task
    background_tasks.add_task(run_scan_pipeline, scan.id)

    return ScanResponse(
        id=scan.id,
        domain=scan.domain,
        status=scan.status,
        created_at=scan.created_at,
        subdomain_count=0,
    )


@router.get("/", response_model=ScanListResponse)
async def list_scans(
    skip: int = 0,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """List all scans, newest first."""
    result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).offset(skip).limit(limit)
    )
    scans = result.scalars().all()

    count_result = await db.execute(select(func.count(Scan.id)))
    total = count_result.scalar()

    scan_responses = []
    for scan in scans:
        sub_count_result = await db.execute(
            select(func.count(Subdomain.id)).where(Subdomain.scan_id == scan.id)
        )
        sub_count = sub_count_result.scalar()

        scan_responses.append(
            ScanResponse(
                id=scan.id,
                domain=scan.domain,
                status=scan.status,
                risk_score=scan.risk_score,
                started_at=scan.started_at,
                completed_at=scan.completed_at,
                created_at=scan.created_at,
                error_message=scan.error_message,
                subdomain_count=sub_count,
            )
        )

    return ScanListResponse(scans=scan_responses, total=total)


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get full scan details with all discovered data."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Load subdomains
    sub_result = await db.execute(
        select(Subdomain).where(Subdomain.scan_id == scan_id)
    )
    subdomains = sub_result.scalars().all()
    subdomain_ids = [s.id for s in subdomains]

    # Load ports keyed by subdomain_id
    ports_by_sub: dict = {}
    if subdomain_ids:
        port_result = await db.execute(
            select(Port).where(Port.subdomain_id.in_(subdomain_ids))
            .order_by(Port.port_number)
        )
        for port in port_result.scalars().all():
            ports_by_sub.setdefault(port.subdomain_id, []).append(port)

    # Load technologies keyed by subdomain_id
    tech_by_sub: dict = {}
    if subdomain_ids:
        tech_result = await db.execute(
            select(Technology).where(Technology.subdomain_id.in_(subdomain_ids))
            .order_by(Technology.name)
        )
        for tech in tech_result.scalars().all():
            tech_by_sub.setdefault(tech.subdomain_id, []).append(tech)

    # Load WAF results keyed by subdomain_id
    waf_by_sub: dict = {}
    if subdomain_ids:
        waf_result = await db.execute(
            select(WAFResult).where(WAFResult.subdomain_id.in_(subdomain_ids))
        )
        for waf in waf_result.scalars().all():
            waf_by_sub[waf.subdomain_id] = waf

    # Load header analysis keyed by subdomain_id
    headers_by_sub: dict = {}
    if subdomain_ids:
        header_result = await db.execute(
            select(HeaderAnalysis).where(HeaderAnalysis.subdomain_id.in_(subdomain_ids))
        )
        for ha in header_result.scalars().all():
            headers_by_sub[ha.subdomain_id] = ha

    # Load SSL info keyed by subdomain_id
    ssl_by_sub: dict = {}
    if subdomain_ids:
        ssl_result = await db.execute(
            select(SSLInfo).where(SSLInfo.subdomain_id.in_(subdomain_ids))
        )
        for si in ssl_result.scalars().all():
            ssl_by_sub[si.subdomain_id] = si

    # Build SubdomainResponse list with nested port/tech/waf/header/ssl data
    subdomain_responses = []
    for sub in subdomains:
        waf = waf_by_sub.get(sub.id)
        ha = headers_by_sub.get(sub.id)
        si = ssl_by_sub.get(sub.id)
        subdomain_responses.append(
            SubdomainResponse(
                id=sub.id,
                hostname=sub.hostname,
                ip_address=sub.ip_address,
                is_alive=sub.is_alive,
                http_status=sub.http_status,
                page_title=sub.page_title,
                source=sub.source,
                reverse_hostname=sub.reverse_hostname,
                waf_detected=waf.detected if waf else None,
                waf_name=waf.waf_name if waf else None,
                ports=[
                    PortResponse(
                        port_number=p.port_number,
                        protocol=p.protocol,
                        service=p.service,
                    )
                    for p in ports_by_sub.get(sub.id, [])
                ],
                technologies=[
                    TechnologyResponse(
                        name=t.name,
                        version=t.version,
                        category=t.category,
                    )
                    for t in tech_by_sub.get(sub.id, [])
                ],
                header_analysis=HeaderAnalysisResponse(
                    has_hsts=ha.has_hsts,
                    hsts_value=ha.hsts_value,
                    has_csp=ha.has_csp,
                    csp_value=ha.csp_value,
                    has_x_frame_options=ha.has_x_frame_options,
                    x_frame_options_value=ha.x_frame_options_value,
                    has_x_content_type_options=ha.has_x_content_type_options,
                    has_referrer_policy=ha.has_referrer_policy,
                    referrer_policy_value=ha.referrer_policy_value,
                    has_permissions_policy=ha.has_permissions_policy,
                    server_banner=ha.server_banner,
                    x_powered_by=ha.x_powered_by,
                    redirect_count=ha.redirect_count,
                    final_url=ha.final_url,
                    security_score=ha.security_score,
                    missing_headers=ha.missing_headers,
                ) if ha else None,
                ssl_info=SSLInfoResponse(
                    issuer=si.issuer,
                    subject=si.subject,
                    valid_from=si.valid_from,
                    valid_until=si.valid_until,
                    is_expired=si.is_expired,
                    san_domains=si.san_domains,
                    grade=si.grade,
                    protocols=si.protocols,
                    vulnerabilities=si.vulnerabilities,
                ) if si else None,
            )
        )

    # Load DNS records
    dns_result = await db.execute(
        select(DNSRecord)
        .where(DNSRecord.scan_id == scan_id)
        .order_by(DNSRecord.record_type, DNSRecord.hostname)
    )
    dns_records = dns_result.scalars().all()

    # Load email security (one row per scan)
    email_result = await db.execute(
        select(EmailSecurity).where(EmailSecurity.scan_id == scan_id)
    )
    email_security = email_result.scalar_one_or_none()

    # Load WHOIS info (one row per scan)
    whois_result = await db.execute(
        select(WhoisInfo).where(WhoisInfo.scan_id == scan_id)
    )
    whois_info = whois_result.scalar_one_or_none()

    # Load ASN records
    asn_result = await db.execute(
        select(ASNInfo).where(ASNInfo.scan_id == scan_id).order_by(ASNInfo.asn)
    )
    asn_info = asn_result.scalars().all()

    # Load technologies for CVE lookup (need tech_id → name/version mapping)
    tech_rows: list = []
    if subdomain_ids:
        tech_result_raw = await db.execute(
            select(Technology).where(Technology.subdomain_id.in_(subdomain_ids))
        )
        tech_rows = tech_result_raw.scalars().all()

    tech_ids = [t.id for t in tech_rows]
    tech_map = {t.id: t for t in tech_rows}

    # Load CVEs grouped by technology
    cves_list: list = []
    if tech_ids:
        cve_result = await db.execute(
            select(CVE).where(CVE.technology_id.in_(tech_ids))
        )
        raw_cves = cve_result.scalars().all()

        # Deduplicate: same CVE ID + same tech name (may appear across multiple subdomains)
        seen_cve_keys: set = set()
        raw_cves_sorted = sorted(raw_cves, key=lambda c: c.cvss_score or 0.0, reverse=True)
        for cve in raw_cves_sorted:
            tech = tech_map.get(cve.technology_id)
            if not tech:
                continue
            key = (cve.cve_id, tech.name.lower())
            if key in seen_cve_keys:
                continue
            seen_cve_keys.add(key)
            cves_list.append(
                CVEResponse(
                    cve_id=cve.cve_id,
                    severity=cve.severity.value if cve.severity else None,
                    cvss_score=cve.cvss_score,
                    description=cve.description,
                    technology_name=tech.name,
                    technology_version=tech.version,
                )
            )

    # Load subdomain takeover results (only vulnerable ones for display)
    takeovers_list: list = []
    if subdomain_ids:
        sub_hostname_map = {s.id: s.hostname for s in subdomains}
        tak_result = await db.execute(
            select(SubdomainTakeover)
            .where(SubdomainTakeover.subdomain_id.in_(subdomain_ids))
            .where(SubdomainTakeover.is_vulnerable == True)
        )
        for tak in tak_result.scalars().all():
            takeovers_list.append(
                SubdomainTakeoverResponse(
                    hostname=sub_hostname_map.get(tak.subdomain_id, "unknown"),
                    is_vulnerable=tak.is_vulnerable,
                    service=tak.service,
                    cname_target=tak.cname_target,
                    fingerprint=tak.fingerprint,
                    severity=tak.severity.value if tak.severity else None,
                )
            )

    # Load CORS results (vulnerable subdomains only)
    cors_list: list = []
    if subdomain_ids:
        cors_result = await db.execute(
            select(CORSResult)
            .where(CORSResult.subdomain_id.in_(subdomain_ids))
            .order_by(CORSResult.severity)
        )
        cors_list = [
            CORSResultResponse(
                hostname=r.hostname or "",
                is_vulnerable=r.is_vulnerable,
                misconfig_type=r.misconfig_type,
                allowed_origin=r.allowed_origin,
                allow_credentials=r.allow_credentials,
                severity=r.severity.value if r.severity else None,
            )
            for r in cors_result.scalars().all()
        ]

    # Load JS findings for this scan
    js_result = await db.execute(
        select(JSFinding)
        .where(JSFinding.scan_id == scan_id)
        .order_by(JSFinding.secret_count.desc(), JSFinding.endpoint_count.desc())
    )
    js_list = [
        JSFindingResponse(
            subdomain_hostname=r.subdomain_hostname,
            js_url=r.js_url,
            endpoints=r.endpoints,
            secrets=r.secrets,
            endpoint_count=r.endpoint_count,
            secret_count=r.secret_count,
        )
        for r in js_result.scalars().all()
    ]

    # Load directory findings for this scan
    dir_result = await db.execute(
        select(DirectoryFinding)
        .where(DirectoryFinding.scan_id == scan_id)
        .order_by(DirectoryFinding.severity, DirectoryFinding.subdomain_hostname)
    )
    _SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    dir_rows = dir_result.scalars().all()
    dir_rows_sorted = sorted(
        dir_rows,
        key=lambda r: _SEVERITY_ORDER.get(r.severity.value if r.severity else "low", 4),
    )
    dir_list = [
        DirectoryFindingResponse(
            subdomain_hostname=r.subdomain_hostname,
            path=r.path,
            status_code=r.status_code,
            content_length=r.content_length,
            finding_type=r.finding_type,
            severity=r.severity.value if r.severity else None,
        )
        for r in dir_rows_sorted
    ]

    # Load IP reputation results for this scan
    rep_result = await db.execute(
        select(IPReputation)
        .where(IPReputation.scan_id == scan_id)
        .order_by(IPReputation.is_blacklisted.desc(), IPReputation.abuse_score.desc())
    )
    ip_reputation_list = [
        IPReputationResponse(
            ip_address=r.ip_address,
            hostname=r.hostname,
            is_blacklisted=r.is_blacklisted,
            blacklists=r.blacklists,
            threat_type=r.threat_type,
            urlhaus_status=r.urlhaus_status,
            urlhaus_tags=r.urlhaus_tags,
            abuse_score=r.abuse_score,
        )
        for r in rep_result.scalars().all()
    ]

    # Load wayback findings for this scan
    wayback_result = await db.execute(
        select(WaybackFinding)
        .where(WaybackFinding.scan_id == scan_id)
        .order_by(WaybackFinding.category, WaybackFinding.url)
    )
    wayback_list = [
        WaybackFindingResponse(
            url=r.url,
            status_code=r.status_code,
            mime_type=r.mime_type,
            last_seen=r.last_seen,
            category=r.category,
        )
        for r in wayback_result.scalars().all()
    ]

    # Load DNS security result for this scan
    dns_sec_result = await db.execute(
        select(DNSSecurity).where(DNSSecurity.scan_id == scan_id)
    )
    dns_sec_row = dns_sec_result.scalar_one_or_none()
    dns_security = (
        DNSSecurityResponse(
            dnssec_enabled=dns_sec_row.dnssec_enabled,
            dnssec_valid=dns_sec_row.dnssec_valid,
            has_caa=dns_sec_row.has_caa,
            caa_issuers=dns_sec_row.caa_issuers,
            caa_wildcard_issuers=dns_sec_row.caa_wildcard_issuers,
            ns_count=dns_sec_row.ns_count,
            issues=dns_sec_row.issues,
        )
        if dns_sec_row
        else None
    )

    # Load reverse IP results for this scan
    rev_ip_result = await db.execute(
        select(ReverseIPResultModel)
        .where(ReverseIPResultModel.scan_id == scan_id)
        .order_by(ReverseIPResultModel.domain_count.desc())
    )
    reverse_ip_list = [
        ReverseIPEntryResponse(
            ip_address=r.ip_address,
            co_hosted_domains=r.co_hosted_domains,
            domain_count=r.domain_count,
            skipped_reason=r.skipped_reason,
            error=r.error,
        )
        for r in rev_ip_result.scalars().all()
    ]

    # Load OTX threat intel result for this scan
    otx_result_row = await db.execute(
        select(OTXResultModel).where(OTXResultModel.scan_id == scan_id)
    )
    otx_row = otx_result_row.scalar_one_or_none()
    otx_result = (
        OTXResultResponse(
            pulse_count=otx_row.pulse_count,
            threat_types=otx_row.threat_types,
            malware_families=otx_row.malware_families,
            adversaries=otx_row.adversaries,
            country=otx_row.country,
            first_seen=otx_row.first_seen,
            alexa_rank=otx_row.alexa_rank,
            is_known_malicious=otx_row.is_known_malicious,
            error=otx_row.error,
        )
        if otx_row
        else None
    )

    # Load IP geolocation results for this scan
    geo_result = await db.execute(
        select(IPGeoLocation)
        .where(IPGeoLocation.scan_id == scan_id)
        .order_by(IPGeoLocation.country, IPGeoLocation.ip_address)
    )
    geo_list = [
        IPGeoLocationResponse(
            ip_address=r.ip_address,
            hostname=r.hostname,
            country=r.country,
            country_code=r.country_code,
            region=r.region,
            city=r.city,
            isp=r.isp,
            org=r.org,
            asn=r.asn,
            is_hosting=r.is_hosting,
        )
        for r in geo_result.scalars().all()
    ]

    return ScanDetailResponse(
        id=scan.id,
        domain=scan.domain,
        status=scan.status,
        risk_score=scan.risk_score,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        created_at=scan.created_at,
        zone_transfer_successful=scan.zone_transfer_successful,
        subdomains=subdomain_responses,
        dns_records=dns_records,
        email_security=email_security,
        whois_info=whois_info,
        asn_info=asn_info,
        cves=cves_list,
        takeovers=takeovers_list,
        ip_reputation=ip_reputation_list,
        cors_results=cors_list,
        js_findings=js_list,
        dir_findings=dir_list,
        wayback_findings=wayback_list,
        dns_security=dns_security,
        geo_locations=geo_list,
        reverse_ip=reverse_ip_list,
        otx_result=otx_result,
    )


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Delete a scan and all its data."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    await db.delete(scan)
