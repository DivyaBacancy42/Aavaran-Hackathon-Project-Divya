import asyncio
import logging
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import async_session
from app.models.models import ASNInfo, CVE, CORSResult, DirectoryFinding, DNSRecord, DNSSecurity, EmailSecurity, HeaderAnalysis, IPGeoLocation, IPReputation, JSFinding, OTXResult as OTXResultModel, Port, ReverseIPResult as ReverseIPResultModel, Scan, ScanStatus, Severity, SSLInfo, Subdomain, SubdomainTakeover, Technology, WAFResult, WaybackFinding, WhoisInfo
from app.scanners.alive_scanner import AliveScanner
from app.scanners.asn_scanner import ASNScanner
from app.scanners.cve_scanner import CVEScanner
from app.scanners.dns_scanner import DNSScanner
from app.scanners.email_scanner import EmailScanner
from app.scanners.header_scanner import HeaderScanner
from app.scanners.port_scanner import PortScanner
from app.scanners.cors_scanner import CORSScanner
from app.scanners.dir_scanner import DirScanner
from app.scanners.js_scanner import JSScanner
from app.scanners.reputation_scanner import ReputationScanner
from app.scanners.reverse_dns_scanner import ReverseDNSScanner
from app.scanners.subdomain_scanner import SubdomainScanner
from app.scanners.osv_scanner import OSVScanner
from app.scanners.takeover_scanner import TakeoverScanner
from app.scanners.tech_scanner import TechScanner
from app.scanners.ssl_scanner import SSLScanner
from app.scanners.waf_scanner import WAFScanner
from app.scanners.whois_scanner import WhoisScanner
from app.scanners.wayback_scanner import WaybackScanner
from app.scanners.dns_security_scanner import DNSSecurityScanner
from app.scanners.geo_scanner import GeoScanner
from app.scanners.reverse_ip_scanner import ReverseIPScanner
from app.scanners.otx_scanner import OTXScanner

logger = logging.getLogger(__name__)


# ── Apex-domain helper ────────────────────────────────────────────────────────

# 2-level TLDs that require 3 parts to form the registrable domain
_TWO_PART_TLDS = {
    "co.uk", "org.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "school.nz",
    "co.in", "net.in", "org.in", "firm.in", "gen.in",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "ad.jp", "ed.jp", "go.jp",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "co.za", "org.za", "net.za", "gov.za", "edu.za",
    "com.mx", "net.mx", "org.mx", "gob.mx",
    "com.ar", "net.ar", "org.ar", "gov.ar",
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg",
    "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk",
    "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw",
}


def _apex_domain(domain: str) -> str:
    """Extract the registrable apex domain from any domain or subdomain.

    Examples:
      uatfrontend.doctusmind.com  -> doctusmind.com
      abc.xyz.ded.com             -> ded.com
      sub.example.co.uk           -> example.co.uk
      example.co.uk               -> example.co.uk
      doctusmind.com              -> doctusmind.com (unchanged)
    """
    parts = domain.rstrip(".").split(".")
    if len(parts) <= 2:
        return domain  # already apex or bare TLD

    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in _TWO_PART_TLDS:
        return ".".join(parts[-3:]) if len(parts) >= 3 else domain

    # Default: last 2 parts
    return ".".join(parts[-2:])


async def run_scan_pipeline(scan_id: UUID) -> None:
    """
    Main scan orchestrator. Runs all scanner modules in sequence.
    Each module is isolated — a failure in one does NOT stop the others.
    """
    async with async_session() as db:
        try:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                logger.error(f"Pipeline: scan {scan_id} not found in DB")
                return

            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            await db.commit()

            # ── Scanner modules — add new ones here ───────────────────────
            await _run_dns_scanner(db, scan)
            await _run_subdomain_scanner(db, scan)
            await _ensure_self_as_subdomain(db, scan)   # always scan the input itself
            await _run_alive_scanner(db, scan)
            await _run_reverse_dns_scanner(db, scan)
            await _run_asn_scanner(db, scan)
            await _run_whois_scanner(db, scan)
            await _run_email_scanner(db, scan)
            await _run_port_scanner(db, scan)
            await _run_tech_scanner(db, scan)
            await _run_waf_scanner(db, scan)
            await _run_header_scanner(db, scan)
            await _run_ssl_scanner(db, scan)
            await _run_takeover_scanner(db, scan)
            # NVD CVEScanner disabled — OSV.dev is the primary CVE source.
            # NVD keywordSearch is too loose, has no version-range filtering,
            # and rate-limits unauthenticated callers to 5 req/30s.
            # await _run_cve_scanner(db, scan)
            await _run_osv_scanner(db, scan)
            await _run_cors_scanner(db, scan)
            await _run_js_scanner(db, scan)
            await _run_dir_scanner(db, scan)
            await _run_reputation_scanner(db, scan)
            await _run_wayback_scanner(db, scan)
            await _run_dns_security_scanner(db, scan)
            await _run_geo_scanner(db, scan)
            await _run_reverse_ip_scanner(db, scan)
            await _run_otx_scanner(db, scan)
            await _run_risk_scorer(db, scan)      # always last — reads all findings
            # ─────────────────────────────────────────────────────────────

            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            await db.commit()

            logger.info(f"Pipeline complete for {scan.domain} (scan_id={scan_id})")

        except Exception as e:
            logger.exception(f"Pipeline crashed for scan_id={scan_id}: {e}")
            # Open a fresh session to mark the scan as failed
            async with async_session() as db2:
                result = await db2.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalar_one_or_none()
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = str(e)
                    await db2.commit()


async def _ensure_self_as_subdomain(db: AsyncSession, scan: Scan) -> None:
    """Guarantee the input domain/subdomain is always in the subdomains table.

    When the user enters a subdomain (e.g. uatfrontend.doctusmind.com) the
    subdomain scanner finds zero further subdomains.  Without this step every
    subsequent scanner that filters is_alive==True would have no targets and
    the scan would silently produce no results.

    This runs after _run_subdomain_scanner so it doesn't duplicate an entry
    that was already discovered naturally.
    """
    try:
        existing = await db.execute(
            select(Subdomain).where(
                Subdomain.scan_id == scan.id,
                Subdomain.hostname == scan.domain,
            )
        )
        if existing.scalar_one_or_none() is None:
            db.add(Subdomain(
                scan_id=scan.id,
                hostname=scan.domain,
                source="input",
            ))
            await db.commit()
            logger.info(
                f"_ensure_self_as_subdomain: added {scan.domain} as direct scan target"
            )
    except Exception as e:
        logger.error(f"_ensure_self_as_subdomain failed for {scan.domain}: {e}")


async def _run_dns_scanner(db: AsyncSession, scan: Scan) -> None:
    """Run DNS record extraction + zone transfer check, save results to DB.

    Zone transfer and authoritative NS records exist on the apex domain.
    When input is a subdomain we query the apex so DNS data is complete.
    """
    try:
        apex = _apex_domain(scan.domain)
        if apex != scan.domain:
            logger.info(f"_run_dns_scanner: using apex domain {apex} for {scan.domain}")
        scanner = DNSScanner(apex)
        result = await scanner.run()

        for rec in result.records:
            db.add(
                DNSRecord(
                    scan_id=scan.id,
                    record_type=rec.record_type,
                    hostname=rec.hostname,
                    value=rec.value,
                    ttl=rec.ttl,
                )
            )

        scan.zone_transfer_successful = result.zone_transfer_successful
        await db.commit()

        logger.info(
            f"_run_dns_scanner: saved {len(result.records)} records for {scan.domain}"
        )
    except Exception as e:
        logger.error(f"_run_dns_scanner failed for {scan.domain}: {e}")
        await db.rollback()
        # Do NOT re-raise — pipeline continues to next scanner


async def _run_subdomain_scanner(db: AsyncSession, scan: Scan) -> None:
    """Discover subdomains via crt.sh + DNS brute force and save results to DB."""
    try:
        scanner = SubdomainScanner(scan.domain)
        result = await scanner.run()

        for sub in result.subdomains:
            db.add(
                Subdomain(
                    scan_id=scan.id,
                    hostname=sub.hostname,
                    source=sub.source,
                    ip_address=sub.ip_address,
                )
            )

        await db.commit()

        logger.info(
            f"_run_subdomain_scanner: saved {len(result.subdomains)} subdomains "
            f"for {scan.domain} "
            f"(crt.sh={result.crtsh_count}, dns-brute={result.brute_count})"
        )
    except Exception as e:
        logger.error(f"_run_subdomain_scanner failed for {scan.domain}: {e}")
        await db.rollback()
        # Do NOT re-raise — pipeline continues to next scanner


async def _run_alive_scanner(db: AsyncSession, scan: Scan) -> None:
    """HTTP-probe every discovered subdomain; update is_alive, http_status, page_title."""
    try:
        result = await db.execute(
            select(Subdomain).where(Subdomain.scan_id == scan.id)
        )
        subdomains = result.scalars().all()

        if not subdomains:
            logger.info(f"_run_alive_scanner: no subdomains to probe for {scan.domain}")
            return

        hostnames = [s.hostname for s in subdomains]
        scanner = AliveScanner(hostnames)
        alive_results = await scanner.run()

        result_map = {r.hostname: r for r in alive_results}
        for sub in subdomains:
            r = result_map.get(sub.hostname)
            if r:
                sub.is_alive = r.is_alive
                sub.http_status = r.http_status
                sub.page_title = r.page_title

        await db.commit()

        alive_count = sum(1 for r in alive_results if r.is_alive)
        logger.info(
            f"_run_alive_scanner: {alive_count}/{len(hostnames)} alive "
            f"for {scan.domain}"
        )
    except Exception as e:
        logger.error(f"_run_alive_scanner failed for {scan.domain}: {e}")
        await db.rollback()
        # Do NOT re-raise — pipeline continues to next scanner


async def _run_reverse_dns_scanner(db: AsyncSession, scan: Scan) -> None:
    """PTR lookup for each discovered subdomain IP; updates reverse_hostname column."""
    try:
        result = await db.execute(
            select(Subdomain).where(Subdomain.scan_id == scan.id)
        )
        subdomains = result.scalars().all()

        ip_addresses = [s.ip_address for s in subdomains if s.ip_address]
        if not ip_addresses:
            logger.info(f"_run_reverse_dns_scanner: no IPs to look up for {scan.domain}")
            return

        scanner = ReverseDNSScanner(ip_addresses)
        reverse_result = await scanner.run()

        for sub in subdomains:
            if sub.ip_address and sub.ip_address in reverse_result.ptr_map:
                sub.reverse_hostname = reverse_result.ptr_map[sub.ip_address]

        await db.commit()
        logger.info(
            f"_run_reverse_dns_scanner: resolved {len(reverse_result.ptr_map)} PTR records "
            f"for {scan.domain}"
        )
    except Exception as e:
        logger.error(f"_run_reverse_dns_scanner failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_asn_scanner(db: AsyncSession, scan: Scan) -> None:
    """ASN/IP range discovery via Team Cymru DNS for each unique subdomain IP."""
    try:
        result = await db.execute(
            select(Subdomain).where(Subdomain.scan_id == scan.id)
        )
        subdomains = result.scalars().all()

        ip_addresses = [s.ip_address for s in subdomains if s.ip_address]
        if not ip_addresses:
            logger.info(f"_run_asn_scanner: no IPs for {scan.domain}")
            return

        scanner = ASNScanner(ip_addresses)
        asn_result = await scanner.run()

        for asn_data in asn_result.asn_records:
            db.add(
                ASNInfo(
                    scan_id=scan.id,
                    asn=asn_data.asn,
                    prefix=asn_data.prefix,
                    country=asn_data.country,
                    org_name=asn_data.org_name,
                    sample_ip=asn_data.sample_ip,
                )
            )

        await db.commit()
        logger.info(
            f"_run_asn_scanner: saved {len(asn_result.asn_records)} ASN records "
            f"for {scan.domain}"
        )
    except Exception as e:
        logger.error(f"_run_asn_scanner failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_whois_scanner(db: AsyncSession, scan: Scan) -> None:
    """WHOIS lookup for the scanned domain.

    Always queries the apex/registrable domain — WHOIS servers do not return
    data for sub-domain lookups.  e.g. uatfrontend.doctusmind.com → doctusmind.com
    """
    try:
        apex = _apex_domain(scan.domain)
        if apex != scan.domain:
            logger.info(f"_run_whois_scanner: using apex domain {apex} for {scan.domain}")
        scanner = WhoisScanner(apex)
        result = await scanner.run()

        db.add(
            WhoisInfo(
                scan_id=scan.id,
                registrar=result.registrar,
                creation_date=result.creation_date,
                expiry_date=result.expiry_date,
                updated_date=result.updated_date,
                registrant_name=result.registrant_name,
                registrant_org=result.registrant_org,
                registrant_email=result.registrant_email,
                registrant_country=result.registrant_country,
                name_servers=result.name_servers or [],
                status=result.status,
                dnssec=result.dnssec,
                error=result.error,
            )
        )
        await db.commit()
        logger.info(
            f"_run_whois_scanner: done for {scan.domain} "
            f"(registrar={result.registrar})"
        )
    except Exception as e:
        logger.error(f"_run_whois_scanner failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_email_scanner(db: AsyncSession, scan: Scan) -> None:
    """Check SPF, DKIM, DMARC and compute email spoofing verdict.

    SPF/DMARC/DKIM records live on the apex/registrable domain, not on
    subdomains.  Always query the apex. e.g. sub.example.com → example.com
    """
    try:
        apex = _apex_domain(scan.domain)
        if apex != scan.domain:
            logger.info(f"_run_email_scanner: using apex domain {apex} for {scan.domain}")
        scanner = EmailScanner(apex)
        result = await scanner.run()

        db.add(
            EmailSecurity(
                scan_id=scan.id,
                spf_record=result.spf_record,
                spf_valid=result.spf_valid,
                spf_mechanism=result.spf_mechanism,
                dkim_found=result.dkim_found,
                dkim_selector=result.dkim_selector,
                dmarc_record=result.dmarc_record,
                dmarc_policy=result.dmarc_policy,
                dmarc_pct=result.dmarc_pct,
                mta_sts_mode=result.mta_sts_mode,
                is_spoofable=result.is_spoofable,
            )
        )
        await db.commit()

        logger.info(
            f"_run_email_scanner: done for {scan.domain} "
            f"(spoofable={result.is_spoofable})"
        )
    except Exception as e:
        logger.error(f"_run_email_scanner failed for {scan.domain}: {e}")
        await db.rollback()
        # Do NOT re-raise — pipeline continues to next scanner


async def _run_port_scanner(db: AsyncSession, scan: Scan) -> None:
    """TCP connect scan on common ports for each alive subdomain."""
    try:
        result = await db.execute(
            select(Subdomain).where(Subdomain.scan_id == scan.id, Subdomain.is_alive == True)
        )
        subdomains = result.scalars().all()

        if not subdomains:
            logger.info(f"_run_port_scanner: no alive subdomains for {scan.domain}")
            return

        hostnames = [s.hostname for s in subdomains]
        scanner = PortScanner(hostnames)
        port_result = await scanner.run()

        # Map hostname → subdomain ORM object for fast lookup
        sub_map = {s.hostname: s for s in subdomains}
        for op in port_result.open_ports:
            sub = sub_map.get(op.hostname)
            if sub:
                db.add(
                    Port(
                        subdomain_id=sub.id,
                        port_number=op.port_number,
                        protocol=op.protocol,
                        service=op.service or None,
                        banner=op.banner,
                        version=op.version,
                    )
                )

        await db.commit()
        logger.info(
            f"_run_port_scanner: saved {len(port_result.open_ports)} open ports "
            f"for {scan.domain}"
        )
    except Exception as e:
        logger.error(f"_run_port_scanner failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_tech_scanner(db: AsyncSession, scan: Scan) -> None:
    """Detect web technologies from HTTP headers and HTML for alive subdomains."""
    try:
        result = await db.execute(
            select(Subdomain).where(Subdomain.scan_id == scan.id, Subdomain.is_alive == True)
        )
        subdomains = result.scalars().all()

        if not subdomains:
            logger.info(f"_run_tech_scanner: no alive subdomains for {scan.domain}")
            return

        hostnames = [s.hostname for s in subdomains]
        scanner = TechScanner(hostnames)
        tech_result = await scanner.run()

        sub_map = {s.hostname: s for s in subdomains}
        for tech in tech_result.technologies:
            sub = sub_map.get(tech.hostname)
            if sub:
                db.add(
                    Technology(
                        subdomain_id=sub.id,
                        name=tech.name,
                        version=tech.version,
                        category=tech.category or None,
                    )
                )

        await db.commit()
        logger.info(
            f"_run_tech_scanner: saved {len(tech_result.technologies)} tech detections "
            f"for {scan.domain}"
        )
    except Exception as e:
        logger.error(f"_run_tech_scanner failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_waf_scanner(db: AsyncSession, scan: Scan) -> None:
    """WAF/CDN detection via wafw00f for each alive subdomain."""
    try:
        result = await db.execute(
            select(Subdomain).where(Subdomain.scan_id == scan.id, Subdomain.is_alive == True)
        )
        subdomains = result.scalars().all()

        if not subdomains:
            logger.info(f"_run_waf_scanner: no alive subdomains for {scan.domain}")
            return

        sem = asyncio.Semaphore(5)  # wafw00f is slow; limit concurrency

        async def detect(sub: Subdomain):
            async with sem:
                scanner = WAFScanner(sub.hostname)
                waf_result = await scanner.run()
                db.add(
                    WAFResult(
                        subdomain_id=sub.id,
                        detected=waf_result.detected,
                        waf_name=waf_result.waf_name,
                        manufacturer=waf_result.manufacturer,
                    )
                )

        await asyncio.gather(*[detect(s) for s in subdomains], return_exceptions=True)
        await db.commit()

        logger.info(
            f"_run_waf_scanner: checked {len(subdomains)} subdomains for {scan.domain}"
        )
    except Exception as e:
        logger.error(f"_run_waf_scanner failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_header_scanner(db: AsyncSession, scan: Scan) -> None:
    """Analyze HTTP security headers for each alive subdomain."""
    try:
        result = await db.execute(
            select(Subdomain).where(Subdomain.scan_id == scan.id, Subdomain.is_alive == True)
        )
        subdomains = result.scalars().all()

        if not subdomains:
            logger.info(f"_run_header_scanner: no alive subdomains for {scan.domain}")
            return

        hostnames = [s.hostname for s in subdomains]
        scanner = HeaderScanner(hostnames)
        header_results = await scanner.run()

        result_map = {r.hostname: r for r in header_results}
        saved = 0
        for sub in subdomains:
            r = result_map.get(sub.hostname)
            if not r or r.error:
                continue
            db.add(
                HeaderAnalysis(
                    subdomain_id=sub.id,
                    has_hsts=r.has_hsts,
                    hsts_value=r.hsts_value,
                    has_csp=r.has_csp,
                    csp_value=r.csp_value,
                    has_x_frame_options=r.has_x_frame_options,
                    x_frame_options_value=r.x_frame_options_value,
                    has_x_content_type_options=r.has_x_content_type_options,
                    has_referrer_policy=r.has_referrer_policy,
                    referrer_policy_value=r.referrer_policy_value,
                    has_permissions_policy=r.has_permissions_policy,
                    server_banner=r.server_banner,
                    x_powered_by=r.x_powered_by,
                    redirect_count=r.redirect_count,
                    final_url=r.final_url,
                    security_score=r.security_score,
                    missing_headers=r.missing_headers or [],
                )
            )
            saved += 1

        await db.commit()
        logger.info(
            f"_run_header_scanner: saved {saved} header analyses for {scan.domain}"
        )
    except Exception as e:
        logger.error(f"_run_header_scanner failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_ssl_scanner(db: AsyncSession, scan: Scan) -> None:
    """SSL/TLS certificate analysis + protocol grading for each alive subdomain."""
    try:
        result = await db.execute(
            select(Subdomain).where(Subdomain.scan_id == scan.id, Subdomain.is_alive == True)
        )
        subdomains = result.scalars().all()

        if not subdomains:
            logger.info(f"_run_ssl_scanner: no alive subdomains for {scan.domain}")
            return

        hostnames = [s.hostname for s in subdomains]
        scanner = SSLScanner(hostnames)
        ssl_results = await scanner.run()

        result_map = {r.hostname: r for r in ssl_results}
        saved = 0
        for sub in subdomains:
            r = result_map.get(sub.hostname)
            if not r or r.error:
                continue
            db.add(
                SSLInfo(
                    subdomain_id=sub.id,
                    issuer=r.issuer,
                    subject=r.subject,
                    valid_from=r.valid_from.replace(tzinfo=None) if r.valid_from else None,
                    valid_until=r.valid_until.replace(tzinfo=None) if r.valid_until else None,
                    is_expired=r.is_expired,
                    san_domains=r.san_domains or [],
                    grade=r.grade,
                    protocols=r.protocols or {},
                    vulnerabilities=r.vulnerabilities or {},
                )
            )
            saved += 1

        await db.commit()
        logger.info(
            f"_run_ssl_scanner: saved {saved} SSL analyses for {scan.domain}"
        )
    except Exception as e:
        logger.error(f"_run_ssl_scanner failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_takeover_scanner(db: AsyncSession, scan: Scan) -> None:
    """Check alive subdomains for dangling CNAME / subdomain takeover risk."""
    try:
        result = await db.execute(
            select(Subdomain).where(Subdomain.scan_id == scan.id, Subdomain.is_alive == True)
        )
        subdomains = result.scalars().all()

        if not subdomains:
            logger.info(f"_run_takeover_scanner: no alive subdomains for {scan.domain}")
            return

        hostnames = [s.hostname for s in subdomains]
        scanner = TakeoverScanner(hostnames)
        takeover_results = await scanner.run()

        result_map = {r.hostname: r for r in takeover_results}
        saved = 0
        for sub in subdomains:
            r = result_map.get(sub.hostname)
            if not r:
                continue
            db.add(
                SubdomainTakeover(
                    subdomain_id=sub.id,
                    is_vulnerable=r.is_vulnerable,
                    service=r.service,
                    cname_target=r.cname_target,
                    fingerprint=r.fingerprint,
                    severity=Severity(r.severity) if r.severity else None,
                )
            )
            saved += 1

        await db.commit()
        vulnerable = sum(1 for r in takeover_results if r.is_vulnerable)
        logger.info(
            f"_run_takeover_scanner: checked {saved} subdomains, "
            f"{vulnerable} potentially vulnerable for {scan.domain}"
        )
    except Exception as e:
        logger.error(f"_run_takeover_scanner failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_cve_scanner(db: AsyncSession, scan: Scan) -> None:
    """Look up CVEs for each detected technology version using the NVD API."""
    try:
        # Load all technologies for subdomains in this scan
        result = await db.execute(
            select(Technology)
            .join(Subdomain, Technology.subdomain_id == Subdomain.id)
            .where(Subdomain.scan_id == scan.id)
        )
        all_techs = result.scalars().all()

        if not all_techs:
            logger.info(f"_run_cve_scanner: no technologies for {scan.domain}")
            return

        # Feed (name, version) pairs to the scanner (dedup happens inside)
        pairs = [(t.name, t.version) for t in all_techs]
        scanner = CVEScanner(pairs)
        cve_map = await scanner.run()  # {(name_lower, version_lower): [CVEResult]}

        saved = 0
        for tech in all_techs:
            if not tech.version:
                continue
            key = (tech.name.lower(), tech.version.lower())
            cves = cve_map.get(key, [])
            for cve in cves:
                db.add(
                    CVE(
                        technology_id=tech.id,
                        cve_id=cve.cve_id,
                        severity=Severity(cve.severity) if cve.severity else None,
                        cvss_score=cve.cvss_score,
                        description=cve.description,
                    )
                )
                saved += 1

        await db.commit()
        logger.info(f"_run_cve_scanner: saved {saved} CVEs for {scan.domain}")
    except Exception as e:
        logger.error(f"_run_cve_scanner failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_osv_scanner(db: AsyncSession, scan: Scan) -> None:
    """Query OSV.dev for package-level vulnerabilities in detected technologies.

    Queries by version — version-less lookups return hundreds of old CVEs
    across all releases, producing inconsistent and irrelevant results.
    Results are stored in the same `cves` table as NVD CVEs.
    """
    try:
        result = await db.execute(
            select(Technology)
            .join(Subdomain, Technology.subdomain_id == Subdomain.id)
            .where(Subdomain.scan_id == scan.id)
        )
        all_techs = result.scalars().all()

        if not all_techs:
            logger.info(f"_run_osv_scanner: no technologies for {scan.domain}")
            return

        pairs = [(t.name, t.version) for t in all_techs]
        scanner = OSVScanner(pairs)
        osv_result = await scanner.run()

        if not osv_result.by_tech:
            logger.info(f"_run_osv_scanner: no OSV-mapped technologies for {scan.domain}")
            return

        # Collect already-saved CVE IDs for this scan to avoid duplicates
        existing_cve_ids: set = set()
        tech_ids = [t.id for t in all_techs]
        if tech_ids:
            ex_result = await db.execute(
                select(CVE.cve_id).where(CVE.technology_id.in_(tech_ids))
            )
            existing_cve_ids = {row[0] for row in ex_result.fetchall()}

        saved = 0
        for tech in all_techs:
            vulns = osv_result.by_tech.get(tech.name.lower(), [])
            for vuln in vulns:
                if vuln.vuln_id in existing_cve_ids:
                    continue  # already saved by NVD scanner
                db.add(CVE(
                    technology_id=tech.id,
                    cve_id=vuln.vuln_id,
                    severity=Severity(vuln.severity) if vuln.severity else None,
                    cvss_score=vuln.cvss_score,
                    description=vuln.summary,
                ))
                existing_cve_ids.add(vuln.vuln_id)
                saved += 1

        await db.commit()
        logger.info(f"_run_osv_scanner: saved {saved} OSV vulns for {scan.domain}")
    except Exception as e:
        logger.error(f"_run_osv_scanner failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_cors_scanner(db: AsyncSession, scan: Scan) -> None:
    """Check alive subdomains for CORS misconfigurations."""
    try:
        result = await db.execute(
            select(Subdomain).where(Subdomain.scan_id == scan.id, Subdomain.is_alive == True)
        )
        subdomains = result.scalars().all()

        if not subdomains:
            logger.info(f"_run_cors_scanner: no alive subdomains for {scan.domain}")
            return

        hostnames = [s.hostname for s in subdomains]
        scanner = CORSScanner(hostnames)
        cors_results = await scanner.run()

        sub_map = {s.hostname: s for s in subdomains}
        saved = 0
        for r in cors_results:
            sub = sub_map.get(r.hostname)
            if not sub:
                continue
            db.add(CORSResult(
                subdomain_id=sub.id,
                hostname=r.hostname,
                is_vulnerable=r.is_vulnerable,
                misconfig_type=r.misconfig_type,
                allowed_origin=r.allowed_origin,
                allow_credentials=r.allow_credentials,
                severity=Severity(r.severity) if r.severity else None,
            ))
            saved += 1

        await db.commit()
        logger.info(
            f"_run_cors_scanner: {saved} CORS vulnerabilities found for {scan.domain}"
        )
    except Exception as e:
        logger.error(f"_run_cors_scanner failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_js_scanner(db: AsyncSession, scan: Scan) -> None:
    """Analyze JS files for API endpoints and secrets."""
    try:
        result = await db.execute(
            select(Subdomain).where(Subdomain.scan_id == scan.id, Subdomain.is_alive == True)
        )
        subdomains = result.scalars().all()

        if not subdomains:
            logger.info(f"_run_js_scanner: no alive subdomains for {scan.domain}")
            return

        hostnames = [s.hostname for s in subdomains]
        scanner = JSScanner(hostnames)
        js_results = await scanner.run()

        saved = 0
        for r in js_results:
            db.add(JSFinding(
                scan_id=scan.id,
                subdomain_hostname=r.hostname,
                js_url=r.js_url,
                endpoints=r.endpoints or None,
                secrets=r.secrets or None,
                endpoint_count=r.endpoint_count,
                secret_count=r.secret_count,
            ))
            saved += 1

        await db.commit()
        logger.info(
            f"_run_js_scanner: saved {saved} JS findings for {scan.domain}"
        )
    except Exception as e:
        logger.error(f"_run_js_scanner failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_dir_scanner(db: AsyncSession, scan: Scan) -> None:
    """Brute-force common paths on alive subdomains."""
    try:
        result = await db.execute(
            select(Subdomain).where(Subdomain.scan_id == scan.id, Subdomain.is_alive == True)
        )
        subdomains = result.scalars().all()

        if not subdomains:
            logger.info(f"_run_dir_scanner: no alive subdomains for {scan.domain}")
            return

        hostnames = [s.hostname for s in subdomains]
        scanner = DirScanner(hostnames)
        dir_results = await scanner.run()

        saved = 0
        for r in dir_results:
            db.add(DirectoryFinding(
                scan_id=scan.id,
                subdomain_hostname=r.subdomain_hostname,
                path=r.path,
                status_code=r.status_code,
                content_length=r.content_length,
                finding_type=r.finding_type,
                severity=Severity(r.severity) if r.severity else None,
            ))
            saved += 1

        await db.commit()
        critical = sum(1 for r in dir_results if r.severity == "critical")
        logger.info(
            f"_run_dir_scanner: saved {saved} path findings "
            f"({critical} critical) for {scan.domain}"
        )
    except Exception as e:
        logger.error(f"_run_dir_scanner failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_reputation_scanner(db: AsyncSession, scan: Scan) -> None:
    """Feature 32: Check each unique public IP against DNSBL + URLhaus (abuse.ch)."""
    try:
        result = await db.execute(
            select(Subdomain).where(
                Subdomain.scan_id == scan.id,
                Subdomain.is_alive == True,
                Subdomain.ip_address.isnot(None),
            )
        )
        subdomains = result.scalars().all()

        if not subdomains:
            logger.info(f"_run_reputation_scanner: no alive subdomains with IPs for {scan.domain}")
            return

        pairs = [(s.ip_address, s.hostname) for s in subdomains if s.ip_address]
        scanner = ReputationScanner(pairs)
        rep_results = await scanner.run()

        saved = 0
        for r in rep_results:
            db.add(IPReputation(
                scan_id=scan.id,
                ip_address=r.ip_address,
                hostname=r.hostname,
                is_blacklisted=r.is_blacklisted,
                blacklists=r.blacklists if r.blacklists else None,
                threat_type=r.threat_type,
                urlhaus_status=r.urlhaus_status,
                urlhaus_tags=r.urlhaus_tags if r.urlhaus_tags else None,
                abuse_score=r.abuse_score,
            ))
            saved += 1

        await db.commit()
        blacklisted = sum(1 for r in rep_results if r.is_blacklisted)
        logger.info(
            f"_run_reputation_scanner: saved {saved} results, "
            f"{blacklisted} blacklisted for {scan.domain}"
        )
    except Exception as e:
        logger.error(f"_run_reputation_scanner failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_wayback_scanner(db: AsyncSession, scan: Scan) -> None:
    """Discover historical endpoints for the domain via Wayback Machine CDX API."""
    try:
        scanner = WaybackScanner(scan.domain)
        result = await scanner.run()

        if result.error:
            logger.warning(f"_run_wayback_scanner: error for {scan.domain}: {result.error}")
            return

        saved = 0
        for f in result.findings:
            db.add(WaybackFinding(
                scan_id=scan.id,
                url=f.url,
                status_code=f.status_code,
                mime_type=f.mime_type,
                last_seen=f.last_seen,
                category=f.category,
            ))
            saved += 1

        await db.commit()
        logger.info(
            f"_run_wayback_scanner: saved {saved} findings "
            f"({result.total_archived} total archived) for {scan.domain}"
        )
    except Exception as e:
        logger.error(f"_run_wayback_scanner failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_dns_security_scanner(db: AsyncSession, scan: Scan) -> None:
    """DNSSEC validation + CAA record analysis for the scan domain."""
    try:
        scanner = DNSSecurityScanner(scan.domain)
        data = await scanner.run()

        db.add(DNSSecurity(
            scan_id=scan.id,
            dnssec_enabled=data.dnssec_enabled,
            dnssec_valid=data.dnssec_valid,
            has_caa=data.has_caa,
            caa_issuers=data.caa_issuers if data.caa_issuers else None,
            caa_wildcard_issuers=data.caa_wildcard_issuers if data.caa_wildcard_issuers else None,
            ns_count=data.ns_count,
            issues=data.issues if data.issues else None,
        ))
        await db.commit()

        logger.info(
            f"_run_dns_security_scanner: {scan.domain} — "
            f"DNSSEC={data.dnssec_enabled} CAA={data.has_caa} issues={len(data.issues)}"
        )
    except Exception as e:
        logger.error(f"_run_dns_security_scanner failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_geo_scanner(db: AsyncSession, scan: Scan) -> None:
    """Geolocate unique public IPs via ip-api.com (free, no key)."""
    try:
        result = await db.execute(
            select(Subdomain).where(
                Subdomain.scan_id == scan.id,
                Subdomain.ip_address.isnot(None),
            )
        )
        subdomains = result.scalars().all()

        if not subdomains:
            logger.info(f"_run_geo_scanner: no IPs to geolocate for {scan.domain}")
            return

        pairs = [(s.ip_address, s.hostname) for s in subdomains if s.ip_address]
        scanner = GeoScanner(pairs)
        geo_result = await scanner.run()

        saved = 0
        for g in geo_result.locations:
            db.add(IPGeoLocation(
                scan_id=scan.id,
                ip_address=g.ip_address,
                hostname=g.hostname,
                country=g.country,
                country_code=g.country_code,
                region=g.region,
                city=g.city,
                isp=g.isp,
                org=g.org,
                asn=g.asn,
                is_hosting=g.is_hosting,
            ))
            saved += 1

        await db.commit()
        logger.info(
            f"_run_geo_scanner: saved {saved} geolocation records for {scan.domain}"
        )
    except Exception as e:
        logger.error(f"_run_geo_scanner failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_risk_scorer(db: AsyncSession, scan: Scan) -> None:
    """Feature 34: Calculate overall risk score (0–100) from all scan findings.

    Runs last in the pipeline so every scanner has already written its data.
    Score components (with max contributions):
      CVEs            — up to 45 pts  (critical=12ea, high=5ea, medium=1.5ea)
      Takeovers       — up to 20 pts  (by severity)
      SSL issues      — up to 20 pts  (expired cert + worst TLS grade)
      Email spoofing  — up to 15 pts  (is_spoofable / dmarc=none)
      WAF coverage    — up to 10 pts  (<30% protected)
      Dangerous ports — up to 12 pts  (22, 3306, 5432, 6379, etc.)
      HTTP headers    — up to 10 pts  (avg security score < 60)
      Blacklisted IPs — up to 15 pts  (5 pts per blacklisted IP)
    Theoretical max ~147; divide by 1.47 to normalize to 100.
    """
    try:
        score = 0.0

        # 1. CVEs ──────────────────────────────────────────────────────────────
        cve_result = await db.execute(
            select(CVE)
            .join(Technology, CVE.technology_id == Technology.id)
            .join(Subdomain, Technology.subdomain_id == Subdomain.id)
            .where(Subdomain.scan_id == scan.id)
        )
        all_cves = cve_result.scalars().all()
        crit = sum(1 for c in all_cves if c.severity and c.severity.value == "critical")
        high = sum(1 for c in all_cves if c.severity and c.severity.value == "high")
        med  = sum(1 for c in all_cves if c.severity and c.severity.value == "medium")
        score += min(crit * 12, 36) + min(high * 5, 15) + min(med * 1.5, 7)

        # 2. Subdomain takeovers ───────────────────────────────────────────────
        tak_result = await db.execute(
            select(SubdomainTakeover)
            .join(Subdomain, SubdomainTakeover.subdomain_id == Subdomain.id)
            .where(Subdomain.scan_id == scan.id, SubdomainTakeover.is_vulnerable == True)
        )
        takeovers = tak_result.scalars().all()
        tak_crit = sum(1 for t in takeovers if t.severity and t.severity.value == "critical")
        tak_high = sum(1 for t in takeovers if t.severity and t.severity.value == "high")
        tak_med  = sum(1 for t in takeovers if t.severity and t.severity.value == "medium")
        score += min(tak_crit * 15 + tak_high * 10 + tak_med * 5, 20)

        # 3. SSL issues ────────────────────────────────────────────────────────
        ssl_result = await db.execute(
            select(SSLInfo)
            .join(Subdomain, SSLInfo.subdomain_id == Subdomain.id)
            .where(Subdomain.scan_id == scan.id)
        )
        ssl_infos = ssl_result.scalars().all()
        ssl_pts = 0
        if any(s.is_expired for s in ssl_infos):
            ssl_pts += 10
        GRADE_RISK = {"F": 10, "D": 7, "C": 4, "B": 2}
        worst_grade_pts = max(
            (GRADE_RISK.get(s.grade, 0) for s in ssl_infos if s.grade),
            default=0,
        )
        ssl_pts += worst_grade_pts
        score += min(ssl_pts, 20)

        # 4. Email security ────────────────────────────────────────────────────
        email_result = await db.execute(
            select(EmailSecurity).where(EmailSecurity.scan_id == scan.id)
        )
        email_sec = email_result.scalar_one_or_none()
        if email_sec:
            if email_sec.is_spoofable:
                score += 15
            elif email_sec.dmarc_policy == "none":
                score += 7
        else:
            score += 5  # unknown email security = small risk

        # 5. WAF coverage ──────────────────────────────────────────────────────
        alive_result = await db.execute(
            select(Subdomain).where(Subdomain.scan_id == scan.id, Subdomain.is_alive == True)
        )
        alive_subs = alive_result.scalars().all()
        if alive_subs:
            sub_ids = [s.id for s in alive_subs]
            waf_result = await db.execute(
                select(WAFResult).where(WAFResult.subdomain_id.in_(sub_ids))
            )
            waf_rows = waf_result.scalars().all()
            protected = sum(1 for w in waf_rows if w.detected)
            coverage = protected / len(alive_subs)
            if coverage < 0.3:
                score += 10
            elif coverage < 0.7:
                score += 5

            # 6. Dangerous open ports ──────────────────────────────────────────
            DANGEROUS_PORTS = {21, 22, 23, 3306, 5432, 6379, 27017, 1433, 1521, 3389, 5900}
            port_result = await db.execute(
                select(Port).where(Port.subdomain_id.in_(sub_ids))
            )
            all_ports = port_result.scalars().all()
            dangerous_open = {p.port_number for p in all_ports if p.port_number in DANGEROUS_PORTS}
            score += min(len(dangerous_open) * 3, 12)

            # 7. HTTP security headers ─────────────────────────────────────────
            header_result = await db.execute(
                select(HeaderAnalysis).where(HeaderAnalysis.subdomain_id.in_(sub_ids))
            )
            header_rows = header_result.scalars().all()
            header_scores = [h.security_score for h in header_rows if h.security_score is not None]
            if header_scores:
                avg_header = sum(header_scores) / len(header_scores)
                if avg_header < 30:
                    score += 10
                elif avg_header < 60:
                    score += 5

        # 8. Blacklisted IPs ───────────────────────────────────────────────────
        rep_result = await db.execute(
            select(IPReputation).where(
                IPReputation.scan_id == scan.id,
                IPReputation.is_blacklisted == True,
            )
        )
        blacklisted_count = len(rep_result.scalars().all())
        score += min(blacklisted_count * 5, 15)

        # Normalize to 0–100 (theoretical max ~147)
        final_score = min(round(score / 1.47), 100)

        scan.risk_score = float(final_score)
        await db.commit()
        logger.info(
            f"_run_risk_scorer: risk_score={final_score} "
            f"(raw={score:.1f}) for {scan.domain}"
        )
    except Exception as e:
        logger.error(f"_run_risk_scorer failed for {scan.domain}: {e}")
        await db.rollback()


async def _run_reverse_ip_scanner(db: AsyncSession, scan: Scan) -> None:
    """Feature #8 — Reverse IP Lookup via HackerTarget."""
    try:
        # Collect unique IPs from alive subdomains
        sub_result = await db.execute(
            select(Subdomain)
            .where(Subdomain.scan_id == scan.id, Subdomain.ip_address.isnot(None))
        )
        subdomains = sub_result.scalars().all()
        ips = [s.ip_address for s in subdomains if s.ip_address]

        scanner = ReverseIPScanner(ips)
        result = await scanner.run()

        if result.error and not result.entries:
            logger.warning(f"ReverseIPScanner: {result.error}")
            return

        for entry in result.entries:
            db.add(ReverseIPResultModel(
                scan_id=scan.id,
                ip_address=entry.ip_address,
                co_hosted_domains=entry.co_hosted_domains if not entry.error and not entry.skipped_reason else None,
                domain_count=entry.domain_count,
                skipped_reason=entry.skipped_reason,
                error=entry.error,
            ))
        await db.commit()
        logger.info(f"ReverseIPScanner: saved {len(result.entries)} entries for {scan.domain}")
    except Exception as exc:
        logger.error(f"_run_reverse_ip_scanner failed for {scan.domain}: {exc}")
        await db.rollback()


async def _run_otx_scanner(db: AsyncSession, scan: Scan) -> None:
    """Feature #9 — AlienVault OTX threat intelligence lookup."""
    try:
        scanner = OTXScanner(scan.domain)
        result = await scanner.run()

        db.add(OTXResultModel(
            scan_id=scan.id,
            pulse_count=result.pulse_count,
            threat_types=result.threat_types or [],
            malware_families=result.malware_families or [],
            adversaries=result.adversaries or [],
            country=result.country,
            first_seen=result.first_seen,
            alexa_rank=result.alexa_rank,
            is_known_malicious=result.is_known_malicious,
            error=result.error,
        ))
        await db.commit()
        logger.info(
            f"OTXScanner: {scan.domain} → pulse_count={result.pulse_count}, "
            f"malicious={result.is_known_malicious}"
        )
    except Exception as exc:
        logger.error(f"_run_otx_scanner failed for {scan.domain}: {exc}")
        await db.rollback()
