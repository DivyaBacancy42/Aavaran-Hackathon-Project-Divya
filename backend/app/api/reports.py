"""
PDF Report Generator for SHODH scans.
GET /api/scans/{scan_id}/report  →  returns application/pdf
"""
import io
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.models import (
    ASNInfo, CVE, CORSResult, DirectoryFinding, DNSRecord, DNSSecurity,
    EmailSecurity, HeaderAnalysis, IPGeoLocation, IPReputation, JSFinding,
    OTXResult as OTXResultModel, Port, ReverseIPResult as ReverseIPResultModel,
    Scan, ScanStatus, SSLInfo, Subdomain, SubdomainTakeover, Technology,
    WAFResult, WaybackFinding, WhoisInfo,
)

# reportlab imports
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable, PageTemplate,
    Paragraph, Spacer, Table, TableStyle, PageBreak,
)
from reportlab.platypus.flowables import KeepTogether

router = APIRouter(prefix="/api/scans", tags=["reports"])

# ── Colour palette ──────────────────────────────────────────────────────────
C_BG         = colors.white
C_SURFACE    = colors.HexColor("#f5f5fa")
C_ACCENT     = colors.HexColor("#00aa55")
C_DANGER     = colors.HexColor("#cc1133")
C_WARNING    = colors.HexColor("#dd7700")
C_INFO       = colors.HexColor("#0066cc")
C_PURPLE     = colors.HexColor("#6633cc")
C_TEXT       = colors.HexColor("#1a1a2a")
C_MUTED      = colors.HexColor("#666680")
C_BORDER     = colors.HexColor("#ccccdd")
C_ROW_EVEN   = colors.HexColor("#f0f0f8")
C_ROW_ODD    = colors.white
C_HEADER_ROW = colors.HexColor("#1a1a2e")

SEV_COLORS = {
    "critical": C_DANGER,
    "high":     colors.HexColor("#ff6633"),
    "medium":   C_WARNING,
    "low":      colors.HexColor("#88cc44"),
    "info":     C_INFO,
}

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm


# ── Style helpers ────────────────────────────────────────────────────────────

def _styles():
    base = getSampleStyleSheet()

    def s(name, **kw):
        return ParagraphStyle(name, **kw)

    return {
        "title":    s("RPT_title",    fontSize=28, textColor=C_ACCENT,
                      alignment=TA_CENTER, spaceAfter=4, fontName="Helvetica-Bold"),
        "subtitle": s("RPT_subtitle", fontSize=13, textColor=C_TEXT,
                      alignment=TA_CENTER, spaceAfter=2, fontName="Helvetica"),
        "meta":     s("RPT_meta",     fontSize=9,  textColor=C_MUTED,
                      alignment=TA_CENTER, spaceAfter=1, fontName="Helvetica"),
        "h1":       s("RPT_h1",       fontSize=16, textColor=C_ACCENT,
                      spaceBefore=12, spaceAfter=10, fontName="Helvetica-Bold", leading=22),
        "h2":       s("RPT_h2",       fontSize=12, textColor=C_INFO,
                      spaceBefore=8,  spaceAfter=6,  fontName="Helvetica-Bold", leading=18),
        "body":     s("RPT_body",     fontSize=8,  textColor=C_TEXT,
                      fontName="Helvetica", leading=11),
        "mono":     s("RPT_mono",     fontSize=7,  textColor=C_TEXT,
                      fontName="Courier", leading=10),
        "mono_sm":  s("RPT_mono_sm",  fontSize=6,  textColor=C_MUTED,
                      fontName="Courier", leading=9),
        "danger":   s("RPT_danger",   fontSize=8,  textColor=C_DANGER,
                      fontName="Helvetica-Bold"),
        "warning":  s("RPT_warning",  fontSize=8,  textColor=C_WARNING,
                      fontName="Helvetica-Bold"),
        "good":     s("RPT_good",     fontSize=8,  textColor=C_ACCENT,
                      fontName="Helvetica-Bold"),
        "label":    s("RPT_label",    fontSize=7,  textColor=C_MUTED,
                      fontName="Helvetica"),
    }


def _tbl_style(header_cols=None, col_widths=None):
    """Base dark table style. header_cols: list of column indices to colour specially."""
    ts = TableStyle([
        # Header row
        ("BACKGROUND", (0, 0), (-1, 0), C_HEADER_ROW),
        ("TEXTCOLOR",  (0, 0), (-1, 0), C_ACCENT),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, 0), 7),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
        ("TOPPADDING",    (0, 0), (-1, 0), 5),
        # Body rows
        ("FONTNAME",   (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",   (0, 1), (-1, -1), 7),
        ("TEXTCOLOR",  (0, 1), (-1, -1), C_TEXT),
        ("TOPPADDING",    (0, 1), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("GRID",       (0, 0), (-1, -1), 0.3, C_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_ROW_ODD, C_ROW_EVEN]),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("WORDWRAP",   (0, 0), (-1, -1), True),
    ])
    return ts


def _sev_para(sev, styles):
    """Return a coloured severity Paragraph."""
    col = SEV_COLORS.get((sev or "info").lower(), C_MUTED)
    st = ParagraphStyle("sev_inline", fontSize=7, textColor=col,
                        fontName="Helvetica-Bold")
    return Paragraph((sev or "info").upper(), st)


def _wrap(text, style, max_chars=120):
    """Wrap long text into a Paragraph so it doesn't overflow cells."""
    text = str(text or "")
    if len(text) > max_chars:
        text = text[:max_chars] + "…"
    return Paragraph(text, style)


# ── Page template with dark background + header/footer ──────────────────────

def _build_page_template(domain: str, scan_date: str):
    def on_page(canvas, doc):
        canvas.saveState()
        # White background
        canvas.setFillColor(colors.white)
        canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
        # Top bar (dark)
        canvas.setFillColor(colors.HexColor("#1a1a2e"))
        canvas.rect(0, PAGE_H - 12 * mm, PAGE_W, 12 * mm, fill=1, stroke=0)
        canvas.setFillColor(colors.HexColor("#00aa55"))
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(MARGIN, PAGE_H - 8 * mm, f"AAVRAN — {domain}")
        canvas.setFillColor(colors.HexColor("#aaaacc"))
        canvas.setFont("Helvetica", 7)
        canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 8 * mm, scan_date)
        # Bottom bar (dark)
        canvas.setFillColor(colors.HexColor("#1a1a2e"))
        canvas.rect(0, 0, PAGE_W, 10 * mm, fill=1, stroke=0)
        canvas.setFillColor(colors.HexColor("#aaaacc"))
        canvas.setFont("Helvetica", 7)
        canvas.drawString(MARGIN, 4 * mm, "CONFIDENTIAL — Attack Surface Intelligence Report")
        canvas.drawRightString(PAGE_W - MARGIN, 4 * mm, f"Page {doc.page}")
        canvas.restoreState()

    frame = Frame(MARGIN, 12 * mm, PAGE_W - 2 * MARGIN, PAGE_H - 26 * mm, id="main")
    return PageTemplate(id="main", frames=[frame], onPage=on_page)


# ── Section: Cover Page ──────────────────────────────────────────────────────

def _cover(scan, styles, story):
    story.append(Spacer(1, 30 * mm))

    story.append(Paragraph("AAVRAN", ParagraphStyle(
        "cover_brand", fontSize=48, textColor=C_ACCENT,
        alignment=TA_CENTER, fontName="Helvetica-Bold",
        leading=62, spaceAfter=0, spaceBefore=0)))
    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph("Attack Surface Intelligence Report",
                            ParagraphStyle("cover_sub", fontSize=15, textColor=C_TEXT,
                                           alignment=TA_CENTER, fontName="Helvetica",
                                           leading=20, spaceAfter=0, spaceBefore=0)))
    story.append(Spacer(1, 8 * mm))
    story.append(HRFlowable(width="80%", color=C_ACCENT, thickness=1.5))
    story.append(Spacer(1, 10 * mm))

    story.append(Paragraph(scan.domain.upper(), ParagraphStyle(
        "cover_domain", fontSize=20, textColor=C_INFO,
        alignment=TA_CENTER, fontName="Helvetica-Bold",
        leading=26, spaceAfter=0, spaceBefore=0)))
    story.append(Spacer(1, 6 * mm))

    date_str = (scan.completed_at or scan.created_at).strftime("%B %d, %Y %H:%M UTC") \
        if (scan.completed_at or scan.created_at) else "—"
    story.append(Paragraph(f"Scan completed: {date_str}",
                            ParagraphStyle("cover_meta", fontSize=9, textColor=C_MUTED,
                                           alignment=TA_CENTER, fontName="Helvetica", leading=13)))
    story.append(Spacer(1, 10 * mm))

    if scan.risk_score is not None:
        score = scan.risk_score
        if score >= 70:
            score_col = C_DANGER
            label = "CRITICAL RISK"
        elif score >= 40:
            score_col = C_WARNING
            label = "HIGH RISK"
        elif score >= 20:
            score_col = colors.HexColor("#cc8800")
            label = "MEDIUM RISK"
        else:
            score_col = C_ACCENT
            label = "LOW RISK"

        story.append(Paragraph(f"{score:.0f} / 100", ParagraphStyle(
            "cover_score", fontSize=44, textColor=score_col,
            alignment=TA_CENTER, fontName="Helvetica-Bold",
            leading=56, spaceAfter=0, spaceBefore=0)))
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph(label, ParagraphStyle(
            "cover_label", fontSize=13, textColor=score_col,
            alignment=TA_CENTER, fontName="Helvetica-Bold",
            leading=18, spaceAfter=0, spaceBefore=0)))

    story.append(Spacer(1, 10 * mm))
    story.append(HRFlowable(width="80%", color=C_BORDER, thickness=0.5))
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph(
        "This report was generated by AAVRAN — a self-hosted, open-source attack surface "
        "mapping platform. All data is collected from passive DNS, certificate transparency, "
        "TCP port scanning, and public threat intelligence feeds. No active exploitation was performed.",
        ParagraphStyle("cover_note", fontSize=8, textColor=C_MUTED,
                       alignment=TA_CENTER, fontName="Helvetica", leading=13)))
    story.append(PageBreak())


# ── Section: Critical Action Items ──────────────────────────────────────────

def _critical_actions(scan_data: dict, styles, story):
    """Build the Critical Action Items table — highest priority findings."""
    items = []  # (priority, category, finding, recommendation)

    cves = scan_data.get("cves", [])
    for cve in cves:
        sev = (cve.get("severity") or "info").lower()
        if sev in ("critical", "high"):
            items.append((
                sev,
                "CVE / Vulnerability",
                f"{cve['cve_id']} in {cve['technology_name']} {cve.get('technology_version') or ''}  "
                f"(CVSS {cve.get('cvss_score') or 'N/A'})",
                "Patch or upgrade the affected software immediately.",
            ))

    for tak in scan_data.get("takeovers", []):
        # takeovers are dicts (built in _load_all_data)
        items.append((
            (tak.get("severity") or "critical").lower(),
            "Subdomain Takeover",
            f"{tak['hostname']} → {tak.get('cname_target') or tak.get('service') or ''}",
            "Remove the dangling DNS CNAME record or reclaim the cloud resource.",
        ))

    for cors in scan_data.get("cors_results", []):
        # cors_results are dicts (built in _load_all_data)
        items.append((
            (cors.get("severity") or "high").lower(),
            "CORS Misconfiguration",
            f"{cors['hostname']} reflects {cors.get('allowed_origin') or 'arbitrary'} origin",
            "Restrict CORS to trusted origins only. Never reflect the request Origin header.",
        ))

    for js in scan_data.get("js_findings", []):
        # js_findings are SQLAlchemy objects — use attribute access
        if (js.secret_count or 0) > 0:
            items.append((
                "high",
                "Exposed Secrets in JS",
                f"{js.subdomain_hostname} — {js.secret_count} secret(s) in {js.js_url}",
                "Rotate all exposed credentials immediately and remove from client-side JS.",
            ))

    for rep in scan_data.get("ip_reputation", []):
        # ip_reputation are SQLAlchemy objects — use attribute access
        if rep.is_blacklisted:
            items.append((
                "high",
                "Blacklisted IP",
                f"{rep.ip_address} ({rep.hostname or ''}) on {', '.join(rep.blacklists or [])}",
                "Investigate the IP for malware/spam activity. Request delisting after remediation.",
            ))

    # Expired / bad SSL — subdomains are SQLAlchemy objects with attached ssl_info
    for sub in scan_data.get("subdomains", []):
        ssl = sub.ssl_info
        if ssl:
            if ssl.is_expired:
                items.append((
                    "critical",
                    "Expired SSL Certificate",
                    f"{sub.hostname} — certificate expired",
                    "Renew the SSL certificate immediately to restore encrypted connections.",
                ))
            elif ssl.grade in ("F", "D"):
                items.append((
                    "high",
                    "Weak SSL/TLS Configuration",
                    f"{sub.hostname} — TLS grade {ssl.grade}",
                    "Disable TLS 1.0/1.1, enable TLS 1.3, and update cipher suites.",
                ))

    # Missing security headers
    for sub in scan_data.get("subdomains", []):
        ha = sub.header_analysis
        if ha and ha.security_score is not None and ha.security_score < 40:
            missing = ", ".join(ha.missing_headers or [])
            items.append((
                "medium",
                "Missing Security Headers",
                f"{sub.hostname} (score {ha.security_score}/100) — missing: {missing}",
                "Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options headers.",
            ))

    # DMARC not enforced — email_security is a SQLAlchemy object
    es = scan_data.get("email_security")
    if es:
        if not es.spf_valid:
            items.append(("high", "Email Security", "SPF record invalid or missing",
                          "Add a valid SPF record to prevent email spoofing."))
        if es.dmarc_policy in ("none", None):
            items.append(("high", "Email Security", "DMARC policy is 'none' (monitoring only)",
                          "Set DMARC policy to 'quarantine' or 'reject' to block spoofed email."))

    # DNS Security — dns_security is a SQLAlchemy object
    dns_sec = scan_data.get("dns_security")
    if dns_sec:
        for issue in (dns_sec.issues or []):
            items.append(("medium", "DNS Security", issue,
                          "Resolve the DNS security misconfiguration."))

    # Zone transfer
    if scan_data.get("zone_transfer_successful"):
        items.append(("critical", "DNS Zone Transfer",
                      "Authoritative nameserver allows unrestricted AXFR zone transfer",
                      "Restrict AXFR transfers to authorised secondary nameservers only."))

    # Dangerous open ports (no WAF) — subdomains/ports are SQLAlchemy objects
    DANGEROUS_PORTS = {3306, 5432, 6379, 27017, 9200, 2375, 5984, 9042, 11211,
                       1433, 1521, 2379, 4001, 8500, 9092}
    for sub in scan_data.get("subdomains", []):
        if not sub.waf_detected:
            for port in (sub.ports or []):
                if port.port_number in DANGEROUS_PORTS:
                    items.append((
                        "critical",
                        "Exposed Database/Service Port",
                        f"{sub.hostname}:{port.port_number} ({port.service or ''}) — no WAF",
                        "Restrict access to this port using a firewall. Never expose DB ports publicly.",
                    ))

    if not items:
        story.append(Paragraph("Critical Action Items", styles["h1"]))
        story.append(Paragraph("No critical findings detected.", styles["body"]))
        story.append(Spacer(1, 4 * mm))
        return

    # Sort: critical first, then high, medium, low
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    items.sort(key=lambda x: SEV_ORDER.get(x[0], 5))

    story.append(Paragraph("Critical Action Items", styles["h1"]))
    story.append(Paragraph(
        f"The following {len(items)} item(s) require immediate attention, listed by priority.",
        styles["body"]))
    story.append(Spacer(1, 3 * mm))

    col_w = [PAGE_W - 2 * MARGIN - 20 * mm - 38 * mm - 55 * mm,
             20 * mm, 38 * mm, 55 * mm]  # finding, severity, category, recommendation
    # Reorder columns for readability: #, Severity, Category, Finding, Recommendation
    headers = ["#", "Severity", "Category", "Finding", "Recommendation"]
    col_w2 = [8 * mm, 18 * mm, 32 * mm, 65 * mm, 55 * mm]

    tbl_data = [headers]
    for i, (sev, cat, finding, rec) in enumerate(items, 1):
        tbl_data.append([
            str(i),
            _sev_para(sev, styles),
            _wrap(cat, styles["mono_sm"], 30),
            _wrap(finding, styles["body"], 100),
            _wrap(rec, styles["body"], 90),
        ])

    ts = _tbl_style()
    # Highlight critical/high rows
    for row_idx, (sev, *_) in enumerate(items, 1):
        if sev == "critical":
            ts.add("BACKGROUND", (0, row_idx), (-1, row_idx),
                   colors.HexColor("#ffe8ec"))
            ts.add("LEFTPADDING",  (0, row_idx), (0, row_idx), 5)
            ts.add("LINEAFTER",    (0, row_idx), (0, row_idx), 2, C_DANGER)
        elif sev == "high":
            ts.add("BACKGROUND", (0, row_idx), (-1, row_idx),
                   colors.HexColor("#fff3e0"))

    tbl = Table(tbl_data, colWidths=col_w2, repeatRows=1)
    tbl.setStyle(ts)
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))


# ── Section: DNS Records ─────────────────────────────────────────────────────

def _dns_records(dns_records, styles, story):
    story.append(Paragraph("DNS Records", styles["h1"]))
    if not dns_records:
        story.append(Paragraph("No DNS records found.", styles["body"]))
        return

    story.append(Spacer(1, 4 * mm))
    headers = ["Type", "Hostname", "Value", "TTL"]
    col_w = [16 * mm, 45 * mm, 95 * mm, 18 * mm]
    tbl_data = [headers]
    for r in dns_records:
        tbl_data.append([
            r.record_type,
            _wrap(r.hostname, styles["mono_sm"], 50),
            _wrap(r.value, styles["mono_sm"], 100),
            str(r.ttl) if r.ttl else "—",
        ])

    tbl = Table(tbl_data, colWidths=col_w, repeatRows=1)
    tbl.setStyle(_tbl_style())
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))


# ── Section: Subdomains ──────────────────────────────────────────────────────

def _subdomains(subdomains, styles, story):
    story.append(Paragraph("Discovered Subdomains", styles["h1"]))
    if not subdomains:
        story.append(Paragraph("No subdomains discovered.", styles["body"]))
        return

    alive = [s for s in subdomains if s.is_alive]
    dead  = [s for s in subdomains if not s.is_alive]

    story.append(Paragraph(
        f"Total: {len(subdomains)}  |  Alive: {len(alive)}  |  Unreachable: {len(dead)}",
        styles["body"]))
    story.append(Spacer(1, 2 * mm))

    headers = ["Hostname", "IP", "Status", "WAF", "SSL Grade", "Technologies"]
    col_w = [55 * mm, 25 * mm, 14 * mm, 22 * mm, 18 * mm, 40 * mm]
    tbl_data = [headers]

    for sub in subdomains:
        techs = ", ".join(t.name for t in (sub.technologies or []))[:50]
        ssl_grade = (sub.ssl_info.grade if sub.ssl_info else None) or "—"
        waf = sub.waf_name if sub.waf_detected else ("None" if sub.waf_detected is False else "—")
        status_p = Paragraph(
            str(sub.http_status or ("Alive" if sub.is_alive else "Dead")),
            ParagraphStyle("st", fontSize=7, textColor=C_ACCENT if sub.is_alive else C_MUTED,
                           fontName="Helvetica-Bold"))
        tbl_data.append([
            _wrap(sub.hostname, styles["mono_sm"], 60),
            _wrap(sub.ip_address or "—", styles["mono_sm"], 20),
            status_p,
            _wrap(waf, styles["body"], 25),
            ssl_grade,
            _wrap(techs or "—", styles["body"], 50),
        ])

    tbl = Table(tbl_data, colWidths=col_w, repeatRows=1)
    tbl.setStyle(_tbl_style())
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))


# ── Section: Open Ports ──────────────────────────────────────────────────────

def _open_ports(subdomains, styles, story):
    DANGEROUS = {3306, 5432, 6379, 27017, 9200, 2375, 5984, 9042, 11211,
                 1433, 1521, 2379, 4001, 8500, 9092, 23, 21}
    all_ports = []
    for sub in subdomains:
        for port in (sub.ports or []):
            all_ports.append((sub.hostname, port.port_number,
                              port.service or "", port.version or ""))

    story.append(Paragraph("Open Ports", styles["h1"]))
    if not all_ports:
        story.append(Paragraph("No open ports discovered.", styles["body"]))
        return

    story.append(Paragraph(f"{len(all_ports)} open port(s) across all hosts.", styles["body"]))
    story.append(Spacer(1, 2 * mm))

    all_ports.sort(key=lambda x: (x[1] not in DANGEROUS, x[1]))

    headers = ["Host", "Port", "Service", "Version", "Risk"]
    col_w = [55 * mm, 18 * mm, 30 * mm, 40 * mm, 22 * mm]
    tbl_data = [headers]
    ts = _tbl_style()

    for row_i, (host, port, svc, ver) in enumerate(all_ports, 1):
        is_dangerous = port in DANGEROUS
        risk_p = Paragraph("HIGH" if is_dangerous else "low",
                           ParagraphStyle("rp", fontSize=7,
                                          textColor=C_DANGER if is_dangerous else C_MUTED,
                                          fontName="Helvetica-Bold"))
        tbl_data.append([
            _wrap(host, styles["mono_sm"], 55),
            str(port),
            _wrap(svc, styles["body"], 30),
            _wrap(ver, styles["mono_sm"], 40),
            risk_p,
        ])
        if is_dangerous:
            ts.add("BACKGROUND", (0, row_i), (-1, row_i), colors.HexColor("#ffe8ec"))

    tbl = Table(tbl_data, colWidths=col_w, repeatRows=1)
    tbl.setStyle(ts)
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))


# ── Section: Technologies ────────────────────────────────────────────────────

def _technologies(subdomains, styles, story):
    story.append(Paragraph("Technology Stack", styles["h1"]))
    tech_map: dict = {}
    for sub in subdomains:
        for t in (sub.technologies or []):
            key = (t.name, t.version or "", t.category or "")
            tech_map.setdefault(key, []).append(sub.hostname)

    if not tech_map:
        story.append(Paragraph("No technologies detected.", styles["body"]))
        return

    story.append(Spacer(1, 4 * mm))
    headers = ["Technology", "Version", "Category", "Found On"]
    col_w = [40 * mm, 25 * mm, 30 * mm, 79 * mm]
    tbl_data = [headers]
    for (name, ver, cat), hosts in sorted(tech_map.items()):
        tbl_data.append([
            _wrap(name, styles["body"], 40),
            _wrap(ver or "—", styles["mono_sm"], 25),
            _wrap(cat or "—", styles["body"], 30),
            _wrap(", ".join(set(hosts))[:100], styles["mono_sm"], 100),
        ])

    tbl = Table(tbl_data, colWidths=col_w, repeatRows=1)
    tbl.setStyle(_tbl_style())
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))


# ── Section: CVEs ────────────────────────────────────────────────────────────

def _cves(cves, styles, story):
    story.append(Paragraph("CVE / Vulnerability Findings", styles["h1"]))
    if not cves:
        story.append(Paragraph("No CVEs detected.", styles["body"]))
        return

    story.append(Paragraph(f"{len(cves)} CVE(s) found.", styles["body"]))
    story.append(Spacer(1, 2 * mm))

    headers = ["CVE ID", "Severity", "CVSS", "Technology", "Version", "Description"]
    col_w = [28 * mm, 18 * mm, 12 * mm, 28 * mm, 18 * mm, 70 * mm]
    tbl_data = [headers]
    ts = _tbl_style()
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    cves_s = sorted(cves, key=lambda c: SEV_ORDER.get((c.get("severity") or "info").lower(), 5))

    for row_i, cve in enumerate(cves_s, 1):
        sev = (cve.get("severity") or "info").lower()
        tbl_data.append([
            _wrap(cve["cve_id"], styles["mono_sm"], 28),
            _sev_para(sev, styles),
            str(cve.get("cvss_score") or "—"),
            _wrap(cve.get("technology_name") or "—", styles["body"], 28),
            _wrap(cve.get("technology_version") or "—", styles["mono_sm"], 18),
            _wrap(cve.get("description") or "—", styles["body"], 100),
        ])
        if sev == "critical":
            ts.add("BACKGROUND", (0, row_i), (-1, row_i), colors.HexColor("#ffe8ec"))
        elif sev == "high":
            ts.add("BACKGROUND", (0, row_i), (-1, row_i), colors.HexColor("#fff3e0"))

    tbl = Table(tbl_data, colWidths=col_w, repeatRows=1)
    tbl.setStyle(ts)
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))


# ── Section: Email Security ──────────────────────────────────────────────────

def _email_security(es, styles, story):
    story.append(Paragraph("Email Security (SPF / DKIM / DMARC)", styles["h1"]))
    if not es:
        story.append(Paragraph("No email security data collected.", styles["body"]))
        return

    story.append(Spacer(1, 4 * mm))
    def yesno(val, good_on_true=True):
        if val is None:
            return Paragraph("—", styles["body"])
        ok = bool(val) == good_on_true
        return Paragraph("YES" if val else "NO",
                         ParagraphStyle("yn", fontSize=7,
                                        textColor=C_ACCENT if ok else C_DANGER,
                                        fontName="Helvetica-Bold"))

    rows = [
        ["SPF Record",     _wrap(es.spf_record or "—", styles["mono_sm"], 100)],
        ["SPF Valid",      yesno(es.spf_valid)],
        ["SPF Mechanism",  Paragraph(es.spf_mechanism or "—", styles["body"])],
        ["DKIM Found",     yesno(es.dkim_found)],
        ["DKIM Selector",  Paragraph(es.dkim_selector or "—", styles["mono_sm"])],
        ["DMARC Record",   _wrap(es.dmarc_record or "—", styles["mono_sm"], 100)],
        ["DMARC Policy",   Paragraph(es.dmarc_policy or "—", styles["body"])],
        ["DMARC %",        Paragraph(str(es.dmarc_pct) + "%" if es.dmarc_pct is not None else "—",
                                     styles["body"])],
        ["MTA-STS Mode",   Paragraph(es.mta_sts_mode or "—", styles["body"])],
        ["Spoofable",      yesno(es.is_spoofable, good_on_true=False)],
    ]

    tbl = Table(rows, colWidths=[45 * mm, 129 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), C_HEADER_ROW),
        ("TEXTCOLOR",  (0, 0), (0, -1), C_ACCENT),
        ("FONTNAME",   (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 7),
        ("TEXTCOLOR",  (1, 0), (1, -1), C_TEXT),
        ("FONTNAME",   (1, 0), (1, -1), "Helvetica"),
        ("GRID",       (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_ROW_ODD, C_ROW_EVEN]),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))


# ── Section: SSL/TLS ─────────────────────────────────────────────────────────

def _ssl_tls(subdomains, styles, story):
    story.append(Paragraph("SSL / TLS Certificate Analysis", styles["h1"]))
    ssl_subs = [(s, s.ssl_info) for s in subdomains if s.ssl_info]
    if not ssl_subs:
        story.append(Paragraph("No SSL data collected.", styles["body"]))
        return

    story.append(Spacer(1, 4 * mm))
    headers = ["Host", "Grade", "Issuer", "Valid Until", "Expired", "TLS Protocols"]
    col_w = [45 * mm, 12 * mm, 40 * mm, 24 * mm, 14 * mm, 39 * mm]
    tbl_data = [headers]
    ts = _tbl_style()

    for row_i, (sub, ssl) in enumerate(ssl_subs, 1):
        grade = ssl.grade or "?"
        grade_col = C_ACCENT if grade in ("A+", "A") else (
            C_WARNING if grade in ("B", "C") else C_DANGER)
        grade_p = Paragraph(grade, ParagraphStyle("gp", fontSize=8, textColor=grade_col,
                                                   fontName="Helvetica-Bold"))
        proto = ssl.protocols or {}
        if hasattr(proto, '__dict__'):
            proto = vars(proto)
        proto_str = " / ".join(k for k, v in proto.items() if v)
        exp_p = Paragraph("YES" if ssl.is_expired else "NO",
                          ParagraphStyle("ep", fontSize=7,
                                         textColor=C_DANGER if ssl.is_expired else C_ACCENT,
                                         fontName="Helvetica-Bold"))
        valid_until = ssl.valid_until.strftime("%Y-%m-%d") if ssl.valid_until else "—"
        tbl_data.append([
            _wrap(sub.hostname, styles["mono_sm"], 45),
            grade_p,
            _wrap(ssl.issuer or "—", styles["body"], 40),
            valid_until,
            exp_p,
            _wrap(proto_str or "—", styles["mono_sm"], 40),
        ])
        if ssl.is_expired:
            ts.add("BACKGROUND", (0, row_i), (-1, row_i), colors.HexColor("#ffe8ec"))

    tbl = Table(tbl_data, colWidths=col_w, repeatRows=1)
    tbl.setStyle(ts)
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))


# ── Section: CORS Misconfigurations ─────────────────────────────────────────

def _cors(cors_results, styles, story):
    story.append(Paragraph("CORS Misconfigurations", styles["h1"]))
    vulns = [c for c in cors_results if c.get("is_vulnerable")]
    if not vulns:
        story.append(Paragraph("No CORS misconfigurations detected.", styles["body"]))
        return

    story.append(Spacer(1, 4 * mm))
    headers = ["Host", "Type", "Reflected Origin", "With Credentials", "Severity"]
    col_w = [45 * mm, 38 * mm, 38 * mm, 24 * mm, 20 * mm]
    tbl_data = [headers]
    for v in vulns:
        # cors items are dicts (built in _load_all_data)
        tbl_data.append([
            _wrap(v.get("hostname", ""), styles["mono_sm"], 45),
            _wrap(v.get("misconfig_type") or "—", styles["body"], 38),
            _wrap(v.get("allowed_origin") or "—", styles["mono_sm"], 38),
            "YES" if v.get("allow_credentials") else "NO",
            _sev_para(v.get("severity"), styles),
        ])

    tbl = Table(tbl_data, colWidths=col_w, repeatRows=1)
    tbl.setStyle(_tbl_style())
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))


# ── Section: Directory Findings ──────────────────────────────────────────────

def _directory_findings(dir_findings, styles, story):
    story.append(Paragraph("Directory / Path Discovery", styles["h1"]))
    if not dir_findings:
        story.append(Paragraph("No sensitive paths discovered.", styles["body"]))
        return

    story.append(Spacer(1, 4 * mm))
    headers = ["Host", "Path", "Status", "Type", "Severity"]
    col_w = [45 * mm, 50 * mm, 14 * mm, 30 * mm, 18 * mm]
    tbl_data = [headers]
    ts = _tbl_style()
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    dirs_s = sorted(dir_findings,
                    key=lambda d: SEV_ORDER.get(str(d.severity or "low"), 4))

    for row_i, d in enumerate(dirs_s, 1):
        sev = str(d.severity or "low")
        tbl_data.append([
            _wrap(d.subdomain_hostname, styles["mono_sm"], 45),
            _wrap(d.path, styles["mono_sm"], 50),
            str(d.status_code),
            _wrap(d.finding_type or "—", styles["body"], 30),
            _sev_para(sev, styles),
        ])
        if sev in ("critical", "high"):
            ts.add("BACKGROUND", (0, row_i), (-1, row_i),
                   colors.HexColor("#ffe8ec" if sev == "critical" else "#fff3e0"))

    tbl = Table(tbl_data, colWidths=col_w, repeatRows=1)
    tbl.setStyle(ts)
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))


# ── Section: JS Secret Findings ──────────────────────────────────────────────

def _js_findings(js_findings, styles, story):
    story.append(Paragraph("JavaScript Analysis — Secrets & Endpoints", styles["h1"]))
    if not js_findings:
        story.append(Paragraph("No JS secrets or notable endpoints found.", styles["body"]))
        return

    story.append(Spacer(1, 4 * mm))
    for js in js_findings:
        if not (js.secret_count or js.endpoint_count):
            continue
        story.append(Paragraph(f"File: {js.js_url}", styles["h2"]))
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(f"Host: {js.subdomain_hostname}  |  "
                                f"Secrets: {js.secret_count}  |  Endpoints: {js.endpoint_count}",
                                styles["body"]))

        if js.secrets:
            sec_rows = [["Secret Type", "Value (masked)"]]
            for sec in js.secrets:
                sec_rows.append([
                    _wrap(getattr(sec, "type", None) or (sec.get("type") if isinstance(sec, dict) else None) or "unknown", styles["body"], 30),
                    _wrap(getattr(sec, "value", None) or (sec.get("value") if isinstance(sec, dict) else None) or "—", styles["mono_sm"], 80),
                ])
            sec_tbl = Table(sec_rows, colWidths=[35 * mm, 90 * mm])
            sec_tbl.setStyle(_tbl_style())
            story.append(sec_tbl)
        story.append(Spacer(1, 3 * mm))

    story.append(Spacer(1, 2 * mm))


# ── Section: Subdomain Takeovers ─────────────────────────────────────────────

def _takeovers(takeovers, styles, story):
    story.append(Paragraph("Subdomain Takeover Vulnerabilities", styles["h1"]))
    if not takeovers:
        story.append(Paragraph("No subdomain takeover vulnerabilities detected.", styles["body"]))
        return

    story.append(Spacer(1, 4 * mm))
    headers = ["Hostname", "Service", "CNAME Target", "Fingerprint", "Severity"]
    col_w = [45 * mm, 25 * mm, 40 * mm, 40 * mm, 18 * mm]
    tbl_data = [headers]
    for t in takeovers:
        # takeovers are dicts (built in _load_all_data)
        tbl_data.append([
            _wrap(t.get("hostname", ""), styles["mono_sm"], 45),
            _wrap(t.get("service") or "—", styles["body"], 25),
            _wrap(t.get("cname_target") or "—", styles["mono_sm"], 40),
            _wrap(t.get("fingerprint") or "—", styles["mono_sm"], 40),
            _sev_para(t.get("severity"), styles),
        ])

    tbl = Table(tbl_data, colWidths=col_w, repeatRows=1)
    ts = _tbl_style()
    for i in range(1, len(tbl_data)):
        ts.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#ffe8ec"))
    tbl.setStyle(ts)
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))


# ── Section: IP Reputation ────────────────────────────────────────────────────

def _ip_reputation(rep_list, styles, story):
    story.append(Paragraph("IP Reputation", styles["h1"]))
    if not rep_list:
        story.append(Paragraph("No IP reputation data collected.", styles["body"]))
        return

    story.append(Spacer(1, 4 * mm))
    headers = ["IP Address", "Hostname", "Blacklisted", "Lists", "Abuse Score"]
    col_w = [28 * mm, 45 * mm, 20 * mm, 55 * mm, 22 * mm]
    tbl_data = [headers]
    ts = _tbl_style()

    for row_i, r in enumerate(rep_list, 1):
        bl_p = Paragraph("YES" if r.is_blacklisted else "NO",
                         ParagraphStyle("blp", fontSize=7,
                                        textColor=C_DANGER if r.is_blacklisted else C_ACCENT,
                                        fontName="Helvetica-Bold"))
        lists_str = ", ".join(r.blacklists or []) or "—"
        score = str(r.abuse_score) if r.abuse_score is not None else "—"
        tbl_data.append([
            _wrap(r.ip_address, styles["mono_sm"], 28),
            _wrap(r.hostname or "—", styles["mono_sm"], 45),
            bl_p,
            _wrap(lists_str, styles["body"], 55),
            score,
        ])
        if r.is_blacklisted:
            ts.add("BACKGROUND", (0, row_i), (-1, row_i), colors.HexColor("#ffe8ec"))

    tbl = Table(tbl_data, colWidths=col_w, repeatRows=1)
    tbl.setStyle(ts)
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))


# ── Section: DNS Security ─────────────────────────────────────────────────────

def _dns_security(dns_sec, styles, story):
    story.append(Paragraph("DNS Security (DNSSEC / CAA)", styles["h1"]))
    if not dns_sec:
        story.append(Paragraph("No DNS security data collected.", styles["body"]))
        return

    story.append(Spacer(1, 4 * mm))
    def yn(val):
        col = C_ACCENT if val else C_DANGER
        return Paragraph("YES" if val else "NO",
                         ParagraphStyle("yn2", fontSize=7, textColor=col,
                                        fontName="Helvetica-Bold"))

    rows = [
        ["DNSSEC Enabled",         yn(dns_sec.dnssec_enabled)],
        ["DNSSEC Valid",           yn(dns_sec.dnssec_valid)],
        ["CAA Record Present",     yn(dns_sec.has_caa)],
        ["CAA Issuers",            Paragraph(", ".join(dns_sec.caa_issuers or []) or "—",
                                             styles["body"])],
        ["Nameserver Count",       Paragraph(str(dns_sec.ns_count or "—"), styles["body"])],
        ["Issues",                 _wrap("; ".join(dns_sec.issues or []) or "None",
                                         styles["body"], 100)],
    ]

    tbl = Table(rows, colWidths=[45 * mm, 129 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), C_HEADER_ROW),
        ("TEXTCOLOR",  (0, 0), (0, -1), C_ACCENT),
        ("FONTNAME",   (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 7),
        ("TEXTCOLOR",  (1, 0), (1, -1), C_TEXT),
        ("FONTNAME",   (1, 0), (1, -1), "Helvetica"),
        ("GRID",       (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_ROW_ODD, C_ROW_EVEN]),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))


# ── Section: Geolocation ─────────────────────────────────────────────────────

def _geolocation(geo_list, styles, story):
    story.append(Paragraph("IP Geolocation", styles["h1"]))
    if not geo_list:
        story.append(Paragraph("No geolocation data collected.", styles["body"]))
        return

    story.append(Spacer(1, 4 * mm))
    headers = ["IP Address", "Hostname", "Country", "City", "ISP/Org", "Datacenter"]
    col_w = [28 * mm, 40 * mm, 22 * mm, 22 * mm, 40 * mm, 22 * mm]
    tbl_data = [headers]
    for r in geo_list:
        dc_p = Paragraph("YES" if r.is_hosting else "NO",
                         ParagraphStyle("dc", fontSize=7,
                                        textColor=C_WARNING if r.is_hosting else C_MUTED,
                                        fontName="Helvetica-Bold"))
        tbl_data.append([
            _wrap(r.ip_address, styles["mono_sm"], 28),
            _wrap(r.hostname or "—", styles["mono_sm"], 40),
            _wrap(r.country or "—", styles["body"], 22),
            _wrap(r.city or "—", styles["body"], 22),
            _wrap(r.isp or r.org or "—", styles["body"], 40),
            dc_p,
        ])

    tbl = Table(tbl_data, colWidths=col_w, repeatRows=1)
    tbl.setStyle(_tbl_style())
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))


# ── Section: WHOIS ────────────────────────────────────────────────────────────

def _whois(whois, styles, story):
    story.append(Paragraph("WHOIS Information", styles["h1"]))
    if not whois:
        story.append(Paragraph("No WHOIS data collected.", styles["body"]))
        return

    story.append(Spacer(1, 4 * mm))
    def fmt_date(d):
        if d is None:
            return "—"
        if isinstance(d, datetime):
            return d.strftime("%Y-%m-%d")
        return str(d)

    rows = [
        ["Registrar",     _wrap(whois.registrar or "—", styles["body"], 80)],
        ["Created",       Paragraph(fmt_date(whois.creation_date), styles["body"])],
        ["Expires",       Paragraph(fmt_date(whois.expiry_date), styles["body"])],
        ["Updated",       Paragraph(fmt_date(whois.updated_date), styles["body"])],
        ["Registrant",    _wrap(whois.registrant_name or "—", styles["body"], 80)],
        ["Org",           _wrap(whois.registrant_org or "—", styles["body"], 80)],
        ["Country",       Paragraph(whois.registrant_country or "—", styles["body"])],
        ["Name Servers",  _wrap(", ".join(whois.name_servers or []) or "—", styles["body"], 100)],
        ["Status",        _wrap(whois.status or "—", styles["body"], 100)],
        ["DNSSEC",        Paragraph(whois.dnssec or "—", styles["body"])],
    ]

    tbl = Table(rows, colWidths=[35 * mm, 139 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), C_HEADER_ROW),
        ("TEXTCOLOR",  (0, 0), (0, -1), C_ACCENT),
        ("FONTNAME",   (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 7),
        ("TEXTCOLOR",  (1, 0), (1, -1), C_TEXT),
        ("FONTNAME",   (1, 0), (1, -1), "Helvetica"),
        ("GRID",       (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_ROW_ODD, C_ROW_EVEN]),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 4 * mm))


# ── Section: Wayback ─────────────────────────────────────────────────────────

def _wayback(wayback_findings, styles, story):
    story.append(Paragraph("Historical Endpoints (Wayback Machine)", styles["h1"]))
    if not wayback_findings:
        story.append(Paragraph("No historical endpoints found.", styles["body"]))
        return

    story.append(Spacer(1, 4 * mm))

    # Group by category
    by_cat: dict = {}
    for w in wayback_findings:
        by_cat.setdefault(w.category or "other", []).append(w)

    for cat, entries in sorted(by_cat.items()):
        story.append(Paragraph(cat.upper(), styles["h2"]))
        story.append(Spacer(1, 3 * mm))
        headers = ["URL", "Status", "Last Seen"]
        col_w = [115 * mm, 20 * mm, 30 * mm]
        tbl_data = [headers]
        for e in entries[:30]:  # cap at 30 per category
            tbl_data.append([
                _wrap(e.url, styles["mono_sm"], 120),
                e.status_code or "—",
                e.last_seen or "—",
            ])
        tbl = Table(tbl_data, colWidths=col_w, repeatRows=1)
        tbl.setStyle(_tbl_style())
        story.append(tbl)
        story.append(Spacer(1, 2 * mm))

    story.append(Spacer(1, 3 * mm))


# ── Main PDF builder ──────────────────────────────────────────────────────────

async def _load_all_data(db: AsyncSession, scan_id: UUID):
    """Load everything needed for the report."""
    r = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = r.scalar_one_or_none()
    if not scan:
        return None, None

    sub_r = await db.execute(select(Subdomain).where(Subdomain.scan_id == scan_id))
    subdomains = sub_r.scalars().all()
    sub_ids = [s.id for s in subdomains]

    # Helper to load by subdomain_ids
    async def by_sub(model):
        if not sub_ids:
            return []
        res = await db.execute(select(model).where(model.subdomain_id.in_(sub_ids)))
        return res.scalars().all()

    async def by_scan(model):
        res = await db.execute(select(model).where(model.scan_id == scan_id))
        return res.scalars().all()

    ports = await by_sub(Port)
    techs = await by_sub(Technology)
    wafs  = await by_sub(WAFResult)
    headers_q = await by_sub(HeaderAnalysis)
    ssls  = await by_sub(SSLInfo)
    cors  = await by_sub(CORSResult)
    takeovers_q = await by_sub(SubdomainTakeover)

    dns_r = await db.execute(select(DNSRecord).where(DNSRecord.scan_id == scan_id)
                             .order_by(DNSRecord.record_type, DNSRecord.hostname))
    dns_records = dns_r.scalars().all()

    email_r = await db.execute(select(EmailSecurity).where(EmailSecurity.scan_id == scan_id))
    email_sec = email_r.scalar_one_or_none()

    whois_r = await db.execute(select(WhoisInfo).where(WhoisInfo.scan_id == scan_id))
    whois = whois_r.scalar_one_or_none()

    dns_sec_r = await db.execute(select(DNSSecurity).where(DNSSecurity.scan_id == scan_id))
    dns_sec = dns_sec_r.scalar_one_or_none()

    tech_ids = [t.id for t in techs]
    tech_map = {t.id: t for t in techs}
    cves_raw = []
    if tech_ids:
        cve_r = await db.execute(select(CVE).where(CVE.technology_id.in_(tech_ids)))
        cves_raw = cve_r.scalars().all()

    js_r = await db.execute(select(JSFinding).where(JSFinding.scan_id == scan_id))
    js_findings = js_r.scalars().all()

    dir_r = await db.execute(select(DirectoryFinding).where(DirectoryFinding.scan_id == scan_id))
    dir_findings = dir_r.scalars().all()

    rep_r = await db.execute(select(IPReputation).where(IPReputation.scan_id == scan_id))
    ip_rep = rep_r.scalars().all()

    wb_r = await db.execute(select(WaybackFinding).where(WaybackFinding.scan_id == scan_id))
    wayback = wb_r.scalars().all()

    geo_r = await db.execute(select(IPGeoLocation).where(IPGeoLocation.scan_id == scan_id))
    geo = geo_r.scalars().all()

    # Build lookup dicts keyed by subdomain_id
    ports_m    = {}
    techs_m    = {}
    wafs_m     = {}
    headers_m  = {}
    ssls_m     = {}

    for p in ports:
        ports_m.setdefault(p.subdomain_id, []).append(p)
    for t in techs:
        techs_m.setdefault(t.subdomain_id, []).append(t)
    for w in wafs:
        wafs_m[w.subdomain_id] = w
    for h in headers_q:
        headers_m[h.subdomain_id] = h
    for s in ssls:
        ssls_m[s.subdomain_id] = s

    # Convert subdomains to plain dicts (avoids SQLAlchemy DetachedInstanceError in executor)
    def _ssl_dict(si):
        if not si:
            return None
        return {
            "issuer": si.issuer, "subject": si.subject,
            "valid_from": si.valid_from, "valid_until": si.valid_until,
            "is_expired": si.is_expired, "san_domains": si.san_domains,
            "grade": si.grade, "protocols": si.protocols,
            "vulnerabilities": si.vulnerabilities,
        }

    def _ha_dict(ha):
        if not ha:
            return None
        return {
            "has_hsts": ha.has_hsts, "hsts_value": ha.hsts_value,
            "has_csp": ha.has_csp, "csp_value": ha.csp_value,
            "has_x_frame_options": ha.has_x_frame_options,
            "x_frame_options_value": ha.x_frame_options_value,
            "has_x_content_type_options": ha.has_x_content_type_options,
            "has_referrer_policy": ha.has_referrer_policy,
            "referrer_policy_value": ha.referrer_policy_value,
            "has_permissions_policy": ha.has_permissions_policy,
            "server_banner": ha.server_banner, "x_powered_by": ha.x_powered_by,
            "redirect_count": ha.redirect_count, "final_url": ha.final_url,
            "security_score": ha.security_score, "missing_headers": ha.missing_headers,
        }

    from types import SimpleNamespace

    def _ns(d):
        """Recursively convert dict to SimpleNamespace for attribute access."""
        if isinstance(d, dict):
            return SimpleNamespace(**{k: _ns(v) for k, v in d.items()})
        if isinstance(d, list):
            return [_ns(i) for i in d]
        return d

    subdomain_dicts = []
    for sub in subdomains:
        waf = wafs_m.get(sub.id)
        sub_ports = [
            {"port_number": p.port_number, "protocol": p.protocol,
             "service": p.service, "version": p.version, "banner": p.banner}
            for p in ports_m.get(sub.id, [])
        ]
        sub_techs = [
            {"name": t.name, "version": t.version, "category": t.category}
            for t in techs_m.get(sub.id, [])
        ]
        subdomain_dicts.append({
            "id": str(sub.id),
            "hostname": sub.hostname,
            "ip_address": sub.ip_address,
            "is_alive": sub.is_alive,
            "http_status": sub.http_status,
            "page_title": sub.page_title,
            "source": sub.source,
            "reverse_hostname": getattr(sub, "reverse_hostname", None),
            "waf_detected": waf.detected if waf else None,
            "waf_name": waf.waf_name if waf else None,
            "ports": sub_ports,
            "technologies": sub_techs,
            "header_analysis": _ha_dict(headers_m.get(sub.id)),
            "ssl_info": _ssl_dict(ssls_m.get(sub.id)),
        })
    subdomains_ns = [_ns(d) for d in subdomain_dicts]

    # Build CVE list with tech metadata
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    seen_cve: set = set()
    cves_list = []
    for cve in sorted(cves_raw, key=lambda c: SEV_ORDER.get(
            (c.severity.value if c.severity else "info"), 5)):
        t = tech_map.get(cve.technology_id)
        if not t:
            continue
        key = (cve.cve_id, t.name.lower())
        if key in seen_cve:
            continue
        seen_cve.add(key)
        cves_list.append({
            "cve_id": cve.cve_id,
            "severity": cve.severity.value if cve.severity else None,
            "cvss_score": cve.cvss_score,
            "description": cve.description,
            "technology_name": t.name,
            "technology_version": t.version,
        })

    # Filter takeovers to vulnerable only — resolve hostname via subdomain_id
    sub_hostname_map = {s.id: s.hostname for s in subdomains}
    takeovers_list = [
        {
            "hostname": sub_hostname_map.get(t.subdomain_id, "unknown"),
            "service": t.service,
            "cname_target": t.cname_target,
            "fingerprint": t.fingerprint,
            "severity": t.severity.value if t.severity else "high",
        }
        for t in takeovers_q if t.is_vulnerable
    ]

    # cors_results — convert to dicts with string severity
    cors_list = [
        {
            "hostname": c.hostname or "",
            "is_vulnerable": c.is_vulnerable,
            "misconfig_type": c.misconfig_type,
            "allowed_origin": c.allowed_origin,
            "allow_credentials": c.allow_credentials,
            "severity": c.severity.value if c.severity else "high",
        }
        for c in cors if c.is_vulnerable
    ]

    # Convert scan to plain dict
    scan_dict = {
        "id": str(scan.id), "domain": scan.domain,
        "status": scan.status.value if hasattr(scan.status, "value") else scan.status,
        "risk_score": scan.risk_score,
        "started_at": scan.started_at, "completed_at": scan.completed_at,
        "created_at": scan.created_at,
        "zone_transfer_successful": scan.zone_transfer_successful,
    }

    # Convert dns_records to plain dicts
    dns_dicts = [
        {"record_type": r.record_type, "hostname": r.hostname,
         "value": r.value, "ttl": r.ttl}
        for r in dns_records
    ]

    # Convert email_security to plain dict
    email_dict = None
    if email_sec:
        email_dict = {
            "spf_record": email_sec.spf_record, "spf_valid": email_sec.spf_valid,
            "spf_mechanism": getattr(email_sec, "spf_mechanism", None),
            "dkim_found": email_sec.dkim_found, "dkim_selector": email_sec.dkim_selector,
            "dmarc_record": email_sec.dmarc_record, "dmarc_policy": email_sec.dmarc_policy,
            "dmarc_pct": getattr(email_sec, "dmarc_pct", None),
            "mta_sts_mode": getattr(email_sec, "mta_sts_mode", None),
            "is_spoofable": email_sec.is_spoofable,
        }

    # Convert whois to plain dict
    whois_dict = None
    if whois:
        whois_dict = {
            "registrar": whois.registrar, "creation_date": whois.creation_date,
            "expiry_date": whois.expiry_date, "updated_date": whois.updated_date,
            "registrant_name": whois.registrant_name, "registrant_org": whois.registrant_org,
            "registrant_email": getattr(whois, "registrant_email", None),
            "registrant_country": whois.registrant_country,
            "name_servers": whois.name_servers, "status": whois.status,
            "dnssec": whois.dnssec,
        }

    # Convert dns_security to plain dict
    dns_sec_dict = None
    if dns_sec:
        dns_sec_dict = {
            "dnssec_enabled": dns_sec.dnssec_enabled, "dnssec_valid": dns_sec.dnssec_valid,
            "has_caa": dns_sec.has_caa, "caa_issuers": dns_sec.caa_issuers,
            "caa_wildcard_issuers": dns_sec.caa_wildcard_issuers,
            "ns_count": dns_sec.ns_count, "issues": dns_sec.issues,
        }

    # Convert js_findings to plain dicts
    js_dicts = [
        {"subdomain_hostname": j.subdomain_hostname, "js_url": j.js_url,
         "endpoints": j.endpoints, "secrets": j.secrets,
         "endpoint_count": j.endpoint_count or 0, "secret_count": j.secret_count or 0}
        for j in js_findings
    ]

    # Convert dir_findings to plain dicts
    dir_dicts = [
        {"subdomain_hostname": d.subdomain_hostname, "path": d.path,
         "status_code": d.status_code, "content_length": d.content_length,
         "finding_type": d.finding_type,
         "severity": d.severity.value if d.severity else "low"}
        for d in dir_findings
    ]

    # Convert ip_reputation to plain dicts
    rep_dicts = [
        {"ip_address": r.ip_address, "hostname": r.hostname,
         "is_blacklisted": r.is_blacklisted, "blacklists": r.blacklists,
         "threat_type": r.threat_type, "urlhaus_status": r.urlhaus_status,
         "urlhaus_tags": r.urlhaus_tags, "abuse_score": r.abuse_score}
        for r in ip_rep
    ]

    # Convert wayback to plain dicts
    wb_dicts = [
        {"url": w.url, "status_code": w.status_code, "mime_type": w.mime_type,
         "last_seen": w.last_seen, "category": w.category}
        for w in wayback
    ]

    # Convert geo to plain dicts
    geo_dicts = [
        {"ip_address": g.ip_address, "hostname": g.hostname, "country": g.country,
         "country_code": g.country_code, "region": g.region, "city": g.city,
         "isp": g.isp, "org": g.org, "asn": g.asn, "is_hosting": g.is_hosting}
        for g in geo
    ]

    return _ns(scan_dict), {
        "subdomains":        subdomains_ns,
        "dns_records":       [_ns(d) for d in dns_dicts],
        "email_security":    _ns(email_dict) if email_dict else None,
        "whois_info":        _ns(whois_dict) if whois_dict else None,
        "dns_security":      _ns(dns_sec_dict) if dns_sec_dict else None,
        "cves":              cves_list,
        "takeovers":         takeovers_list,
        "cors_results":      cors_list,
        "js_findings":       [_ns(d) for d in js_dicts],
        "dir_findings":      [_ns(d) for d in dir_dicts],
        "ip_reputation":     [_ns(d) for d in rep_dicts],
        "wayback_findings":  [_ns(d) for d in wb_dicts],
        "geo_locations":     [_ns(d) for d in geo_dicts],
        "zone_transfer_successful": scan.zone_transfer_successful,
    }


def _build_pdf(scan, data: dict) -> bytes:
    buf = io.BytesIO()
    styles = _styles()

    scan_date = (scan.completed_at or scan.created_at).strftime("%Y-%m-%d %H:%M UTC") \
        if (scan.completed_at or scan.created_at) else "—"

    doc = BaseDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
    )
    doc.addPageTemplates([_build_page_template(scan.domain, scan_date)])

    story = []

    # 1. Cover
    _cover(scan, styles, story)

    # 2. Critical Action Items (always first section after cover)
    _critical_actions(data, styles, story)
    story.append(PageBreak())

    # 3. DNS Records
    _dns_records(data["dns_records"], styles, story)
    story.append(PageBreak())

    # 4. Subdomains
    _subdomains(data["subdomains"], styles, story)
    story.append(PageBreak())

    # 5. Open Ports
    _open_ports(data["subdomains"], styles, story)
    story.append(PageBreak())

    # 6. Technologies
    _technologies(data["subdomains"], styles, story)
    story.append(PageBreak())

    # 7. CVEs
    _cves(data["cves"], styles, story)
    story.append(PageBreak())

    # 8. Email Security
    _email_security(data["email_security"], styles, story)

    # 9. SSL/TLS
    _ssl_tls(data["subdomains"], styles, story)
    story.append(PageBreak())

    # 10. CORS
    _cors(data["cors_results"], styles, story)

    # 11. Directory Findings
    _directory_findings(data["dir_findings"], styles, story)
    story.append(PageBreak())

    # 12. JS Secrets
    _js_findings(data["js_findings"], styles, story)

    # 13. Subdomain Takeovers
    _takeovers(data["takeovers"], styles, story)
    story.append(PageBreak())

    # 14. IP Reputation
    _ip_reputation(data["ip_reputation"], styles, story)

    # 15. DNS Security
    _dns_security(data["dns_security"], styles, story)
    story.append(PageBreak())

    # 16. Geolocation
    _geolocation(data["geo_locations"], styles, story)

    # 17. WHOIS
    _whois(data["whois_info"], styles, story)
    story.append(PageBreak())

    # 18. Wayback
    _wayback(data["wayback_findings"], styles, story)

    doc.build(story)
    buf.seek(0)
    return buf.read()


# ── API Endpoint ──────────────────────────────────────────────────────────────

@router.get("/{scan_id}/report")
async def download_report(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Generate and download a PDF report for a completed scan."""
    import asyncio
    import logging
    logger = logging.getLogger(__name__)

    scan, data = await _load_all_data(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in ("completed", "failed"):
        raise HTTPException(
            status_code=400,
            detail="Report is only available for completed or failed scans.",
        )

    try:
        # Run synchronously — all data is plain Python objects, no SQLAlchemy session needed
        pdf_bytes = _build_pdf(scan, data)
    except Exception as e:
        logger.error(f"PDF generation failed for scan {scan_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    filename = f"shodh-report-{scan.domain}-{scan_id}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
