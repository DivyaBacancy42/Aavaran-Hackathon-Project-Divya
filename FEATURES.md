# SHODH — Complete Feature List (45 Features)

Implementation order: top to bottom. Each feature is independent.

## Status Legend
- ✅ DONE — Implemented and working
- 🔨 IN PROGRESS — Code ready, needs applying
- ⏳ PENDING — Not started

---

| # | Feature | What It Does | Status |
|---|---|---|---|
| 1 | Domain Input | User enters a single domain name (e.g. example.com) — only input needed to start everything | ✅ DONE |
| 2 | DNS Zone Transfer Check | Attempts `dig axfr` on target's nameservers — if successful, grabs all records instantly | 🔨 IN PROGRESS |
| 3 | Subdomain Discovery | Finds all subdomains using passive sources — certificate transparency logs (crt.sh), search engines, public DNS datasets, archived URLs | ⏳ PENDING |
| 4 | DNS Record Extraction | Pulls A, AAAA, MX, NS, TXT, CNAME, SOA records for the domain and every discovered subdomain | 🔨 IN PROGRESS |
| 5 | Alive/Dead Check | Resolves every discovered subdomain to check which ones are actually live and responding | ⏳ PENDING |
| 6 | IP Resolution & Mapping | Maps every alive subdomain to its IP address, groups subdomains sharing the same IP (virtual hosts) | ⏳ PENDING |
| 7 | Reverse DNS Lookup | Takes discovered IPs and finds other domains/subdomains hosted on the same IP | ⏳ PENDING |
| 8 | ASN & IP Range Discovery | Identifies the company's Autonomous System Number and all IP ranges they own | ⏳ PENDING |
| 9 | WHOIS Lookup | Fetches registrar, creation date, expiry date, registrant info for the domain | ⏳ PENDING |
| 10 | Port Scanning | Scans every discovered IP for open ports (top 1000 or full 65535 based on user choice) | ⏳ PENDING |
| 11 | Service Detection | Identifies what service is running on each open port (HTTP, SSH, FTP, MySQL, RDP, etc.) and its version | ⏳ PENDING |
| 12 | WAF/CDN Detection | Sends crafted HTTP requests to each subdomain and fingerprints which WAF or CDN is protecting it (Cloudflare, AWS WAF, Akamai, etc.) | ⏳ PENDING |
| 13 | Unprotected Asset Flagging | Compares WAF results across all subdomains — flags any subdomain that has NO WAF while others do | ⏳ PENDING |
| 14 | Technology Fingerprinting | Detects tech stack on each subdomain — CMS, framework, server, language, analytics, payment systems with version numbers | ⏳ PENDING |
| 15 | HTTP Header Analysis | Extracts and analyzes response headers — server type, security headers (HSTS, CSP, X-Frame-Options), cookies, redirects | ⏳ PENDING |
| 16 | SSL/TLS Certificate Analysis | Inspects certificate issuer, expiry date, SAN fields, certificate chain, wildcard usage for each subdomain | ⏳ PENDING |
| 17 | SSL/TLS Security Grading | Tests cipher suites, protocol versions (TLS 1.0/1.1/1.2/1.3), known vulnerabilities (Heartbleed, POODLE, etc.) and assigns A-F grade | ⏳ PENDING |
| 18 | SPF Record Check | Parses SPF TXT record — checks if it's configured, too permissive, or missing | ⏳ PENDING |
| 19 | DKIM Record Check | Checks for DKIM DNS records — verifies email authentication is set up | ⏳ PENDING |
| 20 | DMARC Record Check | Checks DMARC policy — is it set to none/quarantine/reject, is the domain spoofable | ⏳ PENDING |
| 21 | Email Spoofing Verdict | Combines SPF + DKIM + DMARC results into a simple YES/NO — "Can someone spoof emails from this domain?" | ⏳ PENDING |
| 22 | Cloud Bucket Discovery | Generates permutations of company/domain name and checks if matching S3, Azure Blob, or GCS buckets exist | ⏳ PENDING |
| 23 | Bucket Permission Check | For each discovered bucket — tests if it's publicly readable, writable, or listable | ⏳ PENDING |
| 24 | CVE Lookup | Takes every detected technology + version and queries vulnerability databases for known CVEs | ⏳ PENDING |
| 25 | CVE Severity Scoring | Returns CVSS score, EPSS exploitation probability, and CISA KEV status for each CVE | ⏳ PENDING |
| 26 | Subdomain Takeover Detection | Checks if any subdomain has a dangling CNAME pointing to a decommissioned service (GitHub Pages, Heroku, S3, etc.) | ⏳ PENDING |
| 27 | Email Breach Lookup | Checks if the domain's email addresses appear in known data breaches — returns breach names and dates | ⏳ PENDING |
| 28 | GitHub Dorking | Searches public GitHub repos for the company's domain/org name — finds exposed config files, .env files, hardcoded secrets | ⏳ PENDING |
| 29 | Secret Detection | Scans any discovered GitHub repos for leaked API keys, database passwords, private keys — verifies if still active | ⏳ PENDING |
| 30 | Historical URL Discovery | Pulls all archived URLs from Wayback Machine and Common Crawl — finds old admin panels, forgotten endpoints, legacy APIs | ⏳ PENDING |
| 31 | Screenshot Capture | Takes headless browser screenshots of every alive web subdomain — generates thumbnail gallery | ⏳ PENDING |
| 32 | Reputation Check | Checks domain and IPs against threat intelligence feeds — flags if any are marked malicious by security vendors | ⏳ PENDING |
| 33 | AI Risk Narrative | Feeds all scan results into local LLM — generates human-readable security assessment with prioritized findings | ⏳ PENDING |
| 34 | Risk Score Calculation | Calculates an overall risk score (0-100) based on weighted findings — critical CVEs, open buckets, missing WAF, breached emails, etc. | ⏳ PENDING |
| 35 | 3D Constellation Map | Renders all discovered assets as interactive nodes in a force-directed 3D graph — color-coded by risk, clickable for details | ⏳ PENDING |
| 36 | Asset Detail Panel | Click any node on the map — side panel shows full details (ports, tech, CVEs, headers, certificate info) | ⏳ PENDING |
| 37 | Filter & Layer Toggle | Toggle visibility by category — show only critical findings, only subdomains, only ports, only unprotected assets | ⏳ PENDING |
| 38 | Company Comparison Mode | Scan two domains side-by-side — compare subdomain count, WAF coverage, CVE count, breach exposure, overall risk score | ⏳ PENDING |
| 39 | PDF/HTML Report Export | One-click export of full scan results — executive summary + technical detail + remediation recommendations | ⏳ PENDING |
| 40 | Scheduled Re-scanning | Set cron-based automatic re-scans (daily/weekly/monthly) — tracks changes over time | ⏳ PENDING |
| 41 | Change Detection & Alerts | Compares current scan with previous — detects new subdomains, new open ports, expired certificates, new CVEs | ⏳ PENDING |
| 42 | Alert Notifications | Sends alerts on changes via email, Slack webhook, Discord webhook, or Telegram bot | ⏳ PENDING |
| 43 | Scan History & Timeline | Stores every scan result — shows security posture trend over time as a graph | ⏳ PENDING |
| 44 | API Key Manager | Dashboard to add/remove optional API keys (Shodan, SecurityTrails, HIBP, VirusTotal) — tool works with zero keys by default | ⏳ PENDING |
| 45 | Docker One-Command Deploy | Entire platform launches with single `docker-compose up` — no manual setup, no dependency hell | ⏳ PENDING |