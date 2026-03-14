import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import {
  Globe, Activity, Lock, AlertTriangle, Server, Eye,
  ShieldCheck, Network, FileSearch, Shield, Search,
  Wifi, Database, Bug, ArrowLeft, Radar,
  GitBranch, Mail, MapPin, Star, Zap, Code, Key,
  Hash, TrendingUp, BookOpen,
} from "lucide-react";
import MarsBackground from "../components/MarsBackground";

// ── Feature data ──────────────────────────────────────────────────────────────

const CATEGORIES = [
  {
    id: "recon",
    label: "Reconnaissance",
    color: "shodh-accent",
    colorHex: "#00ff88",
    tagline: "Map the target before you touch it",
    features: [
      {
        icon: Globe,
        name: "Subdomain Discovery",
        badge: "Feature #3",
        what: "Queries Certificate Transparency logs (crt.sh) for every SSL certificate ever issued for the domain, then runs a DNS brute-force against a curated wordlist to confirm live hosts.",
        why: "Subdomains are the #1 forgotten attack surface. A forgotten staging.company.com or old-api.company.com exposes the same data as the main site with far less protection.",
        detail: "Uses crt.sh wildcard search → DNS A/AAAA resolution → alive check. Deduplicates across both sources. Runs fully asynchronously — 100 subdomains checked in under 10 seconds.",
      },
      {
        icon: Hash,
        name: "DNS Record Extraction",
        badge: "Feature #4",
        what: "Fetches all DNS record types — A, AAAA, CNAME, MX, NS, TXT, SOA — for the root domain and discovered subdomains.",
        why: "DNS records reveal IP addresses, mail servers, third-party services (Cloudflare, SendGrid, Slack), and often internal infrastructure details leaked in TXT records.",
        detail: "Uses dnspython for async DNS resolution. Follows CNAME chains. Detects dangling CNAMEs (key input for takeover scanning). All records stored and surfaced in the UI.",
      },
      {
        icon: GitBranch,
        name: "DNS Zone Transfer (AXFR)",
        badge: "Feature #2",
        what: "Attempts a full DNS zone transfer against every authoritative nameserver. A successful transfer dumps the complete internal DNS map of the organisation.",
        why: "Zone transfers are a critical misconfiguration. If exposed, the attacker gets every hostname, internal IP, and service in seconds — equivalent to the target's internal network map.",
        detail: "Tries AXFR against each NS record. Flags zone_transfer_successful on the scan. Results are shown as a critical finding. Most modern DNS servers block this — but many don't.",
      },
      {
        icon: Server,
        name: "WHOIS Lookup",
        badge: "Feature #9",
        what: "Performs WHOIS/RDAP registration lookup to reveal the domain's registrar, creation date, expiry date, registrant organisation, and name servers.",
        why: "Expiry dates predict domain hijacking windows. Registrant data identifies the real organisation behind an anonymous domain. Old creation dates indicate legacy infrastructure.",
        detail: "RDAP-first (HTTP/JSON, structured data). Falls back to python-whois port-43, then to system whois CLI. Stores registrar, creation date, expiry date, org, and emails.",
      },
      {
        icon: Network,
        name: "ASN & IP Range Discovery",
        badge: "Feature #8",
        what: "Resolves all discovered IP addresses to their Autonomous System Number (ASN), organisation name, and CIDR prefix via Team Cymru's Whois service.",
        why: "ASN data reveals which cloud provider or ISP the target uses. Knowing the CIDR block means finding adjacent assets and understanding the full IP footprint.",
        detail: "Batch queries Team Cymru (whois.cymru.com) over TCP. Maps each IP → ASN number, AS name, and prefix. Groups results by ASN in the UI for quick overview.",
      },
      {
        icon: Radar,
        name: "Reverse DNS / PTR Lookup",
        badge: "Feature #7",
        what: "For every discovered IP address, performs a reverse DNS (PTR) lookup to find the hostname the server operator configured — often revealing internal naming conventions.",
        why: "PTR records expose internal hostnames like prod-db-1.internal.company.com even when the service isn't publicly listed. Useful for mapping server roles and naming schemes.",
        detail: "Async batch PTR lookups via dnspython. CDN IPs (Cloudflare, CloudFront, Fastly, Akamai CIDRs) are filtered to avoid noise. Results merged into subdomain records.",
      },
      {
        icon: Eye,
        name: "Historical Endpoint Discovery",
        badge: "Wayback Machine",
        what: "Queries the Wayback Machine CDX API for every URL ever crawled under the target domain. Filters for endpoints that returned HTTP 200 at some point in history.",
        why: "Developers delete pages without removing the underlying routes. Forgotten /admin, /api/v1, /.git, and /backup paths remain accessible long after they're removed from navigation.",
        detail: "Searches *.domain with limit 500, status filter 200. Classifies URLs into categories: api, admin, config, backup, auth, debug, upload. Surfaces the highest-risk paths first.",
      },
    ],
  },
  {
    id: "infrastructure",
    label: "Infrastructure Analysis",
    color: "shodh-info",
    colorHex: "#00aaff",
    tagline: "X-ray every service running on the target",
    features: [
      {
        icon: Activity,
        name: "Port & Service Scanning",
        badge: "Feature #10",
        what: "Async TCP connect scan across 70+ ports. Grabs service banners and extracts version strings for SSH, FTP, SMTP, HTTP, Redis, Elasticsearch, and more.",
        why: "Every open port is an attack surface. Redis on port 6379 with no auth, Elasticsearch on 9200 exposed to the internet, or Docker API on 2375 — all critical findings.",
        detail: "asyncio.open_connection with 1.5s timeout, Semaphore(40). TLS ports use ssl.create_default_context. Extracts versions via 7 regex patterns. Covers databases, queues, K8s, monitoring, proxies.",
      },
      {
        icon: Wifi,
        name: "Alive Host Detection",
        badge: "Feature #5",
        what: "HTTP/HTTPS probe for every discovered subdomain. Follows redirects, records final URL, status code, and response time.",
        why: "Not every discovered subdomain is actually live. Filtering to alive hosts prevents wasting scan time and gives accurate results for all downstream scanners.",
        detail: "httpx async client, tries HTTPS first then HTTP. Follows up to 10 redirects. Records is_alive=True for 2xx/3xx/4xx responses (a 403 means something is there). 8s timeout.",
      },
      {
        icon: Lock,
        name: "SSL/TLS Certificate Analysis",
        badge: "Feature #16",
        what: "Fetches and parses the TLS certificate for every HTTPS endpoint. Extracts issuer, subject, SANs, expiry date, validity period, and flags self-signed or wildcard certs.",
        why: "Expired certs cause browser warnings and broken trust chains. Self-signed certs on production indicate poor security hygiene. SANs reveal additional hostnames on the same IP.",
        detail: "asyncio.to_thread wrapping sync SSL socket + cryptography library. Semaphore(5). Parses x509 certificate fields. Extracts up to 50 Subject Alternative Names. Checks validity window.",
      },
      {
        icon: Lock,
        name: "SSL/TLS Security Grading",
        badge: "Feature #17",
        what: "Tests actual TLS protocol support — TLS 1.0, 1.1, 1.2, 1.3 — and scores the configuration from A+ down to F. Identifies BEAST and weak-protocol vulnerabilities.",
        why: "TLS 1.0 and 1.1 are deprecated and vulnerable to POODLE, BEAST, and BEAST-like attacks. PCI DSS and HIPAA prohibit them. A site supporting TLS 1.0 has a compliance failure.",
        detail: "Attempts connection with each ssl.TLSVersion enum. Grading: A+(TLS1.3 only) → A(1.3+1.2) → B(1.1 allowed) → C(1.0 allowed) → D(no 1.2/1.3) → F(expired/self-signed).",
      },
      {
        icon: FileSearch,
        name: "HTTP Header Security Analysis",
        badge: "Feature #15",
        what: "Checks for the presence and correct configuration of 6 critical security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.",
        why: "Missing security headers enable XSS, clickjacking, MIME-sniffing, and information leakage. They're trivially fixable with a one-line server config change — yet remain absent on most sites.",
        detail: "httpx probe per alive subdomain. Semaphore(10). Scores each header HIGH(30pts), MEDIUM(15pts), LOW(5pts). Security score 0–100. Shows which headers are present, missing, and misconfigured.",
      },
    ],
  },
  {
    id: "fingerprint",
    label: "Technology Fingerprinting",
    color: "shodh-purple",
    colorHex: "#8855ff",
    tagline: "Identify every tool in the target stack",
    features: [
      {
        icon: Search,
        name: "Web Technology Detection",
        badge: "Feature #11 / #14",
        what: "Detects the complete technology stack from HTTP headers, cookies, and HTML — frameworks, CMS, analytics, CDN, payment processors, and monitoring tools.",
        why: "Knowing the stack tells you which CVEs apply. WordPress 5.9 with WooCommerce means you check specific plugin CVEs. Laravel with a known version means specific deserialization bugs.",
        detail: "Primary: Wappalyzer fingerprint database (7,500+ signatures) downloaded and cached. Fallback: built-in regex patterns with CDN URL version extraction. Resolves technology implies chains (WooCommerce → WordPress → PHP).",
      },
      {
        icon: Shield,
        name: "WAF / CDN Detection",
        badge: "Feature #12",
        what: "Identifies Web Application Firewalls and Content Delivery Networks protecting the target using wafw00f — the industry-standard WAF fingerprinting tool.",
        why: "A WAF changes the attack strategy entirely. Payloads that work against an unprotected target get blocked. Knowing the WAF type lets red teamers select bypass techniques.",
        detail: "Calls wafw00f identwaf() per alive subdomain. Parses 'Name (Manufacturer)' format. Returns waf_name and manufacturer. Results stored per subdomain. Integrated with unprotected asset flagging.",
      },
      {
        icon: AlertTriangle,
        name: "Unprotected Asset Flagging",
        badge: "Feature #13",
        what: "Highlights alive subdomains that have no WAF or CDN protection — direct exposure to the internet with no filtering layer between the attacker and the application.",
        why: "An unprotected subdomain is the highest-priority target. No WAF means SQLi, XSS, and brute-force attacks land directly on the application. Often forgotten staging or internal services.",
        detail: "Computed from WAF results in the frontend. If anyWafDetected is true for the scan but a specific subdomain has waf_detected=false, it's flagged as unprotected in the UI with a red border alert.",
      },
    ],
  },
  {
    id: "vulnerabilities",
    label: "Vulnerability Intelligence",
    color: "shodh-danger",
    colorHex: "#ff3355",
    tagline: "Find the CVEs before attackers do",
    features: [
      {
        icon: Bug,
        name: "CVE Lookup via OSV.dev",
        badge: "Feature #24 / #25",
        what: "Queries the OSV (Open Source Vulnerabilities) database for known CVEs in every detected technology. Works with or without a version number — unlike NVD, OSV has built-in version range filtering.",
        why: "A detected library with known critical CVEs is an immediate action item. jQuery 3.5.1 has CVE-2020-11023 (XSS). Log4j 2.14.1 is Log4Shell. OSV returns only CVEs that actually affect the installed version.",
        detail: "81 technology → (package, ecosystem) mappings across npm, PyPI, Packagist, RubyGems, Go, Maven, and Debian ecosystems. No rate limits. Concurrent queries. Version-less queries filtered to CRITICAL/HIGH only to reduce noise.",
      },
      {
        icon: GitBranch,
        name: "Subdomain Takeover Detection",
        badge: "Feature #26",
        what: "Detects dangling DNS records pointing to decommissioned cloud services — where an attacker can register the same resource and serve malicious content on your subdomain.",
        why: "Subdomain takeovers are trivial to exploit. A CNAME to an unclaimed S3 bucket or Heroku app lets attackers serve phishing pages under your brand, steal cookies, and bypass CSP.",
        detail: "Resolves CNAME chains via dnspython. Checks HTTP body against 20+ cloud provider fingerprints (AWS S3, Heroku, GitHub Pages, Netlify, Vercel, Azure, Fastly, etc.). Unique per subdomain with severity scoring.",
      },
      {
        icon: Code,
        name: "CORS Misconfiguration Scanner",
        badge: "CORS Scanner",
        what: "Tests each subdomain for dangerous CORS configurations — wildcard origins, arbitrary origin reflection, and null origin acceptance — all of which allow cross-site data theft.",
        why: "A CORS misconfiguration on an API endpoint lets any website read authenticated API responses on behalf of a logged-in user. It's the equivalent of disabling the browser's same-origin policy.",
        detail: "Sends two probes per subdomain: Origin: https://evil.attacker.com and Origin: null. Checks Access-Control-Allow-Origin reflection and ACAO: * with credentials. Severity: critical/high/medium.",
      },
      {
        icon: Key,
        name: "JavaScript Secret Scanner",
        badge: "JS Scanner",
        what: "Crawls all JavaScript files loaded by each alive subdomain. Extracts hardcoded API keys, tokens, and secrets using pattern matching — AWS keys, GitHub tokens, Stripe keys, JWTs, and more.",
        why: "Developers accidentally commit API keys to JS bundles shipped to browsers. A hardcoded AWS_ACCESS_KEY_ID in a production JS file gives an attacker full cloud access. Extremely common.",
        detail: "Crawls same-origin JS files via regex on script src. Extracts secrets matching 8 pattern categories. Secrets are masked in storage (first 6 chars + ***). Stores endpoint paths extracted from JS for further recon.",
      },
      {
        icon: FileSearch,
        name: "Directory Discovery",
        badge: "Dir Scanner",
        what: "Probes 120 common sensitive paths on every alive subdomain — /.env, /.git/HEAD, /admin, /phpmyadmin, /wp-admin, /api/v1, /backup.zip, and many more.",
        why: "Exposed .env files contain database passwords and API keys. Accessible .git directories allow source code reconstruction. These are top-10 OWASP findings and trivially exploitable.",
        detail: "120-path built-in wordlist. Async httpx with Semaphore(20). Classifies findings as critical (secret files), high (admin panels), medium (API docs), or low (config paths). Only 200/403 responses flagged.",
      },
      {
        icon: Server,
        name: "DNS Security (DNSSEC + CAA)",
        badge: "DNS Security",
        what: "Checks DNSSEC validation status (DNSKEY records + AD flag), CAA (Certification Authority Authorization) records that restrict which CAs can issue certs, and nameserver count for redundancy.",
        why: "Without DNSSEC, DNS responses can be spoofed (DNS cache poisoning). Without CAA records, any CA can issue a cert for your domain — enabling MITM attacks with a valid cert.",
        detail: "Queries DNSKEY via 8.8.8.8 UDP with want_dnssec=True. Checks AD flag in response. Reads CAA issue/issuewild tags. Counts NS records for redundancy analysis. Stores all results per scan.",
      },
    ],
  },
  {
    id: "email",
    label: "Email Security",
    color: "shodh-warning",
    colorHex: "#ffaa00",
    tagline: "Stop spoofing and phishing at the DNS layer",
    features: [
      {
        icon: Mail,
        name: "SPF Analysis",
        badge: "Feature #6",
        what: "Parses the SPF (Sender Policy Framework) TXT record to determine which mail servers are authorised to send email on behalf of the domain — and how strictly violations are enforced.",
        why: "A missing SPF record means anyone can spoof email from your domain. A soft-fail (~all) means violations are logged but not rejected. Only hard-fail (-all) actually blocks spoofed email.",
        detail: "Parses mechanism: hard_fail (-all), soft_fail (~all), neutral (?all), or open (no ~all). Stored as spf_mechanism. Warning shown for soft_fail and open configurations.",
      },
      {
        icon: ShieldCheck,
        name: "DKIM Verification",
        badge: "Feature #6",
        what: "Checks for the presence of DKIM (DomainKeys Identified Mail) DNS records, which cryptographically sign outgoing email to prove it hasn't been tampered with in transit.",
        why: "DKIM prevents email body tampering and header forgery. Without DKIM, phishing emails impersonating your domain pass basic authentication checks and reach inboxes.",
        detail: "Queries TXT records for common DKIM selectors (default._domainkey, google._domainkey, mail._domainkey). Stores dkim_enabled boolean. Lists selectors found.",
      },
      {
        icon: Shield,
        name: "DMARC Policy Analysis",
        badge: "Feature #6",
        what: "Reads the DMARC (_dmarc) TXT record to check the policy for SPF/DKIM failures — none (reporting only), quarantine (spam folder), or reject (block the email).",
        why: "DMARC ties SPF and DKIM together. p=none means all spoofed emails are delivered. p=reject with pct=100 is the gold standard — it completely blocks email spoofing for the domain.",
        detail: "Parses p= tag (none/quarantine/reject), pct= tag (percentage enforced, default 100). Low pct values get a warning. MTA-STS mode also checked from v=STSv1 mode= tag.",
      },
    ],
  },
  {
    id: "threat",
    label: "Threat Intelligence",
    color: "shodh-accent",
    colorHex: "#00ff88",
    tagline: "Cross-reference against known threat actor infrastructure",
    features: [
      {
        icon: Radar,
        name: "AlienVault OTX Correlation",
        badge: "Feature #9 (OTX)",
        what: "Checks the domain against the AlienVault Open Threat Exchange — a global threat intelligence feed contributed to by security researchers and organisations worldwide.",
        why: "If a domain appears in threat actor reports, malware campaigns, or C2 infrastructure databases, it's a serious red flag even if the site looks clean. OTX has data on millions of malicious domains.",
        detail: "Queries the OTX public API (no key required). Returns pulse count, threat types, malware families, adversary names. pulse_count > 0 sets is_known_malicious=True. Shows threat tags and actor names in UI.",
      },
      {
        icon: Database,
        name: "IP Reputation & Blacklist Check",
        badge: "Feature #32",
        what: "Checks every discovered IP against DNSBL blacklists (Spamhaus ZEN, SpamCop, SORBS) and the URLhaus malware database to detect IPs hosting spam or malware.",
        why: "An IP on Spamhaus ZEN will have email blocked by most providers. An IP in URLhaus hosts active malware payloads. These directly impact deliverability and brand trust.",
        detail: "DNSBL checked via reversed-IP DNS query (asyncio.to_thread). URLhaus checked via async POST to abuse.ch API. Private IPs skipped. Results grouped by blacklist. Unique per scan, ordered by severity.",
      },
      {
        icon: MapPin,
        name: "IP Geolocation & Hosting Detection",
        badge: "Feature (Geo)",
        what: "Geolocates every discovered IP to country, region, city, ISP, ASN, and organisation name. Flags whether the IP is a known datacenter/hosting provider vs a residential connection.",
        why: "Geolocation reveals where infrastructure is hosted and whether it's in a high-risk jurisdiction. Datacenter IPs suggest VPS/cloud hosting. Residential IPs may indicate compromised machines used as proxies.",
        detail: "ip-api.com batch API (100 IPs/request, free, no key). Returns country, region, city, ISP, org, ASN, is_hosting. Shows flag emojis, country summary, datacenter vs residential badges in UI.",
      },
    ],
  },
  {
    id: "risk",
    label: "Risk Scoring",
    color: "shodh-danger",
    colorHex: "#ff3355",
    tagline: "One number that tells the whole story",
    features: [
      {
        icon: TrendingUp,
        name: "Composite Risk Score",
        badge: "Feature #34",
        what: "Calculates a 0–100 risk score by weighing findings from 8 scanner components — CVE severity, subdomain takeovers, SSL health, email security, WAF coverage, exposed ports, header gaps, and IP reputation.",
        why: "Raw scan data is overwhelming. Security teams need a single prioritised number to communicate risk to leadership, triage findings, and track improvement over time.",
        detail: "Runs last in the pipeline after all scanners complete. 8 weighted components: CVEs (critical×25, high×10, medium×3), takeovers (×30), SSL issues, email policy, WAF gaps, dangerous ports, missing headers, blacklisted IPs. Score normalized to 0–100. Stored on the Scan record and shown prominently in the UI.",
      },
    ],
  },
];

// ── Component ─────────────────────────────────────────────────────────────────

const colorMap: Record<string, string> = {
  "shodh-accent":  "text-shodh-accent border-shodh-accent/30 bg-shodh-accent/10",
  "shodh-info":    "text-shodh-info border-shodh-info/30 bg-shodh-info/10",
  "shodh-purple":  "text-shodh-purple border-shodh-purple/30 bg-shodh-purple/10",
  "shodh-danger":  "text-shodh-danger border-shodh-danger/30 bg-shodh-danger/10",
  "shodh-warning": "text-shodh-warning border-shodh-warning/30 bg-shodh-warning/10",
};

const iconColorMap: Record<string, string> = {
  "shodh-accent":  "text-shodh-accent bg-shodh-accent/10 group-hover:bg-shodh-accent/20",
  "shodh-info":    "text-shodh-info bg-shodh-info/10 group-hover:bg-shodh-info/20",
  "shodh-purple":  "text-shodh-purple bg-shodh-purple/10 group-hover:bg-shodh-purple/20",
  "shodh-danger":  "text-shodh-danger bg-shodh-danger/10 group-hover:bg-shodh-danger/20",
  "shodh-warning": "text-shodh-warning bg-shodh-warning/10 group-hover:bg-shodh-warning/20",
};

const borderMap: Record<string, string> = {
  "shodh-accent":  "hover:border-shodh-accent/40",
  "shodh-info":    "hover:border-shodh-info/40",
  "shodh-purple":  "hover:border-shodh-purple/40",
  "shodh-danger":  "hover:border-shodh-danger/40",
  "shodh-warning": "hover:border-shodh-warning/40",
};

export default function Understanding() {
  const navigate = useNavigate();

  const totalFeatures = CATEGORIES.reduce((acc, c) => acc + c.features.length, 0);

  return (
    <div className="relative min-h-screen">

      {/* Mars replaces Earth on this route — covers SpaceBackground */}
      <MarsBackground />

      {/* ── Top nav bar ──────────────────────────────────────────────────── */}
      <div className="sticky top-0 z-50 backdrop-blur-md bg-shodh-bg/70 border-b border-shodh-border/40">
        <div className="max-w-6xl mx-auto px-6 py-3 flex items-center justify-between">
          <button
            onClick={() => navigate("/")}
            className="flex items-center gap-2 text-[#7a9ab0] hover:text-shodh-accent transition-colors text-sm font-mono group"
          >
            <ArrowLeft className="w-4 h-4 group-hover:-translate-x-0.5 transition-transform" />
            Back to scanner
          </button>
          <div className="flex items-center gap-2">
            <BookOpen className="w-4 h-4 text-shodh-accent" />
            <span className="text-shodh-text font-sans font-semibold text-sm">Feature Reference</span>
          </div>
          <div className="text-[#7a9ab0] font-mono text-xs">
            {totalFeatures} modules documented
          </div>
        </div>
      </div>

      {/* ── Hero ─────────────────────────────────────────────────────────── */}
      <section className="pt-20 pb-16 px-6 text-center relative">
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7 }}
        >
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-shodh-accent/10 border border-shodh-accent/20 text-shodh-accent text-xs font-mono mb-6">
            <Star className="w-3 h-3" />
            Understanding Aavaran
          </div>

          <h1 className="text-5xl md:text-6xl font-bold font-display mb-4">
            <span className="text-shodh-text">How </span>
            <span className="text-shodh-accent glow-text-green">Aavaran</span>
            <span className="text-shodh-text"> Works</span>
          </h1>
          <p className="text-[#a0c0cc] font-mono text-sm max-w-xl mx-auto leading-relaxed">
            Every scan module explained — what it does, why it matters, and how it finds what other tools miss.
          </p>
        </motion.div>

        {/* Category quick-jump pills */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3, duration: 0.6 }}
          className="flex flex-wrap justify-center gap-2 mt-10"
        >
          {CATEGORIES.map((cat) => (
            <a
              key={cat.id}
              href={`#${cat.id}`}
              className={`px-3 py-1.5 rounded-full border text-xs font-mono transition-all duration-200 hover:scale-105 ${colorMap[cat.color]}`}
            >
              {cat.label}
            </a>
          ))}
        </motion.div>

        {/* Stats */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
          className="flex justify-center gap-8 mt-10"
        >
          {[
            { value: `${totalFeatures}`, label: "Scan Modules" },
            { value: `${CATEGORIES.length}`, label: "Categories" },
            { value: "0",  label: "API Keys Required" },
          ].map((s) => (
            <div key={s.label} className="text-center">
              <p className="text-2xl font-bold font-mono text-shodh-accent">{s.value}</p>
              <p className="text-[10px] text-[#7a9ab0] font-mono uppercase tracking-wider mt-0.5">{s.label}</p>
            </div>
          ))}
        </motion.div>
      </section>

      {/* ── Category sections ─────────────────────────────────────────────── */}
      <div className="max-w-6xl mx-auto px-6 pb-24 space-y-24">
        {CATEGORIES.map((cat, catIdx) => {
          const iconC = iconColorMap[cat.color];
          const borderC = borderMap[cat.color];
          const textC = colorMap[cat.color].split(" ")[0]; // just the text-* class

          return (
            <section key={cat.id} id={cat.id}>
              {/* Category header */}
              <motion.div
                initial={{ opacity: 0, x: -20 }}
                whileInView={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.6 }}
                viewport={{ once: true, margin: "-80px" }}
                className="mb-8"
              >
                <div className="flex items-center gap-3 mb-1">
                  <div className="h-px flex-1 bg-gradient-to-r from-shodh-border/60 to-transparent" />
                  <span className={`text-[10px] font-mono uppercase tracking-[0.3em] ${textC}`}>
                    0{catIdx + 1}
                  </span>
                </div>
                <h2 className={`text-2xl font-bold font-display ${textC}`}>{cat.label}</h2>
                <p className="text-[#8ab0c0] font-mono text-xs mt-1">{cat.tagline}</p>
              </motion.div>

              {/* Feature cards */}
              <div className="space-y-4">
                {cat.features.map((feat, fi) => {
                  const Icon = feat.icon;
                  return (
                    <motion.div
                      key={feat.name}
                      initial={{ opacity: 0, y: 16 }}
                      whileInView={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.45, delay: fi * 0.06 }}
                      viewport={{ once: true, margin: "-40px" }}
                      className={`group rounded-xl border border-shodh-border/40 bg-[#0e0a14]/70 backdrop-blur-md hover:bg-[#12091a]/80 transition-all duration-300 overflow-hidden ${borderC}`}
                    >
                      {/* Card header */}
                      <div className="flex items-start gap-4 p-5 pb-0">
                        <div className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 transition-colors ${iconC}`}>
                          <Icon className="w-5 h-5" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-3 flex-wrap">
                            <h3 className="text-base font-semibold font-sans text-shodh-text">
                              {feat.name}
                            </h3>
                          </div>
                        </div>
                      </div>

                      {/* Two columns */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-0 divide-y md:divide-y-0 md:divide-x divide-shodh-border/30 mt-4">
                        {[
                          { label: "What it does", text: feat.what, icon: Search },
                          { label: "Why it matters", text: feat.why, icon: AlertTriangle },
                        ].map(({ label, text, icon: ColIcon }) => (
                          <div key={label} className="px-5 py-4">
                            <div className="flex items-center gap-1.5 mb-2">
                              <ColIcon className="w-3 h-3 text-[#8a9fb5]" />
                              <span className="text-[10px] font-mono uppercase tracking-wider text-[#8a9fb5]">
                                {label}
                              </span>
                            </div>
                            <p className="text-xs text-[#b8d8e4] font-mono leading-relaxed">
                              {text}
                            </p>
                          </div>
                        ))}
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            </section>
          );
        })}

        {/* ── Bottom CTA ──────────────────────────────────────────────────── */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="text-center pt-8 border-t border-shodh-border/30"
        >
          <p className="text-[#8ab8cc] font-mono text-xs mb-6">
            All {totalFeatures} modules run automatically on every scan. One domain in. Full exposure out.
          </p>
          <button
            onClick={() => navigate("/")}
            className="inline-flex items-center gap-2 px-7 py-3 bg-shodh-accent text-shodh-bg font-semibold rounded-xl hover:bg-shodh-accent/90 transition-all duration-200 font-sans"
          >
            <Zap className="w-4 h-4" />
            Run a scan now
          </button>
          <p className="text-[#4a6878] text-[10px] font-mono mt-4">
            آवरण · self-hosted · zero API keys · your data stays local
          </p>
        </motion.div>
      </div>
    </div>
  );
}
