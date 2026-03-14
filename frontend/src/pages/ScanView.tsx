import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  ArrowLeft,
  Shield,
  Globe,
  Loader2,
  AlertTriangle,
  CheckCircle,
  Activity,
  Server,
  Lock,
  Unlock,
  Layers,
  ExternalLink,
  Mail,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Copy,
  RefreshCw,
  Building2,
  Network,
  Calendar,
  User,
  Cpu,
  Wifi,
  AlertOctagon,
  CheckCircle2,
  XCircle,
  FileText,
  Bug,
  Link2Off,
  FolderOpen,
  Code2,
  Globe2,
  Key,
  Clock,
} from "lucide-react";
import axios from "axios";

interface Port {
  port_number: number;
  protocol: string;
  service: string | null;
  version: string | null;
  banner: string | null;
}

interface Technology {
  name: string;
  version: string | null;
  category: string | null;
}

interface HeaderAnalysis {
  has_hsts: boolean | null;
  hsts_value: string | null;
  has_csp: boolean | null;
  csp_value: string | null;
  has_x_frame_options: boolean | null;
  x_frame_options_value: string | null;
  has_x_content_type_options: boolean | null;
  has_referrer_policy: boolean | null;
  referrer_policy_value: string | null;
  has_permissions_policy: boolean | null;
  server_banner: string | null;
  x_powered_by: string | null;
  redirect_count: number | null;
  final_url: string | null;
  security_score: number | null;
  missing_headers: string[] | null;
}

interface SSLInfo {
  issuer: string | null;
  subject: string | null;
  valid_from: string | null;
  valid_until: string | null;
  is_expired: boolean | null;
  san_domains: string[] | null;
  grade: string | null;
  protocols: Record<string, boolean> | null;
  vulnerabilities: Record<string, boolean> | null;
}

interface Subdomain {
  id: string;
  hostname: string;
  ip_address: string | null;
  is_alive: boolean;
  http_status: number | null;
  page_title: string | null;
  source: string | null;
  reverse_hostname: string | null;
  waf_detected: boolean | null;
  waf_name: string | null;
  ports: Port[];
  technologies: Technology[];
  header_analysis: HeaderAnalysis | null;
  ssl_info: SSLInfo | null;
}

interface WhoisInfo {
  registrar: string | null;
  creation_date: string | null;
  expiry_date: string | null;
  updated_date: string | null;
  registrant_name: string | null;
  registrant_org: string | null;
  registrant_email: string | null;
  registrant_country: string | null;
  name_servers: string[] | null;
  status: string | null;
  dnssec: string | null;
  error: string | null;
}

interface ASNInfo {
  asn: string;
  prefix: string | null;
  country: string | null;
  org_name: string | null;
  sample_ip: string | null;
}

interface DNSRecord {
  record_type: string;
  hostname: string;
  value: string;
  ttl: number | null;
}

interface CVEInfo {
  cve_id: string;
  severity: string | null;
  cvss_score: number | null;
  description: string | null;
  technology_name: string;
  technology_version: string | null;
}

interface TakeoverInfo {
  hostname: string;
  is_vulnerable: boolean;
  service: string | null;
  cname_target: string | null;
  fingerprint: string | null;
  severity: string | null;
}

interface IPReputationInfo {
  ip_address: string;
  hostname: string | null;
  is_blacklisted: boolean;
  blacklists: string[] | null;
  threat_type: string | null;
  urlhaus_status: string | null;
  urlhaus_tags: string[] | null;
  abuse_score: number | null;
}

interface CORSResultInfo {
  hostname: string;
  is_vulnerable: boolean;
  misconfig_type: string | null;
  allowed_origin: string | null;
  allow_credentials: boolean;
  severity: string | null;
}

interface JSFindingInfo {
  subdomain_hostname: string;
  js_url: string;
  endpoints: string[] | null;
  secrets: { type: string; value: string }[] | null;
  endpoint_count: number;
  secret_count: number;
}

interface DirectoryFindingInfo {
  subdomain_hostname: string;
  path: string;
  status_code: number;
  content_length: number | null;
  finding_type: string | null;
  severity: string | null;
}

interface WaybackFindingInfo {
  url: string;
  status_code: string | null;
  mime_type: string | null;
  last_seen: string | null;
  category: string | null;
}

interface DNSSecurityInfo {
  dnssec_enabled: boolean;
  dnssec_valid: boolean;
  has_caa: boolean;
  caa_issuers: string[] | null;
  caa_wildcard_issuers: string[] | null;
  ns_count: number | null;
  issues: string[] | null;
}

interface ReverseIPEntry {
  ip_address: string;
  co_hosted_domains: string[] | null;
  domain_count: number;
  skipped_reason: string | null;
  error: string | null;
}

interface OTXResultInfo {
  pulse_count: number;
  threat_types: string[] | null;
  malware_families: string[] | null;
  adversaries: string[] | null;
  country: string | null;
  first_seen: string | null;
  alexa_rank: number | null;
  is_known_malicious: boolean;
  error: string | null;
}

interface EmailSecurity {
  spf_record: string | null;
  spf_valid: boolean | null;
  spf_mechanism: string | null;
  dkim_found: boolean | null;
  dkim_selector: string | null;
  dkim_record: string | null;  // New: Full DKIM TXT for display
  dmarc_record: string | null;
  dmarc_policy: string | null;
  dmarc_pct: number | null;
  mta_sts_mode: string | null;
  is_spoofable: boolean | null;
  errors: string[];  // New: List of scan errors/warnings
}

interface IPGeoLocationInfo {
  ip_address: string;
  hostname: string | null;
  country: string | null;
  country_code: string | null;
  region: string | null;
  city: string | null;
  isp: string | null;
  org: string | null;
  asn: string | null;
  is_hosting: boolean | null;
}

interface ScanData {
  id: string;
  domain: string;
  status: "pending" | "running" | "completed" | "failed";
  risk_score: number | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  zone_transfer_successful: boolean | null;
  subdomains: Subdomain[];
  dns_records: DNSRecord[];
  email_security: EmailSecurity | null;
  whois_info: WhoisInfo | null;
  asn_info: ASNInfo[];
  cves: CVEInfo[];
  takeovers: TakeoverInfo[];
  ip_reputation: IPReputationInfo[];
  cors_results: CORSResultInfo[];
  js_findings: JSFindingInfo[];
  dir_findings: DirectoryFindingInfo[];
  wayback_findings: WaybackFindingInfo[];
  dns_security: DNSSecurityInfo | null;
  geo_locations: IPGeoLocationInfo[];
  reverse_ip: ReverseIPEntry[];
  otx_result: OTXResultInfo | null;
}

// ── Tooltip component ─────────────────────────────────────────────────────────
function Tooltip({ text, tip }: { text: React.ReactNode; tip: string }) {
  return (
    <span className="relative group inline-flex items-center cursor-help">
      <span className="border-b border-dotted border-shodh-muted/50">{text}</span>
      <span className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-max max-w-[230px] px-2.5 py-1.5 rounded bg-[#16162a] border border-shodh-border text-[11px] font-sans font-normal text-shodh-text/90 leading-snug shadow-xl z-50 invisible group-hover:visible opacity-0 group-hover:opacity-100 transition-opacity duration-150 pointer-events-none whitespace-normal text-center normal-case tracking-normal">
        {tip}
        <span className="absolute top-full left-1/2 -translate-x-1/2 w-0 h-0 border-x-4 border-x-transparent border-t-4 border-t-shodh-border" />
      </span>
    </span>
  );
}

// ── Paginator component ────────────────────────────────────────────────────────
const PER_PAGE = 10;

function Paginator({ page, total, perPage = PER_PAGE, onChange }: {
  page: number; total: number; perPage?: number; onChange: (p: number) => void;
}) {
  const totalPages = Math.ceil(total / perPage);
  if (totalPages <= 1) return null;
  const pages: (number | "...")[] = [];
  for (let i = 1; i <= totalPages; i++) {
    if (i === 1 || i === totalPages || Math.abs(i - page) <= 1) pages.push(i);
    else if (pages[pages.length - 1] !== "...") pages.push("...");
  }
  return (
    <div className="flex items-center justify-between px-6 py-3 border-t border-shodh-border/40 bg-shodh-bg/20">
      <span className="text-xs font-mono text-shodh-muted">
        {(page - 1) * perPage + 1}–{Math.min(page * perPage, total)} of {total}
      </span>
      <div className="flex items-center gap-0.5">
        <button onClick={() => onChange(1)} disabled={page === 1}
          className="px-2 py-1 text-xs font-mono text-shodh-muted hover:text-shodh-accent disabled:opacity-30 disabled:cursor-not-allowed transition-colors rounded">«</button>
        <button onClick={() => onChange(page - 1)} disabled={page === 1}
          className="px-2 py-1 text-xs font-mono text-shodh-muted hover:text-shodh-accent disabled:opacity-30 disabled:cursor-not-allowed transition-colors rounded">‹</button>
        {pages.map((p, i) =>
          p === "..." ? (
            <span key={`e${i}`} className="px-1.5 text-xs text-shodh-muted/50">…</span>
          ) : (
            <button key={p} onClick={() => onChange(p as number)}
              className={`px-2.5 py-1 text-xs font-mono rounded transition-colors ${page === p ? "bg-shodh-accent text-shodh-bg font-bold" : "text-shodh-muted hover:text-shodh-accent hover:bg-shodh-border/30"}`}>
              {p}
            </button>
          )
        )}
        <button onClick={() => onChange(page + 1)} disabled={page === totalPages}
          className="px-2 py-1 text-xs font-mono text-shodh-muted hover:text-shodh-accent disabled:opacity-30 disabled:cursor-not-allowed transition-colors rounded">›</button>
        <button onClick={() => onChange(totalPages)} disabled={page === totalPages}
          className="px-2 py-1 text-xs font-mono text-shodh-muted hover:text-shodh-accent disabled:opacity-30 disabled:cursor-not-allowed transition-colors rounded">»</button>
      </div>
    </div>
  );
}

// ── Tooltip text definitions ───────────────────────────────────────────────────
const TIPS: Record<string, string> = {
  // Email
  SPF:   "Sender Policy Framework — lists mail servers authorised to send email for this domain. Prevents forged 'From' addresses.",
  DKIM:  "DomainKeys Identified Mail — adds a cryptographic signature to outgoing emails. Proves the message wasn't altered in transit.",
  DMARC: "Domain-based Message Authentication — ties SPF and DKIM together and tells receivers what to do with failures (none / quarantine / reject).",
  // Security headers
  HSTS:                     "HTTP Strict Transport Security — forces browsers to connect via HTTPS only, preventing protocol downgrade and cookie hijacking attacks.",
  CSP:                      "Content Security Policy — restricts which scripts, styles, and resources the page may load. Primary defence against XSS attacks.",
  "X-Frame-Options":        "Prevents the page from being embedded in iframes on other sites. Blocks clickjacking attacks.",
  "X-Content-Type-Options": "Stops browsers from MIME-sniffing responses away from the declared content type. Prevents drive-by downloads.",
  "Referrer-Policy":        "Controls how much of the page URL is included in the Referer header when users navigate away. Protects sensitive URL parameters.",
  "Permissions-Policy":     "Restricts which browser features (camera, microphone, geolocation) are available to the page and any embedded iframes.",
  // DNS record types
  A:     "Maps a hostname to an IPv4 address — the most common record type.",
  AAAA:  "Maps a hostname to an IPv6 address.",
  MX:    "Mail Exchange — specifies which servers are responsible for accepting email for this domain.",
  NS:    "Name Server — delegates DNS resolution for this zone to the listed authoritative servers.",
  TXT:   "Text record — holds arbitrary text. Commonly used for SPF, DKIM, DMARC, and domain ownership verification.",
  CNAME: "Canonical Name — creates an alias from one hostname to another. The alias inherits all records of the target.",
  SOA:   "Start of Authority — contains zone metadata: primary nameserver, admin email, serial number, and refresh intervals.",
  CAA:   "Certification Authority Authorization — specifies which CAs are allowed to issue SSL certificates for this domain.",
  // SSL
  "TLS 1.3": "Latest TLS version (2018). Most secure and fastest handshake — required for an A+ grade.",
  "TLS 1.2": "Current standard TLS version. Secure when properly configured.",
  "TLS 1.1": "Deprecated TLS version (officially retired 2020). Browsers are dropping support — should be disabled.",
  "TLS 1.0": "Obsolete TLS version (1999). Vulnerable to BEAST and POODLE attacks — must be disabled.",
  BEAST:           "Browser Exploit Against SSL/TLS — a CBC cipher attack that affects TLS 1.0. Disable TLS 1.0 to mitigate.",
  "Weak Protocols":"Server supports deprecated TLS 1.0 or 1.1, which have known cryptographic weaknesses.",
  // CVE
  CVSS:  "Common Vulnerability Scoring System — a 0–10 numeric score rating vulnerability severity. 9–10 = Critical, 7–8.9 = High, 4–6.9 = Medium.",
  // Reputation
  DNSBL:   "DNS Blacklist — real-time lists of IPs known for spam or malware, checked via DNS queries. NXDOMAIN means clean.",
  URLhaus: "Abuse.ch URLhaus — community-driven database of hosts actively distributing malware or phishing content.",
  // CORS
  arbitrary_origin_reflected: "The server reflects any Origin header back, granting cross-origin read access to any website — effectively disables same-origin policy.",
  null_origin:                "The server accepts requests from the 'null' origin, which sandboxed iframes and local HTML files can send.",
  // Directory finding types
  git_exposure:      "Git repository files (.git/config, HEAD) are publicly accessible. Attackers can reconstruct your full source code.",
  env_file:          "Environment config file (.env) is exposed. Likely contains database passwords, API keys, and other secrets.",
  admin_panel:       "Administrative interface is publicly reachable. Susceptible to brute-force or credential stuffing attacks.",
  cms_admin:         "CMS login or admin endpoint is publicly accessible, exposing it to automated credential attacks.",
  api_docs:          "API documentation (Swagger/OpenAPI) is exposed. Reveals all endpoints, parameters, and authentication requirements.",
  devops_panel:      "DevOps monitoring tool (Kibana, Grafana, Spring Actuator) is publicly reachable and may expose infrastructure data.",
  database_dump:     "A database backup or dump file is publicly downloadable. May contain all application data in plaintext.",
  log_file:          "Server log files are accessible. May expose user data, IP addresses, internal paths, and stack traces.",
  debug_endpoint:    "Debug or profiling endpoint is exposed. Can leak environment variables, config, and full stack traces.",
  dependency_file:   "Dependency manifest (package.json, requirements.txt) is accessible. Reveals exact library versions for targeted CVE research.",
  health_check:      "Health or status endpoint is accessible. Generally low risk — informational only.",
  informational:     "Informational file (robots.txt, sitemap.xml). Reveals site structure but is not directly exploitable.",
};

// ── DNS record type colour mapping ───────────────────────────────────────────
const RECORD_TYPE_STYLES: Record<string, string> = {
  A:     "text-shodh-info   border-shodh-info/40   bg-shodh-info/10",
  AAAA:  "text-shodh-info   border-shodh-info/40   bg-shodh-info/10",
  MX:    "text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10",
  NS:    "text-shodh-purple  border-shodh-purple/40  bg-shodh-purple/10",
  TXT:   "text-shodh-muted   border-shodh-border     bg-shodh-border/40",
  CNAME: "text-shodh-accent  border-shodh-accent/40  bg-shodh-accent/10",
  SOA:   "text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10",
  CAA:   "text-shodh-danger  border-shodh-danger/40  bg-shodh-danger/10",
};

const recordTypeBadge = (type: string) =>
  RECORD_TYPE_STYLES[type] ??
  "text-shodh-muted border-shodh-border bg-shodh-border/40";

// ── Subdomain source badge styles ────────────────────────────────────────────

// ── HTTP status badge ────────────────────────────────────────────────────────
function statusBadge(is_alive: boolean, http_status: number | null) {
  if (!is_alive) {
    return <span className="text-xs text-shodh-muted">offline</span>;
  }
  const code = http_status ?? 0;
  let cls = "text-xs px-2 py-0.5 rounded border font-mono ";
  if (code >= 500) cls += "text-shodh-danger  border-shodh-danger/40  bg-shodh-danger/10";
  else if (code >= 400) cls += "text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10";
  else if (code >= 300) cls += "text-shodh-info   border-shodh-info/40   bg-shodh-info/10";
  else if (code >= 200) cls += "text-shodh-accent  border-shodh-accent/40  bg-shodh-accent/10";
  else cls += "text-shodh-muted border-shodh-border bg-shodh-border/40";  // Covers code=0 as "unknown"
  return <span className={cls}>{code > 0 ? code : "alive"}</span>;  // Avoid showing "0"
}

// ── Cloudflare IP detection ──────────────────────────────────────────────────
// Ranges from https://www.cloudflare.com/ips-v4
const CF_PREFIXES = [
  "173.245.", "103.21.", "103.22.", "103.31.",
  "141.101.", "108.162.", "190.93.", "188.114.",
  "197.234.", "198.41.", "162.158.", "162.159.",
];

function isCloudflareIP(ip: string | null): boolean {
  if (!ip) return false;
  if (CF_PREFIXES.some((p) => ip.startsWith(p))) return true;
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return false;
  // 104.16.0.0/13  →  104.16–23
  if (parts[0] === 104 && parts[1] >= 16 && parts[1] <= 23) return true;
  // 104.24.0.0/14  →  104.24–27
  if (parts[0] === 104 && parts[1] >= 24 && parts[1] <= 27) return true;
  // 172.64.0.0/13  →  172.64–71
  if (parts[0] === 172 && parts[1] >= 64 && parts[1] <= 71) return true;
  // 131.0.72.0/22
  if (parts[0] === 131 && parts[1] === 0 && parts[2] >= 72 && parts[2] <= 75) return true;
  return false;
}

// ── Copy to clipboard helper ─────────────────────────────────────────────────
const copyToClipboard = async (text: string, label: string) => {
  try {
    await navigator.clipboard.writeText(text);
    // Optional: Add toast notification here
    console.log(`${label} copied!`);
  } catch (err) {
    console.error("Copy failed:", err);
  }
};

// ── Group DNS records by type ────────────────────────────────────────────────
const groupByType = (records: DNSRecord[]) => {
  const groups: Record<string, DNSRecord[]> = {};
  for (const rec of records) {
    (groups[rec.record_type] ??= []).push(rec);
  }
  return groups;
};

export default function ScanView() {
  const { id } = useParams();
  const [scan, setScan] = useState<ScanData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [subdomainPage, setSubdomainPage] = useState(1);
  const [dnsPage, setDnsPage] = useState(1);
  const [portsPage, setPortsPage] = useState(1);
  const [headersPage, setHeadersPage] = useState(1);
  const [sslPage, setSslPage] = useState(1);
  const [cvePage, setCvePage] = useState(1);
  const [dirPage, setDirPage] = useState(1);
  const [waybackPage, setWaybackPage] = useState(1);
  const [jsPage, setJsPage] = useState(1);
  const [geoPage, setGeoPage] = useState(1);

  const fetchScan = async () => {
    try {
      const res = await axios.get(`/api/scans/${id}`);
      setScan(res.data);
      return res.data;
    } catch {
      setError("Scan not found");
      return null;
    }
  };

  useEffect(() => {
    fetchScan().finally(() => setLoading(false));

    // Poll every 2s while active
    const interval = setInterval(async () => {
      const data = await fetchScan();
      if (data && (data.status === "completed" || data.status === "failed")) {
        clearInterval(interval);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [id]);

  // ── Manual refresh handler ─────────────────────────────────────────────────
  const handleRefresh = async () => {
    setLoading(true);
    await fetchScan();
    setLoading(false);
  };

  // ── Loading / error states ─────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="w-8 h-8 text-shodh-accent animate-spin" />
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-4">
        <AlertTriangle className="w-12 h-12 text-shodh-danger" />
        <p className="text-shodh-muted font-mono">{error || "Something went wrong"}</p>
        <Link to="/" className="text-shodh-accent font-mono text-sm hover:underline">
          ← Back to home
        </Link>
      </div>
    );
  }

  const statusConfig = {
    pending:   { color: "text-shodh-warning", icon: Loader2,        label: "Pending" },
    running:   { color: "text-shodh-info",    icon: Loader2,        label: "Scanning..." },
    completed: { color: "text-shodh-accent",  icon: CheckCircle,    label: "Completed" },
    failed:    { color: "text-shodh-danger",  icon: AlertTriangle,  label: "Failed" },
  };

  const status = statusConfig[scan.status];
  const StatusIcon = status.icon;
  const scanIsActive = scan.status === "pending" || scan.status === "running";

  // Flatten ports and technologies across all subdomains
  const allPorts = scan.subdomains.flatMap((s) => s.ports.map((p) => ({ ...p, hostname: s.hostname })));
  const allTechs = (() => {
    const seen = new Map<string, Technology & { hostnames: string[] }>();
    for (const sub of scan.subdomains) {
      for (const t of sub.technologies) {
        const key = `${t.name}|${t.version ?? ""}`;
        if (seen.has(key)) {
          seen.get(key)!.hostnames.push(sub.hostname);
        } else {
          seen.set(key, { ...t, hostnames: [sub.hostname] });
        }
      }
    }
    return Array.from(seen.values()).sort((a, b) => a.name.localeCompare(b.name));
  })();

  // Feature 13: Unprotected asset flagging
  // Flag alive subdomains with no WAF when at least one sibling has WAF
  const anyWafDetected = scan.subdomains.some((s) => s.waf_detected === true);
  const flaggedSubdomains = anyWafDetected
    ? scan.subdomains.filter((s) => s.is_alive && s.waf_detected === false)
    : [];

  // Feature 15: Subdomains that have completed header analysis
  const headerScanned = scan.subdomains.filter((s) => s.header_analysis !== null);

  // Feature 16/17: Subdomains that have SSL info
  const sslScanned = scan.subdomains.filter((s) => s.ssl_info !== null);

  // Feature 24/25: CVE severity helpers
  const cveSevColor = (sev: string | null) => {
    if (!sev) return "text-shodh-muted";
    if (sev === "critical") return "text-shodh-danger";
    if (sev === "high")     return "text-[#ff6644]";
    if (sev === "medium")   return "text-shodh-warning";
    if (sev === "low")      return "text-shodh-info";
    return "text-shodh-muted";
  };
  const cveSevBg = (sev: string | null) => {
    if (!sev) return "border-shodh-border bg-shodh-border/30";
    if (sev === "critical") return "border-shodh-danger/50 bg-shodh-danger/10";
    if (sev === "high")     return "border-[#ff6644]/50 bg-[#ff6644]/10";
    if (sev === "medium")   return "border-shodh-warning/40 bg-shodh-warning/10";
    if (sev === "low")      return "border-shodh-info/40 bg-shodh-info/10";
    return "border-shodh-border bg-shodh-border/30";
  };
  const cveSevLabel = (sev: string | null) =>
    sev ? sev.toUpperCase() : "?";

  // Feature 26: Takeover severity helpers
  const takeSevColor = (sev: string | null) => {
    if (sev === "critical") return "text-shodh-danger";
    if (sev === "high")     return "text-[#ff6644]";
    if (sev === "medium")   return "text-shodh-warning";
    return "text-shodh-info";
  };

  // SSL grade colour + background helpers
  const gradeColor = (grade: string | null) => {
    if (!grade) return "text-shodh-muted";
    if (grade === "A+" || grade === "A") return "text-shodh-accent";
    if (grade === "B") return "text-shodh-warning";
    if (grade === "C") return "text-[#ffaa00]";
    return "text-shodh-danger";
  };
  const gradeBg = (grade: string | null) => {
    if (!grade) return "border-shodh-border bg-shodh-border/30";
    if (grade === "A+" || grade === "A") return "border-shodh-accent/40 bg-shodh-accent/10";
    if (grade === "B") return "border-shodh-warning/40 bg-shodh-warning/10";
    if (grade === "C") return "border-shodh-warning/30 bg-shodh-warning/5";
    return "border-shodh-danger/40 bg-shodh-danger/10";
  };

  // Security score colour helper
  const scoreColor = (score: number | null) => {
    if (score === null) return "text-shodh-muted";
    if (score >= 80) return "text-shodh-accent";
    if (score >= 50) return "text-shodh-warning";
    return "text-shodh-danger";
  };
  const scoreBg = (score: number | null) => {
    if (score === null) return "border-shodh-border bg-shodh-border/30";
    if (score >= 80) return "border-shodh-accent/40 bg-shodh-accent/10";
    if (score >= 50) return "border-shodh-warning/40 bg-shodh-warning/10";
    return "border-shodh-danger/40 bg-shodh-danger/10";
  };

  return (
    <div className="min-h-screen p-6">
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="max-w-7xl mx-auto"
      >
        {/* ── Back link & Refresh ──────────────────────────────────────────────── */}
        <div className="flex justify-between items-center mb-6">
          <Link
            to="/"
            className="inline-flex items-center gap-2 text-shodh-muted hover:text-shodh-accent transition-colors font-mono text-sm"
          >
            <ArrowLeft className="w-4 h-4" />
            Back
          </Link>
          <div className="flex items-center gap-3">
            {scan?.status === "completed" && (
              <a
                href={`/api/scans/${id}/report`}
                download
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-shodh-accent/10 border border-shodh-accent/30 text-shodh-accent hover:bg-shodh-accent/20 transition-colors font-mono text-sm"
                title="Download PDF Report"
              >
                <FileText className="w-4 h-4" />
                Download PDF
              </a>
            )}
            <button
              onClick={handleRefresh}
              className="inline-flex items-center gap-1 text-shodh-muted hover:text-shodh-accent transition-colors font-mono text-sm disabled:opacity-50"
              disabled={loading}
              title="Refresh scan data"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>
        </div>

        {/* ── Domain header ──────────────────────────────────────────── */}
        <div className="flex items-center gap-4 mb-8">
          <div className="w-12 h-12 bg-shodh-surface/60 backdrop-blur-sm border border-shodh-border/60 rounded-xl flex items-center justify-center">
            <Globe className="w-6 h-6 text-shodh-accent" />
          </div>
          <div>
            <h1 className="text-2xl font-bold font-mono text-shodh-text">
              {scan.domain}
            </h1>
            <div className="flex items-center gap-2 mt-1">
              <StatusIcon
                className={`w-4 h-4 ${status.color} ${
                  scanIsActive ? "animate-spin" : ""
                }`}
              />
              <span className={`text-sm font-mono ${status.color}`}>
                {status.label}
              </span>
            </div>
          </div>

          {/* Risk score */}
          {scan.risk_score !== null && (
            <div className="ml-auto text-right" title="Based on subdomains, misconfigs, and exposures">
              <p className="text-xs text-shodh-muted font-mono uppercase tracking-wider">
                Risk Score
              </p>
              <p
                className={`text-3xl font-bold font-mono ${
                  scan.risk_score >= 70
                    ? "text-shodh-danger"
                    : scan.risk_score >= 40
                    ? "text-shodh-warning"
                    : "text-shodh-accent"
                }`}
              >
                {scan.risk_score}
                <span className="text-sm text-shodh-muted">/100</span>
              </p>
            </div>
          )}
        </div>

        {/* ── Stats cards ────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          {[
            { label: "Subdomains", value: scan.subdomains.length, icon: Globe },
            { label: "DNS Records", value: scan.dns_records.length, icon: Server },
            { label: "Open Ports",  value: allPorts.length || (scanIsActive ? "…" : "—"), icon: Activity },
            { label: "Technologies", value: allTechs.length || (scanIsActive ? "…" : "—"), icon: Cpu },
          ].map(({ label, value, icon: Icon }) => (
            <div
              key={label}
              className="bg-shodh-surface/50 backdrop-blur-md border border-shodh-border/60 rounded-xl p-4"
            >
              <div className="flex items-center gap-2 mb-2">
                <Icon className="w-4 h-4 text-shodh-accent/60" />
                <span className="text-xs text-shodh-muted font-mono uppercase tracking-wider">
                  {label}
                </span>
              </div>
              <p className="text-2xl font-bold font-mono text-shodh-text">
                {value}
              </p>
            </div>
          ))}
        </div>

        {/* ── Zone Transfer Alert ────────────────────────────────────── */}
        <AnimatePresence>
          {scan.zone_transfer_successful === true && (
            <motion.div
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="mb-6 border border-shodh-danger/60 bg-shodh-danger/10 rounded-xl p-5 flex items-start gap-4"
            >
              <div className="mt-0.5 flex-shrink-0">
                <Unlock className="w-6 h-6 text-shodh-danger" />
              </div>
              <div>
                <p className="text-shodh-danger font-mono font-bold text-sm uppercase tracking-wider mb-1">
                  Critical — Zone Transfer Allowed (AXFR)
                </p>
                <p className="text-shodh-text/80 font-mono text-sm leading-relaxed">
                  The nameserver exposed the entire zone file via DNS zone transfer.
                  An attacker can enumerate every record in your DNS zone, revealing
                  internal hostnames, IP addresses, and infrastructure layout.
                  Restrict AXFR to authorised secondaries immediately.
                </p>
              </div>
            </motion.div>
          )}

          {scan.zone_transfer_successful === false && scan.status === "completed" && (
            <motion.div
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="mb-6 border border-shodh-accent/30 bg-shodh-accent/5 rounded-xl p-4 flex items-center gap-3"
            >
              <Lock className="w-5 h-5 text-shodh-accent flex-shrink-0" />
              <p className="text-shodh-accent/80 font-mono text-sm">
                Zone transfer refused — nameservers are correctly secured.
              </p>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ── IP Geolocation + DNS Security side-by-side ─────────────── */}
        {(scan.geo_locations.length > 0 || (scan.status === "completed" && scan.dns_security)) && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">

            {/* IP Geolocation */}
            {scan.geo_locations.length > 0 && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.05 }}
                className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden flex flex-col"
              >
                <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
                  <div>
                    <h2 className="text-sm font-semibold text-shodh-text font-sans uppercase tracking-wider">
                      IP Geolocation &amp; Hosting
                    </h2>
                    <span className="text-xs font-mono text-shodh-muted/60">ip-api.com · country, ISP, ASN, datacenter detection</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {scan.geo_locations.some(g => g.is_hosting) && (
                      <span className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10">
                        {scan.geo_locations.filter(g => g.is_hosting).length} datacenter
                      </span>
                    )}
                    <span className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-info border-shodh-info/40 bg-shodh-info/10">
                      {scan.geo_locations.length} IPs
                    </span>
                  </div>
                </div>

                {/* Country summary */}
                {(() => {
                  const byCountry: Record<string, number> = {};
                  scan.geo_locations.forEach(g => {
                    const c = g.country ?? "Unknown";
                    byCountry[c] = (byCountry[c] ?? 0) + 1;
                  });
                  const sorted = Object.entries(byCountry).sort((a, b) => b[1] - a[1]);
                  return sorted.length > 1 ? (
                    <div className="px-6 py-3 border-b border-shodh-border/40 flex flex-wrap gap-2">
                      {sorted.map(([country, count], i) => (
                        <span key={i} className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-muted border-shodh-border bg-shodh-border/30">
                          {country} ×{count}
                        </span>
                      ))}
                    </div>
                  ) : null;
                })()}

                <div className="overflow-x-auto flex-1">
                  <table className="w-full text-sm font-mono">
                    <thead>
                      <tr className="text-xs text-shodh-muted uppercase tracking-wider border-b border-shodh-border">
                        <th className="px-4 py-2 text-left font-normal">IP</th>
                        <th className="px-4 py-2 text-left font-normal">Location</th>
                        <th className="px-4 py-2 text-left font-normal">ISP / Org</th>
                        <th className="px-4 py-2 text-left font-normal">Type</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scan.geo_locations.slice((geoPage - 1) * PER_PAGE, geoPage * PER_PAGE).map((g, i) => (
                        <tr key={i} className="border-t border-shodh-border/40 hover:bg-shodh-border/20 transition-colors">
                          <td className="px-4 py-2.5">
                            <span className="text-shodh-accent text-xs">{g.ip_address}</span>
                            {g.hostname && (
                              <div className="text-shodh-muted/60 text-[11px] truncate max-w-[120px]">{g.hostname}</div>
                            )}
                          </td>
                          <td className="px-4 py-2.5">
                            <div className="flex items-center gap-1.5">
                              {g.country_code && (
                                <span className="text-base leading-none" title={g.country ?? ""}>
                                  {g.country_code.toUpperCase().split("").map(c =>
                                    String.fromCodePoint(c.charCodeAt(0) + 127397)
                                  ).join("")}
                                </span>
                              )}
                              <span className="text-shodh-text text-xs">
                                {[g.city, g.country].filter(Boolean).join(", ") || "—"}
                              </span>
                            </div>
                          </td>
                          <td className="px-4 py-2.5 text-xs max-w-[140px]">
                            <div className="text-shodh-text truncate">{g.org ?? g.isp ?? "—"}</div>
                          </td>
                          <td className="px-4 py-2.5">
                            {g.is_hosting ? (
                              <span className="text-xs px-2 py-0.5 rounded border text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10">
                                DC
                              </span>
                            ) : g.is_hosting === false ? (
                              <span className="text-xs px-2 py-0.5 rounded border text-shodh-muted border-shodh-border bg-shodh-border/30">
                                Res
                              </span>
                            ) : (
                              <span className="text-shodh-muted/40">—</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <Paginator page={geoPage} total={scan.geo_locations.length} onChange={setGeoPage} />
                <p className="px-6 py-3 text-xs font-mono text-shodh-muted/60 border-t border-shodh-border/40">
                  DC = Datacenter/cloud. Res = Residential.
                </p>
              </motion.div>
            )}

            {/* DNS Security */}
            {scan.status === "completed" && scan.dns_security && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.08 }}
                className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden flex flex-col"
              >
                <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
                  <div>
                    <h2 className="text-sm font-semibold text-shodh-text font-sans uppercase tracking-wider">
                      DNS Security
                    </h2>
                    <span className="text-xs font-mono text-shodh-muted/60">DNSSEC · CAA · Nameserver resilience</span>
                  </div>
                  {(scan.dns_security.issues?.length ?? 0) > 0 ? (
                    <span className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10">
                      {scan.dns_security.issues!.length} issue{scan.dns_security.issues!.length !== 1 ? "s" : ""}
                    </span>
                  ) : (
                    <span className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-accent border-shodh-accent/40 bg-shodh-accent/10">
                      All good
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-px bg-shodh-border/30 border-b border-shodh-border">
                  {[
                    {
                      label: <Tooltip text="DNSSEC" tip="DNS Security Extensions — cryptographically signs DNS records to prevent spoofing and cache poisoning." />,
                      value: scan.dns_security.dnssec_enabled
                        ? (scan.dns_security.dnssec_valid ? "Valid" : "Configured")
                        : "None",
                      color: scan.dns_security.dnssec_valid
                        ? "text-shodh-accent"
                        : scan.dns_security.dnssec_enabled
                        ? "text-shodh-warning"
                        : "text-shodh-danger",
                    },
                    {
                      label: <Tooltip text="CAA Record" tip="Certification Authority Authorization — specifies which CAs are allowed to issue SSL/TLS certificates for this domain." />,
                      value: scan.dns_security.has_caa ? "Present" : "Missing",
                      color: scan.dns_security.has_caa ? "text-shodh-accent" : "text-shodh-danger",
                    },
                    {
                      label: "Nameservers",
                      value: scan.dns_security.ns_count !== null ? String(scan.dns_security.ns_count) : "—",
                      color: (scan.dns_security.ns_count ?? 2) > 1 ? "text-shodh-accent" : "text-shodh-warning",
                    },
                    {
                      label: "Issues",
                      value: String(scan.dns_security.issues?.length ?? 0),
                      color: (scan.dns_security.issues?.length ?? 0) === 0 ? "text-shodh-accent" : "text-shodh-danger",
                    },
                  ].map((stat, i) => (
                    <div key={i} className="bg-shodh-surface/40 px-6 py-4">
                      <p className="text-xs text-shodh-muted font-mono mb-1">{stat.label}</p>
                      <p className={`text-2xl font-bold font-mono ${stat.color}`}>{stat.value}</p>
                    </div>
                  ))}
                </div>

                {scan.dns_security.caa_issuers && scan.dns_security.caa_issuers.length > 0 && (
                  <div className="px-6 py-4 border-b border-shodh-border/40">
                    <p className="text-xs text-shodh-muted font-mono mb-2">Authorized Certificate Authorities</p>
                    <div className="flex flex-wrap gap-2">
                      {scan.dns_security.caa_issuers.map((ca, i) => (
                        <span key={i} className="text-xs px-2 py-0.5 rounded border text-shodh-accent border-shodh-accent/40 bg-shodh-accent/10 font-mono">
                          {ca}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {scan.dns_security.issues && scan.dns_security.issues.length > 0 && (
                  <div className="px-6 py-4 flex-1">
                    <p className="text-xs text-shodh-muted font-mono mb-3">Security Issues</p>
                    <div className="flex flex-col gap-2">
                      {scan.dns_security.issues.map((issue, i) => (
                        <div key={i} className="flex items-start gap-2 p-3 rounded-lg bg-shodh-danger/5 border border-shodh-danger/20">
                          <span className="text-shodh-danger mt-0.5">⚠</span>
                          <span className="text-xs font-mono text-shodh-text/80">{issue}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </motion.div>
            )}

          </div>
        )}

        {/* ── Subdomains section ─────────────────────────────────────── */}
        {scan.subdomains.length > 0 ? (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden mb-6"
          >
            {/* Card header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
              <div className="flex items-center gap-3">
                <Layers className="w-5 h-5 text-shodh-accent" />
                <h2 className="font-mono font-semibold text-shodh-text">
                  Subdomains
                </h2>
              </div>
              <span className="text-xs font-mono text-shodh-muted bg-shodh-border px-2 py-1 rounded">
                {scan.subdomains.length} discovered
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full min-w-[600px] text-sm font-mono">  {/* Mobile scroll */}
                <thead>
                  <tr className="text-xs text-shodh-muted uppercase tracking-wider border-b border-shodh-border">
                    <th className="px-6 py-2 text-left font-normal">Hostname</th>
                    <th className="px-6 py-2 text-left font-normal">IP / PTR</th>
                    <th className="px-6 py-2 text-left font-normal">Status</th>
                    <th className="px-6 py-2 text-left font-normal">WAF</th>
                  </tr>
                </thead>
                <tbody>
                  {scan.subdomains.slice((subdomainPage-1)*PER_PAGE, subdomainPage*PER_PAGE).map((sub) => (
                    <tr
                      key={sub.id}
                      className="border-t border-shodh-border/40 hover:bg-shodh-border/20 transition-colors"
                    >
                      <td className="px-6 py-2.5 text-shodh-text max-w-xs" title={sub.page_title ?? undefined}>
                        <div>
                          <span className="block truncate">{sub.hostname}</span>
                          {sub.page_title && (
                            <p className="text-xs text-shodh-muted truncate mt-0.5">
                              {sub.page_title}
                            </p>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-2.5 text-shodh-muted font-mono">
                        <div className="flex items-center gap-1.5">
                          <span>{sub.ip_address ?? "—"}</span>
                          {isCloudflareIP(sub.ip_address) && (
                            <span
                              className="text-[10px] px-1.5 py-0.5 rounded border font-bold text-[#f48024] border-[#f48024]/40 bg-[#f48024]/10"
                              title="IP belongs to Cloudflare CDN — not the real origin server"
                            >
                              CF
                            </span>
                          )}
                        </div>
                        {sub.reverse_hostname && (
                          <p className="text-[11px] text-shodh-muted/60 truncate mt-0.5" title={sub.reverse_hostname}>
                            ↩ {sub.reverse_hostname}
                          </p>
                        )}
                      </td>
                      <td className="px-6 py-2.5">
                        {statusBadge(sub.is_alive, sub.http_status)}
                      </td>
                      <td className="px-6 py-2.5">
                        {sub.waf_detected === true ? (
                          <span
                            className="text-xs px-2 py-0.5 rounded border text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10"
                            title={sub.waf_name ?? "WAF detected"}
                          >
                            {sub.waf_name ?? "WAF"}
                          </span>
                        ) : sub.waf_detected === false ? (
                          <span className="text-xs text-shodh-muted/50">none</span>
                        ) : (
                          <span className="text-xs text-shodh-muted/30">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Paginator page={subdomainPage} total={scan.subdomains.length} onChange={setSubdomainPage} />
          </motion.div>
        ) : (
          /* Empty subdomains placeholder */
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl p-8 text-center mb-6"
          >
            <Globe className="w-12 h-12 text-shodh-accent/20 mx-auto mb-4" />
            <p className="text-shodh-muted font-mono">
              {scanIsActive ? "Scanning for subdomains..." : "No subdomains discovered."}
            </p>
          </motion.div>
        )}

        {/* ── DNS Records section ─────────────────────────────────────── */}
        {scan.dns_records.length > 0 ? (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden mb-6"
          >
            {/* Card header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
              <div className="flex items-center gap-3">
                <Server className="w-5 h-5 text-shodh-accent" />
                <h2 className="font-mono font-semibold text-shodh-text">
                  DNS Records
                </h2>
              </div>
              <span className="text-xs font-mono text-shodh-muted bg-shodh-border px-2 py-1 rounded">
                {scan.dns_records.length} records
              </span>
            </div>

            {/* Type groups */}
            {Object.entries(groupByType(scan.dns_records.slice((dnsPage-1)*PER_PAGE, dnsPage*PER_PAGE))).map(([rtype, records]) => (
              <div key={rtype} className="border-b border-shodh-border last:border-0">
                {/* Group label */}
                <div className="px-6 py-2 bg-shodh-bg/30 flex items-center gap-2">
                  <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${recordTypeBadge(rtype)}`}>
                    {TIPS[rtype] ? <Tooltip text={rtype} tip={TIPS[rtype]} /> : rtype}
                  </span>
                  <span className="text-xs text-shodh-muted font-mono">
                    {records.length} record{records.length !== 1 ? "s" : ""}
                  </span>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full min-w-[600px] text-sm font-mono">  {/* Mobile scroll */}
                    <thead>
                      <tr className="text-xs text-shodh-muted uppercase tracking-wider">
                        <th className="px-6 py-2 text-left font-normal w-1/3">Hostname</th>
                        <th className="px-6 py-2 text-left font-normal">Value</th>
                        <th className="px-6 py-2 text-right font-normal w-24">TTL</th>
                      </tr>
                    </thead>
                    <tbody>
                      {records.map((rec, i) => (
                        <tr
                          key={i}
                          className="border-t border-shodh-border/40 hover:bg-shodh-border/20 transition-colors"
                        >
                          <td className="px-6 py-2.5 text-shodh-muted truncate max-w-xs">
                            {rec.hostname}
                          </td>
                          <td className="px-6 py-2.5 text-shodh-text break-words max-w-md">  {/* word-break for long TXT */}
                            {rec.value}
                          </td>
                          <td className="px-6 py-2.5 text-right text-shodh-muted">
                            {rec.ttl !== null ? rec.ttl : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ))}
            <Paginator page={dnsPage} total={scan.dns_records.length} onChange={setDnsPage} />
          </motion.div>
        ) : (
          /* ── Empty / scanning placeholder ────────────────────────── */
          <div className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl p-8 text-center">
            <Shield className="w-12 h-12 text-shodh-accent/20 mx-auto mb-4" />
            <p className="text-shodh-muted font-mono">
              {scan.status === "pending"
                ? "Scan queued. Waiting to start..."
                : scan.status === "running"
                ? "Scanning in progress. DNS results will appear here..."
                : scan.status === "completed"
                ? "No DNS records found."
                : "Scan failed. Check error message above."}
            </p>
          </div>
        )}

        {/* ── Email Security section ─────────────────────────────────── */}
        {scan.email_security && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden mb-6"
          >
            {/* Card header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
              <div className="flex items-center gap-3">
                <Mail className="w-5 h-5 text-shodh-accent" />
                <h2 className="font-mono font-semibold text-shodh-text">
                  Email Security
                </h2>
                <span className="text-xs text-shodh-muted font-mono flex items-center gap-1">
                  <Tooltip text="SPF" tip={TIPS.SPF} />
                  <span>·</span>
                  <Tooltip text="DKIM" tip={TIPS.DKIM} />
                  <span>·</span>
                  <Tooltip text="DMARC" tip={TIPS.DMARC} />
                </span>
              </div>

              {/* Spoofable verdict badge */}
              {scan.email_security.is_spoofable === true && (
                <span className="flex items-center gap-1.5 text-xs font-mono font-bold px-3 py-1 rounded-lg border text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10">
                  <ShieldX className="w-3.5 h-3.5" />
                  SPOOFABLE
                </span>
              )}
              {scan.email_security.is_spoofable === false && (
                <span className="flex items-center gap-1.5 text-xs font-mono font-bold px-3 py-1 rounded-lg border text-shodh-accent border-shodh-accent/40 bg-shodh-accent/10">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  PROTECTED
                </span>
              )}
            </div>

            {/* Errors banner (new) */}
            {scan.email_security.errors && scan.email_security.errors.length > 0 && (
              <div className="px-6 py-3 border-b border-shodh-warning/30 bg-shodh-warning/5">
                <details className="cursor-pointer">
                  <summary className="text-xs font-mono text-shodh-warning/80 flex items-center gap-2">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    {scan.email_security.errors.length} warning{scan.email_security.errors.length > 1 ? "s" : ""}
                  </summary>
                  <ul className="mt-2 text-xs text-shodh-warning/70 space-y-1 list-disc list-inside">
                    {scan.email_security.errors.map((err, i) => (
                      <li key={i}>{err}</li>
                    ))}
                  </ul>
                </details>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-shodh-border">

              {/* SPF */}
              <div className="px-6 py-5">
                <div className="flex items-center gap-2 mb-3">
                  {scan.email_security.spf_valid === true  && <ShieldCheck className="w-4 h-4 text-shodh-accent" />}
                  {scan.email_security.spf_valid === false && <ShieldAlert className="w-4 h-4 text-shodh-warning" />}
                  {scan.email_security.spf_valid === null  && <ShieldX className="w-4 h-4 text-shodh-danger" />}
                  <Tooltip text={<span className="text-xs text-shodh-muted font-mono uppercase tracking-wider">SPF</span>} tip={TIPS.SPF} />
                  <span className={`ml-auto text-xs font-mono font-bold px-2 py-0.5 rounded border ${
                    scan.email_security.spf_valid === true
                      ? "text-shodh-accent border-shodh-accent/40 bg-shodh-accent/10"
                      : scan.email_security.spf_valid === false
                      ? "text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10"
                      : "text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10"
                  }`}>
                    {scan.email_security.spf_valid === true  ? "valid"
                      : scan.email_security.spf_valid === false ? "weak"
                      : "missing"}
                  </span>
                </div>
                {/* SPF mechanism badge */}
                {scan.email_security.spf_mechanism && (
                  <div className="mb-2">
                    <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
                      scan.email_security.spf_mechanism === "hard_fail"
                        ? "text-shodh-accent border-shodh-accent/40 bg-shodh-accent/10"
                        : scan.email_security.spf_mechanism === "soft_fail"
                        ? "text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10"
                        : scan.email_security.spf_mechanism === "neutral"
                        ? "text-orange-400 border-orange-400/40 bg-orange-400/10"
                        : "text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10"
                    }`}>
                      {scan.email_security.spf_mechanism === "hard_fail" ? "-all (hard fail)"
                        : scan.email_security.spf_mechanism === "soft_fail" ? "~all (soft fail)"
                        : scan.email_security.spf_mechanism === "neutral" ? "?all (neutral)"
                        : "+all / open"}
                    </span>
                  </div>
                )}
                {scan.email_security.spf_record ? (
                  <div className="space-y-1">
                    <p className="text-xs font-mono text-shodh-muted break-all leading-relaxed">
                      {scan.email_security.spf_record}
                    </p>
                    <button
                      onClick={() => copyToClipboard(scan.email_security!.spf_record!, "SPF record")}
                      className="text-xs text-shodh-muted hover:text-shodh-accent transition-colors flex items-center gap-1"
                      title="Copy SPF record"
                    >
                      <Copy className="w-3 h-3" />
                    </button>
                  </div>
                ) : (
                  <p className="text-xs font-mono text-shodh-danger/70">No SPF record found</p>
                )}
              </div>

              {/* DKIM */}
              <div className="px-6 py-5 md:border-l md:border-shodh-border">
                <div className="flex items-center gap-2 mb-3">
                  {scan.email_security.dkim_found
                    ? <ShieldCheck className="w-4 h-4 text-shodh-accent" />
                    : <ShieldX className="w-4 h-4 text-shodh-danger" />}
                  <Tooltip text={<span className="text-xs text-shodh-muted font-mono uppercase tracking-wider">DKIM</span>} tip={TIPS.DKIM} />
                  <span className={`ml-auto text-xs font-mono font-bold px-2 py-0.5 rounded border ${
                    scan.email_security.dkim_found
                      ? "text-shodh-accent border-shodh-accent/40 bg-shodh-accent/10"
                      : "text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10"
                  }`}>
                    {scan.email_security.dkim_found ? "found" : "missing"}
                  </span>
                </div>
                {scan.email_security.dkim_selector ? (
                  <div className="space-y-1">
                    <p className="text-xs font-mono text-shodh-muted">
                      Selector: <span className="text-shodh-text">{scan.email_security.dkim_selector}</span>
                    </p>
                    {scan.email_security.dkim_record && (
                      <div>
                        <p className="text-xs font-mono text-shodh-muted/70 break-all leading-relaxed">
                          {scan.email_security.dkim_record}
                        </p>
                        <button
                          onClick={() => copyToClipboard(scan.email_security!.dkim_record!, "DKIM record")}
                          className="text-xs text-shodh-muted hover:text-shodh-accent transition-colors flex items-center gap-1"
                          title="Copy DKIM record"
                        >
                          <Copy className="w-3 h-3" />
                        </button>
                      </div>
                    )}
                  </div>
                ) : (
                  <p className="text-xs font-mono text-shodh-danger/70">No DKIM key found on common selectors</p>
                )}
              </div>

              {/* DMARC */}
              <div className="px-6 py-5 md:border-l md:border-shodh-border">
                <div className="flex items-center gap-2 mb-3">
                  {scan.email_security.dmarc_policy === "reject"     && <ShieldCheck className="w-4 h-4 text-shodh-accent" />}
                  {scan.email_security.dmarc_policy === "quarantine" && <ShieldAlert className="w-4 h-4 text-shodh-warning" />}
                  {(scan.email_security.dmarc_policy === "none" || scan.email_security.dmarc_policy === "invalid" || !scan.email_security.dmarc_policy) && <ShieldX className="w-4 h-4 text-shodh-danger" />}
                  <Tooltip text={<span className="text-xs text-shodh-muted font-mono uppercase tracking-wider">DMARC</span>} tip={TIPS.DMARC} />
                  <span className={`ml-auto text-xs font-mono font-bold px-2 py-0.5 rounded border ${
                    scan.email_security.dmarc_policy === "reject"
                      ? "text-shodh-accent border-shodh-accent/40 bg-shodh-accent/10"
                      : scan.email_security.dmarc_policy === "quarantine"
                      ? "text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10"
                      : "text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10"
                  }`}>
                    {scan.email_security.dmarc_policy ?? "missing"}
                  </span>
                </div>
                {/* DMARC pct warning */}
                {scan.email_security.dmarc_pct !== null && scan.email_security.dmarc_pct < 100 && (
                  <p className="text-xs font-mono text-shodh-warning mb-2">
                    pct={scan.email_security.dmarc_pct} ({scan.email_security.dmarc_pct}% enforcement)
                  </p>
                )}
                {scan.email_security.dmarc_record ? (
                  <div className="space-y-1">
                    <p className="text-xs font-mono text-shodh-muted break-all leading-relaxed">
                      {scan.email_security.dmarc_record}
                    </p>
                    <button
                      onClick={() => copyToClipboard(scan.email_security!.dmarc_record!, "DMARC record")}
                      className="text-xs text-shodh-muted hover:text-shodh-accent transition-colors flex items-center gap-1"
                      title="Copy DMARC record"
                    >
                      <Copy className="w-3 h-3" />
                    </button>
                  </div>
                ) : (
                  <p className="text-xs font-mono text-shodh-danger/70">No DMARC record found</p>
                )}
              </div>
            </div>

            {/* MTA-STS row */}
            <div className="px-6 py-4 border-t border-shodh-border flex items-center gap-3">
              <span className="text-xs text-shodh-muted font-mono uppercase tracking-wider">MTA-STS</span>
              <Tooltip
                text={<span className="text-xs text-shodh-muted font-mono">mode</span>}
                tip="MTA-STS (Mail Transfer Agent Strict Transport Security) forces email servers to use TLS when delivering to your domain, preventing downgrade attacks."
              />
              <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
                scan.email_security.mta_sts_mode === "enforce"
                  ? "text-shodh-accent border-shodh-accent/40 bg-shodh-accent/10"
                  : scan.email_security.mta_sts_mode === "testing"
                  ? "text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10"
                  : "text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10"
              }`}>
                {scan.email_security.mta_sts_mode ?? "not configured"}
              </span>
              {!scan.email_security.mta_sts_mode && (
                <span className="text-xs font-mono text-shodh-muted/70">
                  — no _mta-sts TXT record found
                </span>
              )}
            </div>

            {/* Spoofable explanation banner */}
            {scan.email_security.is_spoofable === true && (
              <div className="px-6 py-4 border-t border-shodh-border bg-shodh-danger/5 flex items-start gap-3">
                <ShieldX className="w-4 h-4 text-shodh-danger mt-0.5 flex-shrink-0" />
                <p className="text-xs font-mono text-shodh-danger/80 leading-relaxed">
                  An attacker can send email appearing to come from <strong>@{scan.domain}</strong> and it will pass basic checks.
                  Add a valid SPF record with <code className="bg-shodh-border px-1 rounded">-all</code> and set DMARC policy to <code className="bg-shodh-border px-1 rounded">quarantine</code> or <code className="bg-shodh-border px-1 rounded">reject</code> to fix this.
                </p>
              </div>
            )}
          </motion.div>
        )}

        {/* ── WHOIS section ───────────────────────────────────────── */}
        {scan.whois_info && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden mb-6"
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
              <div className="flex items-center gap-3">
                <Building2 className="w-5 h-5 text-shodh-accent" />
                <h2 className="font-mono font-semibold text-shodh-text">WHOIS</h2>
                <span className="text-xs text-shodh-muted font-mono">Domain Registration</span>
              </div>
              {scan.whois_info.error && (
                <span className="text-xs font-mono text-shodh-warning border border-shodh-warning/40 bg-shodh-warning/10 px-2 py-0.5 rounded">
                  partial data
                </span>
              )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-0 divide-y md:divide-y-0 md:divide-x divide-shodh-border">
              {/* Left: registration dates + registrar */}
              <div className="px-6 py-5 space-y-3">
                {scan.whois_info.registrar && (
                  <div>
                    <p className="text-[10px] text-shodh-muted font-mono uppercase tracking-wider mb-0.5">Registrar</p>
                    <p className="text-sm font-mono text-shodh-text">{scan.whois_info.registrar}</p>
                  </div>
                )}
                <div className="grid grid-cols-2 gap-3">
                  {scan.whois_info.creation_date && (
                    <div>
                      <p className="text-[10px] text-shodh-muted font-mono uppercase tracking-wider mb-0.5 flex items-center gap-1">
                        <Calendar className="w-3 h-3" /> Created
                      </p>
                      <p className="text-sm font-mono text-shodh-text">
                        {new Date(scan.whois_info.creation_date).toLocaleDateString()}
                      </p>
                    </div>
                  )}
                  {scan.whois_info.expiry_date && (
                    <div>
                      <p className="text-[10px] text-shodh-muted font-mono uppercase tracking-wider mb-0.5 flex items-center gap-1">
                        <Calendar className="w-3 h-3" /> Expires
                      </p>
                      <p className={`text-sm font-mono ${
                        new Date(scan.whois_info.expiry_date) < new Date()
                          ? "text-shodh-danger"
                          : new Date(scan.whois_info.expiry_date) < new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
                          ? "text-shodh-warning"
                          : "text-shodh-text"
                      }`}>
                        {new Date(scan.whois_info.expiry_date).toLocaleDateString()}
                      </p>
                    </div>
                  )}
                </div>
                {scan.whois_info.dnssec && (
                  <div>
                    <p className="text-[10px] text-shodh-muted font-mono uppercase tracking-wider mb-0.5">DNSSEC</p>
                    <p className="text-sm font-mono text-shodh-text">{scan.whois_info.dnssec}</p>
                  </div>
                )}
              </div>

              {/* Right: registrant + name servers */}
              <div className="px-6 py-5 space-y-3">
                {(scan.whois_info.registrant_name || scan.whois_info.registrant_org) && (
                  <div>
                    <p className="text-[10px] text-shodh-muted font-mono uppercase tracking-wider mb-0.5 flex items-center gap-1">
                      <User className="w-3 h-3" /> Registrant
                    </p>
                    {scan.whois_info.registrant_org && (
                      <p className="text-sm font-mono text-shodh-text">{scan.whois_info.registrant_org}</p>
                    )}
                    {scan.whois_info.registrant_name && scan.whois_info.registrant_name !== scan.whois_info.registrant_org && (
                      <p className="text-xs font-mono text-shodh-muted">{scan.whois_info.registrant_name}</p>
                    )}
                    {scan.whois_info.registrant_country && (
                      <p className="text-xs font-mono text-shodh-muted/70">{scan.whois_info.registrant_country}</p>
                    )}
                  </div>
                )}
                {scan.whois_info.name_servers && scan.whois_info.name_servers.length > 0 && (
                  <div>
                    <p className="text-[10px] text-shodh-muted font-mono uppercase tracking-wider mb-1">Name Servers</p>
                    <div className="space-y-0.5">
                      {scan.whois_info.name_servers.slice(0, 6).map((ns, i) => (
                        <p key={i} className="text-xs font-mono text-shodh-text/80">{ns}</p>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        )}

        {/* ── WHOIS Risk Flag Analysis ── */}
        {scan.status === "completed" && scan.whois_info && !scan.whois_info.error && (() => {
          const now = new Date();
          const flags: { level: "critical" | "warning" | "info"; title: string; detail: string }[] = [];

          // Flag 1: Domain age < 1 year
          if (scan.whois_info.creation_date) {
            const created = new Date(scan.whois_info.creation_date);
            const ageDays = (now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24);
            if (ageDays < 365) {
              flags.push({
                level: "warning",
                title: "Newly Registered Domain",
                detail: `Registered ${Math.round(ageDays)} days ago. Newly registered domains are disproportionately used for phishing, malware distribution, and fraud. Treat with elevated suspicion.`,
              });
            }
          }

          // Flag 2: Expiring within 30 days → domain takeover risk
          if (scan.whois_info.expiry_date) {
            const expiry = new Date(scan.whois_info.expiry_date);
            const daysLeft = (expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
            if (daysLeft < 0) {
              flags.push({
                level: "critical",
                title: "Domain Expired",
                detail: `This domain expired ${Math.abs(Math.round(daysLeft))} days ago. If not renewed it may be re-registered by a threat actor — domain takeover risk.`,
              });
            } else if (daysLeft <= 30) {
              flags.push({
                level: "critical",
                title: "Domain Expiring Soon",
                detail: `Expires in ${Math.round(daysLeft)} day${Math.round(daysLeft) !== 1 ? "s" : ""}. If the owner misses renewal an attacker can register it immediately — domain takeover risk.`,
              });
            } else if (daysLeft <= 90) {
              flags.push({
                level: "warning",
                title: "Domain Expiring in < 90 Days",
                detail: `Expires in ${Math.round(daysLeft)} days. Monitor renewal status to prevent accidental lapse.`,
              });
            }
          }

          // Flag 3: WHOIS privacy / proxy registration
          const privacyKeywords = [
            "privacy", "protect", "whoisguard", "proxy", "redacted", "withheld",
            "gdpr", "data protected", "registrant redacted", "not disclosed",
          ];
          const contactFields = [
            scan.whois_info.registrant_name,
            scan.whois_info.registrant_email,
            scan.whois_info.registrant_org,
          ].filter(Boolean).map(s => s!.toLowerCase());
          const hasPrivacy = contactFields.some(f =>
            privacyKeywords.some(kw => f.includes(kw))
          ) || contactFields.length === 0;
          if (hasPrivacy) {
            flags.push({
              level: "info",
              title: "WHOIS Privacy Enabled",
              detail: "Registrant details are hidden by a privacy/proxy service. Legitimate for privacy, but also commonly used by malicious actors to obscure ownership.",
            });
          }

          // Flag 4: No expiry date found
          if (!scan.whois_info.expiry_date && !scan.whois_info.error) {
            flags.push({
              level: "info",
              title: "Expiry Date Not Found",
              detail: "Could not determine domain expiry date from WHOIS data. Manual verification recommended.",
            });
          }

          if (flags.length === 0) return null;

          return (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden mb-6"
            >
              <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
                <div className="flex items-center gap-3">
                  <AlertTriangle className="w-5 h-5 text-shodh-warning" />
                  <div>
                    <h2 className="text-sm font-semibold text-shodh-text font-sans uppercase tracking-wider">
                      WHOIS Risk Analysis
                    </h2>
                    <span className="text-xs font-mono text-shodh-muted/60">Registration date · expiry · privacy flags</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {flags.filter(f => f.level === "critical").length > 0 && (
                    <span className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10">
                      {flags.filter(f => f.level === "critical").length} critical
                    </span>
                  )}
                  {flags.filter(f => f.level === "warning").length > 0 && (
                    <span className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10">
                      {flags.filter(f => f.level === "warning").length} warning
                    </span>
                  )}
                </div>
              </div>
              <div className="divide-y divide-shodh-border/40">
                {flags.map((flag, i) => (
                  <div
                    key={i}
                    className={`px-6 py-4 flex items-start gap-4 ${
                      flag.level === "critical"
                        ? "bg-shodh-danger/5"
                        : flag.level === "warning"
                        ? "bg-shodh-warning/5"
                        : ""
                    }`}
                  >
                    <span className={`mt-0.5 text-lg leading-none ${
                      flag.level === "critical" ? "text-shodh-danger" :
                      flag.level === "warning" ? "text-shodh-warning" :
                      "text-shodh-info"
                    }`}>
                      {flag.level === "critical" ? "🔴" : flag.level === "warning" ? "🟡" : "🔵"}
                    </span>
                    <div>
                      <p className={`text-sm font-semibold font-sans mb-1 ${
                        flag.level === "critical" ? "text-shodh-danger" :
                        flag.level === "warning" ? "text-shodh-warning" :
                        "text-shodh-info"
                      }`}>
                        {flag.title}
                      </p>
                      <p className="text-xs font-mono text-shodh-muted/80 leading-relaxed">{flag.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </motion.div>
          );
        })()}

        {/* ── Reverse IP Lookup ── */}
        {scan.status === "completed" && scan.reverse_ip && scan.reverse_ip.length > 0 && (() => {
          const realEntries = scan.reverse_ip.filter(e => !e.skipped_reason && !e.error && e.domain_count > 0);
          const skippedEntries = scan.reverse_ip.filter(e => !!e.skipped_reason);
          if (realEntries.length === 0 && skippedEntries.length === 0) return null;
          return (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden mb-6"
            >
              <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
                <div className="flex items-center gap-3">
                  <Network className="w-5 h-5 text-shodh-info" />
                  <div>
                    <h2 className="text-sm font-semibold text-shodh-text font-sans uppercase tracking-wider">
                      Reverse IP Lookup
                    </h2>
                    <span className="text-xs font-mono text-shodh-muted/60">Co-hosted domains via HackerTarget — shared hosting detection</span>
                  </div>
                </div>
                {realEntries.length > 0 ? (
                  <span className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-info border-shodh-info/40 bg-shodh-info/10">
                    {realEntries.reduce((a, e) => a + e.domain_count, 0)} domains found
                  </span>
                ) : (
                  <span className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-muted border-shodh-border bg-shodh-border/30">
                    all IPs are CDN
                  </span>
                )}
              </div>

              {realEntries.length > 0 && (
                <div className="divide-y divide-shodh-border/40">
                  {realEntries.map((entry, i) => (
                    <div key={i} className="px-6 py-4">
                      <div className="flex items-center gap-3 mb-3">
                        <span className="text-xs font-mono text-shodh-accent bg-shodh-accent/10 border border-shodh-accent/30 px-2 py-0.5 rounded">
                          {entry.ip_address}
                        </span>
                        <span className="text-xs font-mono text-shodh-muted">
                          {entry.domain_count} domain{entry.domain_count !== 1 ? "s" : ""} on this IP
                        </span>
                        {entry.domain_count > 10 && (
                          <span className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10">
                            Shared hosting
                          </span>
                        )}
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {(entry.co_hosted_domains ?? []).slice(0, 30).map((domain, j) => (
                          <span key={j} className="text-xs font-mono px-2 py-0.5 rounded bg-shodh-border/40 text-shodh-muted border border-shodh-border/60">
                            {domain}
                          </span>
                        ))}
                        {(entry.co_hosted_domains?.length ?? 0) > 30 && (
                          <span className="text-xs font-mono text-shodh-muted/60 self-center">
                            +{(entry.co_hosted_domains?.length ?? 0) - 30} more
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {skippedEntries.length > 0 && (
                <div className="px-6 py-3 border-t border-shodh-border/40 flex flex-wrap gap-2 items-center">
                  <span className="text-xs font-mono text-shodh-muted/50">CDN IPs skipped:</span>
                  {skippedEntries.map((e, i) => (
                    <span key={i} className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-muted/50 border-shodh-border/40 bg-shodh-border/20"
                      title="Shared CDN infrastructure — reverse lookup would return thousands of unrelated domains">
                      {e.ip_address} <span className="opacity-50">(CDN)</span>
                    </span>
                  ))}
                </div>
              )}

              <p className="px-6 py-3 text-xs font-mono text-shodh-muted/60 border-t border-shodh-border/40">
                CDN IPs (Cloudflare, CloudFront, Fastly, Akamai) are skipped — they are shared by millions of sites and produce no actionable signal.
              </p>
            </motion.div>
          );
        })()}

        {/* ── AlienVault OTX Threat Intel ── */}
        {scan.status === "completed" && scan.otx_result && !scan.otx_result.error && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden mb-6"
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
              <div className="flex items-center gap-3">
                <AlertOctagon className="w-5 h-5 text-shodh-danger" />
                <div>
                  <h2 className="text-sm font-semibold text-shodh-text font-sans uppercase tracking-wider">
                    Threat Intelligence — OTX
                  </h2>
                  <span className="text-xs font-mono text-shodh-muted/60">AlienVault OTX · threat actor reports · malware correlation</span>
                </div>
              </div>
              {scan.otx_result.is_known_malicious ? (
                <span className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10">
                  ⚠ Flagged in {scan.otx_result.pulse_count} report{scan.otx_result.pulse_count !== 1 ? "s" : ""}
                </span>
              ) : (
                <span className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-accent border-shodh-accent/40 bg-shodh-accent/10">
                  Clean — 0 threat reports
                </span>
              )}
            </div>

            {/* Stats row */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-shodh-border/30 border-b border-shodh-border">
              {[
                {
                  label: "OTX Pulses",
                  value: String(scan.otx_result.pulse_count),
                  color: scan.otx_result.pulse_count > 0 ? "text-shodh-danger" : "text-shodh-accent",
                },
                {
                  label: "Malware Families",
                  value: String(scan.otx_result.malware_families?.length ?? 0),
                  color: (scan.otx_result.malware_families?.length ?? 0) > 0 ? "text-shodh-danger" : "text-shodh-accent",
                },
                {
                  label: "Threat Tags",
                  value: String(scan.otx_result.threat_types?.length ?? 0),
                  color: (scan.otx_result.threat_types?.length ?? 0) > 0 ? "text-shodh-warning" : "text-shodh-accent",
                },
                {
                  label: "Alexa Rank",
                  value: scan.otx_result.alexa_rank ? `#${scan.otx_result.alexa_rank.toLocaleString()}` : "N/A",
                  color: "text-shodh-muted",
                },
              ].map((stat, i) => (
                <div key={i} className="bg-shodh-surface/40 px-6 py-4">
                  <p className="text-xs text-shodh-muted font-mono mb-1">{stat.label}</p>
                  <p className={`text-2xl font-bold font-mono ${stat.color}`}>{stat.value}</p>
                </div>
              ))}
            </div>

            {/* Threat tags */}
            {scan.otx_result.threat_types && scan.otx_result.threat_types.length > 0 && (
              <div className="px-6 py-4 border-b border-shodh-border/40">
                <p className="text-xs text-shodh-muted font-mono mb-2 uppercase tracking-wider">Threat Tags</p>
                <div className="flex flex-wrap gap-2">
                  {scan.otx_result.threat_types.map((tag, i) => (
                    <span key={i} className="text-xs px-2 py-0.5 rounded border text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10 font-mono">
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Malware families */}
            {scan.otx_result.malware_families && scan.otx_result.malware_families.length > 0 && (
              <div className="px-6 py-4 border-b border-shodh-border/40">
                <p className="text-xs text-shodh-muted font-mono mb-2 uppercase tracking-wider">Malware Families</p>
                <div className="flex flex-wrap gap-2">
                  {scan.otx_result.malware_families.map((fam, i) => (
                    <span key={i} className="text-xs px-2 py-0.5 rounded border text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10 font-mono">
                      {fam}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Additional info */}
            <div className="px-6 py-4">
              <div className="flex flex-wrap gap-x-8 gap-y-2">
                {scan.otx_result.country && (
                  <div>
                    <span className="text-xs text-shodh-muted font-mono">Country: </span>
                    <span className="text-xs text-shodh-text font-mono">{scan.otx_result.country}</span>
                  </div>
                )}
                {scan.otx_result.first_seen && (
                  <div>
                    <span className="text-xs text-shodh-muted font-mono">First Seen: </span>
                    <span className="text-xs text-shodh-text font-mono">
                      {new Date(scan.otx_result.first_seen).toLocaleDateString()}
                    </span>
                  </div>
                )}
              </div>
              {!scan.otx_result.is_known_malicious && (
                <p className="text-xs font-mono text-shodh-accent/70 mt-3">
                  ✓ No threat intelligence reports found for this domain in OTX database.
                </p>
              )}
            </div>
          </motion.div>
        )}

        {/* ── Open Ports section ──────────────────────────────────── */}
        {allPorts.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden mb-6"
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
              <div className="flex items-center gap-3">
                <Activity className="w-5 h-5 text-shodh-accent" />
                <h2 className="font-mono font-semibold text-shodh-text">Open Ports</h2>
              </div>
              <span className="text-xs font-mono text-shodh-muted bg-shodh-border px-2 py-1 rounded">
                {allPorts.length} port{allPorts.length !== 1 ? "s" : ""}
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[500px] text-sm font-mono">
                <thead>
                  <tr className="text-xs text-shodh-muted uppercase tracking-wider border-b border-shodh-border">
                    <th className="px-6 py-2 text-left font-normal">Host</th>
                    <th className="px-6 py-2 text-left font-normal">Port</th>
                    <th className="px-6 py-2 text-left font-normal">Protocol</th>
                    <th className="px-6 py-2 text-left font-normal">Service</th>
                    <th className="px-6 py-2 text-left font-normal">Version / Banner</th>
                  </tr>
                </thead>
                <tbody>
                  {allPorts.slice((portsPage-1)*PER_PAGE, portsPage*PER_PAGE).map((p, i) => (
                    <tr key={i} className="border-t border-shodh-border/40 hover:bg-shodh-border/20 transition-colors">
                      <td className="px-6 py-2.5 text-shodh-muted truncate max-w-xs">{p.hostname}</td>
                      <td className="px-6 py-2.5">
                        <span className="text-xs px-2 py-0.5 rounded border text-shodh-accent border-shodh-accent/40 bg-shodh-accent/10">
                          {p.port_number}
                        </span>
                      </td>
                      <td className="px-6 py-2.5 text-shodh-muted">{p.protocol.toUpperCase()}</td>
                      <td className="px-6 py-2.5 text-shodh-text">{p.service ?? "—"}</td>
                      <td className="px-6 py-2.5 max-w-xs">
                        {p.version ? (
                          <span className="text-xs text-shodh-info font-mono">{p.version}</span>
                        ) : p.banner ? (
                          <span className="text-xs text-shodh-muted font-mono truncate block max-w-[220px]" title={p.banner}>
                            {p.banner.slice(0, 60)}{p.banner.length > 60 ? "…" : ""}
                          </span>
                        ) : (
                          <span className="text-shodh-muted/40">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Paginator page={portsPage} total={allPorts.length} onChange={setPortsPage} />
          </motion.div>
        )}

        {/* ── Technologies section ─────────────────────────────────── */}
        {allTechs.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.35 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden mb-6"
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
              <div className="flex items-center gap-3">
                <Cpu className="w-5 h-5 text-shodh-accent" />
                <h2 className="font-mono font-semibold text-shodh-text">Technologies</h2>
              </div>
              <span className="text-xs font-mono text-shodh-muted bg-shodh-border px-2 py-1 rounded">
                {allTechs.length} detected
              </span>
            </div>
            <div className="px-6 py-5">
              {/* Group by category */}
              {(() => {
                const byCategory = allTechs.reduce<Record<string, typeof allTechs>>((acc, t) => {
                  const cat = t.category ?? "Other";
                  (acc[cat] ??= []).push(t);
                  return acc;
                }, {});
                return Object.entries(byCategory).map(([cat, techs]) => (
                  <div key={cat} className="mb-4 last:mb-0">
                    <p className="text-[10px] text-shodh-muted font-mono uppercase tracking-wider mb-2">{cat}</p>
                    <div className="flex flex-wrap gap-2">
                      {techs.map((t, i) => (
                        <span
                          key={i}
                          className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-lg border text-shodh-text border-shodh-border bg-shodh-border/50 font-mono"
                          title={`Detected on: ${(t as typeof t & { hostnames: string[] }).hostnames?.join(", ")}`}
                        >
                          {t.name}
                          {t.version && (
                            <span className="text-shodh-muted text-[10px]">{t.version}</span>
                          )}
                        </span>
                      ))}
                    </div>
                  </div>
                ));
              })()}
            </div>
          </motion.div>
        )}

        {/* ── WAF / CDN summary section ────────────────────────────── */}
        {scan.subdomains.some((s) => s.waf_detected !== null) && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.38 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden mb-6"
          >
            <div className="flex items-center gap-3 px-6 py-4 border-b border-shodh-border">
              <Wifi className="w-5 h-5 text-shodh-warning" />
              <h2 className="font-mono font-semibold text-shodh-text">WAF / CDN Detection</h2>
              <span className="text-xs text-shodh-muted font-mono">via wafw00f</span>
            </div>

            {scan.subdomains.some((s) => s.waf_detected === true) ? (
              <>
                <div className="px-6 py-4 flex flex-wrap gap-3">
                  {Array.from(
                    new Map(
                      scan.subdomains
                        .filter((s) => s.waf_detected && s.waf_name)
                        .map((s) => [s.waf_name, s])
                    ).values()
                  ).map((s, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-2 px-3 py-2 rounded-lg border border-shodh-warning/30 bg-shodh-warning/5"
                    >
                      <Shield className="w-3.5 h-3.5 text-shodh-warning" />
                      <span className="text-sm font-mono text-shodh-text">{s.waf_name}</span>
                    </div>
                  ))}
                </div>
                <p className="px-6 pb-4 text-xs font-mono text-shodh-muted/70">
                  WAF/CDN detected on {scan.subdomains.filter((s) => s.waf_detected).length} of {scan.subdomains.filter((s) => s.is_alive).length} alive subdomains.
                  These protect against common web attacks but may hide the real origin server IP.
                </p>
              </>
            ) : (
              <div className="px-6 py-5 flex items-center gap-3">
                <ShieldCheck className="w-5 h-5 text-shodh-accent flex-shrink-0" />
                <div>
                  <p className="text-sm font-mono text-shodh-accent">No WAF / CDN detected</p>
                  <p className="text-xs font-mono text-shodh-muted mt-0.5">
                    None of the {scan.subdomains.filter((s) => s.is_alive).length} alive subdomains appear to be behind a WAF or CDN.
                    The origin server may be directly exposed.
                  </p>
                </div>
              </div>
            )}
          </motion.div>
        )}

        {/* ── Feature 13: Unprotected Asset Flagging ──────────────── */}
        {flaggedSubdomains.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.39 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-danger/40 rounded-xl overflow-hidden mb-6"
          >
            <div className="flex items-center gap-3 px-6 py-4 border-b border-shodh-danger/20 bg-shodh-danger/5">
              <AlertOctagon className="w-5 h-5 text-shodh-danger flex-shrink-0" />
              <div className="flex-1">
                <h2 className="font-mono font-semibold text-shodh-text">Unprotected Assets</h2>
                <p className="text-xs font-mono text-shodh-muted mt-0.5">
                  These subdomains have <span className="text-shodh-danger">no WAF protection</span> while other parts of this domain are protected.
                </p>
              </div>
              <span className="text-xs font-mono text-shodh-danger bg-shodh-danger/10 border border-shodh-danger/30 px-2 py-1 rounded">
                {flaggedSubdomains.length} at risk
              </span>
            </div>
            <div className="px-6 py-4 flex flex-wrap gap-2">
              {flaggedSubdomains.map((s) => (
                <div
                  key={s.id}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg border border-shodh-danger/30 bg-shodh-danger/5"
                >
                  <ShieldX className="w-3.5 h-3.5 text-shodh-danger flex-shrink-0" />
                  <span className="text-sm font-mono text-shodh-text">{s.hostname}</span>
                  {s.ip_address && (
                    <span className="text-xs font-mono text-shodh-muted">{s.ip_address}</span>
                  )}
                </div>
              ))}
            </div>
            <p className="px-6 pb-4 text-xs font-mono text-shodh-muted/70">
              Origin servers without WAF protection are directly reachable and more exposed to web attacks.
              Consider adding Cloudflare, AWS WAF, or similar protection.
            </p>
          </motion.div>
        )}

        {/* ── Feature 15: Security Headers Analysis ────────────────── */}
        {headerScanned.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.41 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden mb-6"
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
              <div className="flex items-center gap-3">
                <FileText className="w-5 h-5 text-shodh-info" />
                <h2 className="font-mono font-semibold text-shodh-text">Security Headers</h2>
              </div>
              <span className="text-xs font-mono text-shodh-muted bg-shodh-border px-2 py-1 rounded">
                {headerScanned.length} subdomain{headerScanned.length !== 1 ? "s" : ""} analyzed
              </span>
            </div>

            {/* Legend */}
            <div className="flex items-center gap-4 px-6 pt-3 pb-1">
              <div className="flex items-center gap-1.5 text-xs font-mono text-shodh-muted">
                <CheckCircle2 className="w-3.5 h-3.5 text-shodh-accent" /> Present
              </div>
              <div className="flex items-center gap-1.5 text-xs font-mono text-shodh-muted">
                <XCircle className="w-3.5 h-3.5 text-shodh-danger" /> Missing
              </div>
              <div className="flex items-center gap-1.5 text-xs font-mono text-shodh-muted">
                <span className="text-shodh-muted/50">—</span> Not checked
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full min-w-[700px] text-sm font-mono">
                <thead>
                  <tr className="text-xs text-shodh-muted uppercase tracking-wider border-b border-shodh-border">
                    <th className="px-6 py-2 text-left font-normal">Subdomain</th>
                    <th className="px-4 py-2 text-center font-normal">Score</th>
                    <th className="px-3 py-2 text-center font-normal"><Tooltip text="HSTS" tip={TIPS.HSTS} /></th>
                    <th className="px-3 py-2 text-center font-normal"><Tooltip text="CSP" tip={TIPS.CSP} /></th>
                    <th className="px-3 py-2 text-center font-normal"><Tooltip text="XFO" tip={TIPS["X-Frame-Options"]} /></th>
                    <th className="px-3 py-2 text-center font-normal"><Tooltip text="XCTO" tip={TIPS["X-Content-Type-Options"]} /></th>
                    <th className="px-3 py-2 text-center font-normal"><Tooltip text="RP" tip={TIPS["Referrer-Policy"]} /></th>
                    <th className="px-3 py-2 text-center font-normal"><Tooltip text="PP" tip={TIPS["Permissions-Policy"]} /></th>
                    <th className="px-6 py-2 text-left font-normal">Server</th>
                  </tr>
                </thead>
                <tbody>
                  {headerScanned.slice((headersPage-1)*PER_PAGE, headersPage*PER_PAGE).map((sub) => {
                    const ha = sub.header_analysis!;
                    const checkCell = (present: boolean | null) =>
                      present === true ? (
                        <CheckCircle2 className="w-4 h-4 text-shodh-accent mx-auto" />
                      ) : present === false ? (
                        <XCircle className="w-4 h-4 text-shodh-danger mx-auto" />
                      ) : (
                        <span className="text-shodh-muted/40 text-center block">—</span>
                      );
                    return (
                      <tr key={sub.id} className="border-t border-shodh-border/40 hover:bg-shodh-border/20 transition-colors">
                        <td className="px-6 py-2.5 text-shodh-muted truncate max-w-[200px]">{sub.hostname}</td>
                        <td className="px-4 py-2.5 text-center">
                          <span className={`text-xs px-2 py-0.5 rounded border font-mono font-semibold ${scoreColor(ha.security_score)} ${scoreBg(ha.security_score)}`}>
                            {ha.security_score ?? "—"}
                          </span>
                        </td>
                        <td className="px-3 py-2.5 text-center" title={ha.hsts_value ?? undefined}>{checkCell(ha.has_hsts)}</td>
                        <td className="px-3 py-2.5 text-center" title={ha.csp_value?.slice(0, 80) ?? undefined}>{checkCell(ha.has_csp)}</td>
                        <td className="px-3 py-2.5 text-center" title={ha.x_frame_options_value ?? undefined}>{checkCell(ha.has_x_frame_options)}</td>
                        <td className="px-3 py-2.5 text-center">{checkCell(ha.has_x_content_type_options)}</td>
                        <td className="px-3 py-2.5 text-center" title={ha.referrer_policy_value ?? undefined}>{checkCell(ha.has_referrer_policy)}</td>
                        <td className="px-3 py-2.5 text-center">{checkCell(ha.has_permissions_policy)}</td>
                        <td className="px-6 py-2.5 text-shodh-muted/70 truncate max-w-[160px] text-xs">
                          {ha.server_banner ?? <span className="text-shodh-muted/30">—</span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Summary of most common missing headers */}
            {(() => {
              const missing = headerScanned
                .flatMap((s) => s.header_analysis?.missing_headers ?? [])
                .reduce<Record<string, number>>((acc, h) => { acc[h] = (acc[h] ?? 0) + 1; return acc; }, {});
              const sorted = Object.entries(missing).sort((a, b) => b[1] - a[1]);
              if (sorted.length === 0) return null;
              return (
                <div className="px-6 py-4 border-t border-shodh-border/40">
                  <p className="text-[10px] text-shodh-muted font-mono uppercase tracking-wider mb-2">Most commonly missing</p>
                  <div className="flex flex-wrap gap-2">
                    {sorted.map(([header, count]) => (
                      <span key={header} className="text-xs px-2 py-0.5 rounded border font-mono text-shodh-danger border-shodh-danger/30 bg-shodh-danger/5">
                        {TIPS[header] ? (
                          <Tooltip text={header} tip={TIPS[header]} />
                        ) : header}
                        {" "}<span className="text-shodh-muted/60">×{count}</span>
                      </span>
                    ))}
                  </div>
                </div>
              );
            })()}
            <Paginator page={headersPage} total={headerScanned.length} onChange={setHeadersPage} />
          </motion.div>
        )}

        {/* ── Features 16/17: SSL / TLS Analysis ───────────────────── */}
        {sslScanned.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.43 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden mb-6"
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
              <div className="flex items-center gap-3">
                <Lock className="w-5 h-5 text-shodh-purple" />
                <h2 className="font-mono font-semibold text-shodh-text">SSL / TLS Analysis</h2>
              </div>
              <span className="text-xs font-mono text-shodh-muted bg-shodh-border px-2 py-1 rounded">
                {sslScanned.length} subdomain{sslScanned.length !== 1 ? "s" : ""} analyzed
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full min-w-[700px] text-sm font-mono">
                <thead>
                  <tr className="text-xs text-shodh-muted uppercase tracking-wider border-b border-shodh-border">
                    <th className="px-6 py-2 text-left font-normal">Subdomain</th>
                    <th className="px-4 py-2 text-center font-normal">Grade</th>
                    <th className="px-4 py-2 text-left font-normal">Issuer</th>
                    <th className="px-4 py-2 text-left font-normal">Expires</th>
                    <th className="px-6 py-2 text-left font-normal">Protocols</th>
                    <th className="px-4 py-2 text-left font-normal">Flags</th>
                  </tr>
                </thead>
                <tbody>
                  {sslScanned.slice((sslPage-1)*PER_PAGE, sslPage*PER_PAGE).map((sub) => {
                    const ssl = sub.ssl_info!;
                    const expiry = ssl.valid_until ? new Date(ssl.valid_until) : null;
                    const daysLeft = expiry
                      ? Math.ceil((expiry.getTime() - Date.now()) / 86_400_000)
                      : null;
                    const activeVulns = ssl.vulnerabilities
                      ? Object.entries(ssl.vulnerabilities).filter(([, v]) => v).map(([k]) => k)
                      : [];
                    return (
                      <tr key={sub.id} className="border-t border-shodh-border/40 hover:bg-shodh-border/20 transition-colors">
                        <td className="px-6 py-2.5 text-shodh-muted truncate max-w-[180px]">{sub.hostname}</td>
                        <td className="px-4 py-2.5 text-center">
                          <span className={`text-sm px-2.5 py-0.5 rounded border font-mono font-bold ${gradeColor(ssl.grade)} ${gradeBg(ssl.grade)}`}>
                            {ssl.grade ?? "—"}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-shodh-text/80 truncate max-w-[160px] text-xs">
                          {ssl.issuer ?? <span className="text-shodh-muted/40">—</span>}
                        </td>
                        <td className="px-4 py-2.5 text-xs">
                          {expiry ? (
                            <span className={
                              ssl.is_expired
                                ? "text-shodh-danger"
                                : daysLeft !== null && daysLeft < 30
                                ? "text-shodh-warning"
                                : "text-shodh-muted"
                            }>
                              {ssl.is_expired
                                ? "Expired"
                                : daysLeft !== null && daysLeft < 30
                                ? `${daysLeft}d left`
                                : expiry.toLocaleDateString()}
                            </span>
                          ) : (
                            <span className="text-shodh-muted/40">—</span>
                          )}
                        </td>
                        <td className="px-6 py-2.5">
                          <div className="flex flex-wrap gap-1">
                            {ssl.protocols && Object.entries(ssl.protocols).map(([proto, supported]) => (
                              <span
                                key={proto}
                                className={`text-[10px] px-1.5 py-0.5 rounded border font-mono ${
                                  supported
                                    ? proto === "TLS 1.0" || proto === "TLS 1.1"
                                      ? "text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10"
                                      : "text-shodh-accent border-shodh-accent/40 bg-shodh-accent/10"
                                    : "text-shodh-muted/40 border-shodh-border/40 line-through"
                                }`}
                              >
                                {TIPS[proto] ? <Tooltip text={proto} tip={TIPS[proto]} /> : proto}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="px-4 py-2.5">
                          <div className="flex flex-wrap gap-1">
                            {ssl.is_expired && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded border text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10 font-mono">
                                Expired
                              </span>
                            )}
                            {activeVulns.map((v) => (
                              <span key={v} className="text-[10px] px-1.5 py-0.5 rounded border text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10 font-mono">
                                {TIPS[v] ? <Tooltip text={v} tip={TIPS[v]} /> : v}
                              </span>
                            ))}
                            {!ssl.is_expired && activeVulns.length === 0 && (
                              <span className="text-[10px] text-shodh-accent/60 font-mono">Clean</span>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Grade distribution summary */}
            {(() => {
              const gradeCounts = sslScanned.reduce<Record<string, number>>((acc, s) => {
                const g = s.ssl_info?.grade ?? "?";
                acc[g] = (acc[g] ?? 0) + 1;
                return acc;
              }, {});
              const order = ["A+", "A", "B", "C", "D", "F", "?"];
              const sorted = order.filter((g) => gradeCounts[g]);
              if (sorted.length === 0) return null;
              return (
                <div className="px-6 py-4 border-t border-shodh-border/40 flex items-center gap-3 flex-wrap">
                  <span className="text-[10px] text-shodh-muted font-mono uppercase tracking-wider">Grade breakdown</span>
                  {sorted.map((g) => (
                    <span key={g} className={`text-xs px-2 py-0.5 rounded border font-mono font-semibold ${gradeColor(g)} ${gradeBg(g)}`}>
                      {g} <span className="font-normal opacity-70">×{gradeCounts[g]}</span>
                    </span>
                  ))}
                </div>
              );
            })()}
            <Paginator page={sslPage} total={sslScanned.length} onChange={setSslPage} />
          </motion.div>
        )}

        {/* ── Feature 26: Subdomain Takeover Risk ──────────────────── */}
        {scan.takeovers && scan.takeovers.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.44 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-danger/40 rounded-xl overflow-hidden mb-6"
          >
            <div className="flex items-center gap-3 px-6 py-4 border-b border-shodh-danger/20 bg-shodh-danger/5">
              <Link2Off className="w-5 h-5 text-shodh-danger flex-shrink-0" />
              <div className="flex-1">
                <h2 className="font-mono font-semibold text-shodh-text">Subdomain Takeover Risk</h2>
                <p className="text-xs font-mono text-shodh-muted mt-0.5">
                  These subdomains have dangling CNAMEs pointing to unclaimed resources.
                  Requires <span className="text-shodh-warning">manual confirmation</span>.
                </p>
              </div>
              <span className="text-xs font-mono text-shodh-danger bg-shodh-danger/10 border border-shodh-danger/30 px-2 py-1 rounded">
                {scan.takeovers.length} at risk
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full min-w-[600px] text-sm font-mono">
                <thead>
                  <tr className="text-xs text-shodh-muted uppercase tracking-wider border-b border-shodh-border">
                    <th className="px-6 py-2 text-left font-normal">Subdomain</th>
                    <th className="px-4 py-2 text-left font-normal">Service</th>
                    <th className="px-4 py-2 text-left font-normal">CNAME Target</th>
                    <th className="px-4 py-2 text-center font-normal">Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {scan.takeovers.map((t, i) => (
                    <tr key={i} className="border-t border-shodh-border/40 hover:bg-shodh-border/20 transition-colors">
                      <td className="px-6 py-2.5 text-shodh-text font-mono">{t.hostname}</td>
                      <td className="px-4 py-2.5">
                        <span className="text-xs px-2 py-0.5 rounded border text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10">
                          {t.service ?? "Unknown"}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-shodh-muted text-xs truncate max-w-[240px]">
                        {t.cname_target ?? "—"}
                      </td>
                      <td className="px-4 py-2.5 text-center">
                        <span className={`text-xs font-mono font-semibold uppercase ${takeSevColor(t.severity)}`}>
                          {t.severity ?? "—"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <p className="px-6 py-3 text-xs font-mono text-shodh-muted/70 border-t border-shodh-border/40">
              To claim a takeover: register the missing resource (bucket, page, app) on the target service.
              Attackers could otherwise host malicious content on your subdomain.
            </p>
          </motion.div>
        )}

        {/* ── Features 24/25: CVE Vulnerabilities ──────────────────── */}
        {scan.status === "completed" && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.45 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden mb-6"
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
              <div className="flex items-center gap-3">
                <Bug className="w-5 h-5 text-shodh-danger" />
                <h2 className="font-mono font-semibold text-shodh-text">CVE Vulnerabilities</h2>
                <span className="text-xs font-mono text-shodh-muted">via NVD + OSV.dev</span>
              </div>
              <span className={`text-xs font-mono px-2 py-1 rounded border ${
                scan.cves.length === 0
                  ? "text-shodh-accent border-shodh-accent/40 bg-shodh-accent/10"
                  : scan.cves.some((c) => c.severity === "critical")
                  ? "text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10"
                  : scan.cves.some((c) => c.severity === "high")
                  ? "text-[#ff6644] border-[#ff6644]/40 bg-[#ff6644]/10"
                  : "text-shodh-muted bg-shodh-border"
              }`}>
                {scan.cves.length === 0 ? "No CVEs found" : `${scan.cves.length} CVE${scan.cves.length !== 1 ? "s" : ""} found`}
              </span>
            </div>

            {scan.cves.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-shodh-muted gap-3">
                <Bug className="w-10 h-10 opacity-20" />
                <p className="font-mono text-sm">No known vulnerabilities detected</p>
                <p className="font-mono text-xs opacity-60 text-center max-w-md">
                  Technologies were checked against NVD (NIST) and OSV.dev.
                  No CVEs were found for the detected stack.
                </p>
              </div>
            ) : (
              <>
                {/* Severity breakdown bar */}
                {(() => {
                  const counts: Record<string, number> = {};
                  for (const c of scan.cves) {
                    const s = c.severity ?? "unknown";
                    counts[s] = (counts[s] ?? 0) + 1;
                  }
                  const order = ["critical", "high", "medium", "low", "info"];
                  const present = order.filter((s) => counts[s]);
                  if (present.length === 0) return null;
                  return (
                    <div className="flex items-center gap-3 px-6 py-3 border-b border-shodh-border/40 flex-wrap">
                      <span className="text-[10px] text-shodh-muted font-mono uppercase tracking-wider">Severity breakdown</span>
                      {present.map((s) => (
                        <span
                          key={s}
                          className={`text-xs px-2 py-0.5 rounded border font-mono font-semibold ${cveSevColor(s)} ${cveSevBg(s)}`}
                        >
                          {cveSevLabel(s)} <span className="font-normal opacity-70">×{counts[s]}</span>
                        </span>
                      ))}
                    </div>
                  );
                })()}

                <div className="overflow-x-auto">
                  <table className="w-full min-w-[700px] text-sm font-mono">
                    <thead>
                      <tr className="text-xs text-shodh-muted uppercase tracking-wider border-b border-shodh-border">
                        <th className="px-6 py-2 text-left font-normal">CVE / ID</th>
                        <th className="px-4 py-2 text-center font-normal"><Tooltip text="CVSS" tip={TIPS.CVSS} /></th>
                        <th className="px-4 py-2 text-center font-normal">Severity</th>
                        <th className="px-4 py-2 text-left font-normal">Technology</th>
                        <th className="px-6 py-2 text-left font-normal">Description</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scan.cves.slice((cvePage-1)*PER_PAGE, cvePage*PER_PAGE).map((cve, i) => {
                        const isCVE = cve.cve_id.startsWith("CVE-");
                        const isGHSA = cve.cve_id.startsWith("GHSA-");
                        const href = isCVE
                          ? `https://nvd.nist.gov/vuln/detail/${cve.cve_id}`
                          : isGHSA
                          ? `https://github.com/advisories/${cve.cve_id}`
                          : `https://osv.dev/vulnerability/${cve.cve_id}`;
                        return (
                          <tr key={i} className="border-t border-shodh-border/40 hover:bg-shodh-border/20 transition-colors">
                            <td className="px-6 py-2.5">
                              <a
                                href={href}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-shodh-info hover:underline flex items-center gap-1"
                              >
                                {cve.cve_id}
                                <ExternalLink className="w-3 h-3 opacity-60" />
                              </a>
                            </td>
                            <td className="px-4 py-2.5 text-center">
                              {cve.cvss_score !== null ? (
                                <span className={`text-sm font-bold font-mono ${cveSevColor(cve.severity)}`}>
                                  {cve.cvss_score.toFixed(1)}
                                </span>
                              ) : (
                                <span className="text-shodh-muted/40">—</span>
                              )}
                            </td>
                            <td className="px-4 py-2.5 text-center">
                              <span className={`text-[10px] px-2 py-0.5 rounded border font-mono font-semibold ${cveSevColor(cve.severity)} ${cveSevBg(cve.severity)}`}>
                                {cveSevLabel(cve.severity)}
                              </span>
                            </td>
                            <td className="px-4 py-2.5">
                              <span className="text-shodh-text text-xs">
                                {cve.technology_name}
                                {cve.technology_version && (
                                  <span className="text-shodh-muted ml-1">{cve.technology_version}</span>
                                )}
                              </span>
                            </td>
                            <td className="px-6 py-2.5 text-shodh-muted text-xs max-w-[320px] truncate"
                                title={cve.description ?? undefined}>
                              {cve.description ?? <span className="text-shodh-muted/40">No description</span>}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <Paginator page={cvePage} total={scan.cves.length} onChange={setCvePage} />
              </>
            )}

            <p className="px-6 py-3 text-xs font-mono text-shodh-muted/60 border-t border-shodh-border/40">
              Vulnerability data from NVD (NIST) for versioned infrastructure + OSV.dev for open-source packages (npm, PyPI, Packagist, Go, RubyGems).
              Click any ID to view full details.
            </p>
          </motion.div>
        )}

        {/* ── ASN / IP Ranges section ─────────────────────────────── */}
        {scan.asn_info && scan.asn_info.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden mb-6"
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
              <div className="flex items-center gap-3">
                <Network className="w-5 h-5 text-shodh-accent" />
                <h2 className="font-mono font-semibold text-shodh-text">ASN & IP Ranges</h2>
              </div>
              <span className="text-xs font-mono text-shodh-muted bg-shodh-border px-2 py-1 rounded">
                {scan.asn_info.length} network{scan.asn_info.length !== 1 ? "s" : ""}
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full min-w-[500px] text-sm font-mono">
                <thead>
                  <tr className="text-xs text-shodh-muted uppercase tracking-wider border-b border-shodh-border">
                    <th className="px-6 py-2 text-left font-normal">ASN</th>
                    <th className="px-6 py-2 text-left font-normal">Organization</th>
                    <th className="px-6 py-2 text-left font-normal">IP Range</th>
                    <th className="px-6 py-2 text-left font-normal">Country</th>
                  </tr>
                </thead>
                <tbody>
                  {scan.asn_info.map((asn, i) => (
                    <tr
                      key={i}
                      className="border-t border-shodh-border/40 hover:bg-shodh-border/20 transition-colors"
                    >
                      <td className="px-6 py-2.5">
                        <span className="text-xs px-2 py-0.5 rounded border text-shodh-info border-shodh-info/40 bg-shodh-info/10">
                          AS{asn.asn}
                        </span>
                      </td>
                      <td className="px-6 py-2.5 text-shodh-text">{asn.org_name ?? "—"}</td>
                      <td className="px-6 py-2.5 text-shodh-muted">{asn.prefix ?? "—"}</td>
                      <td className="px-6 py-2.5 text-shodh-muted">{asn.country ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}

        {/* ── IP Reputation section (Feature 32) ──────────────────────── */}
        {scan.status === "completed" && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.45 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden mb-6"
          >
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
              <div className="flex items-center gap-3">
                <AlertOctagon className="w-5 h-5 text-shodh-warning" />
                <h2 className="font-mono font-semibold text-shodh-text">IP Reputation</h2>
                <span className="text-xs font-mono text-shodh-muted flex items-center gap-1">
                  via <Tooltip text="DNSBL" tip={TIPS.DNSBL} /> + <Tooltip text="URLhaus" tip={TIPS.URLhaus} />
                </span>
              </div>
              {(() => {
                const blacklistedCount = scan.ip_reputation.filter(r => r.is_blacklisted).length;
                const total = scan.ip_reputation.length;
                return (
                  <span className={`text-xs font-mono px-2 py-1 rounded border ${
                    blacklistedCount > 0
                      ? "text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10"
                      : "text-shodh-accent border-shodh-accent/40 bg-shodh-accent/10"
                  }`}>
                    {blacklistedCount > 0 ? `${blacklistedCount} blacklisted` : `${total} clean`}
                  </span>
                );
              })()}
            </div>

            {scan.ip_reputation.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-10 gap-3">
                <Shield className="w-10 h-10 text-shodh-muted opacity-20" />
                <p className="text-sm font-mono text-shodh-muted">No IP addresses checked</p>
                <p className="text-xs font-mono text-shodh-muted/60">Requires alive subdomains with resolved IPs</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] text-sm font-mono">
                  <thead>
                    <tr className="text-xs text-shodh-muted uppercase tracking-wider border-b border-shodh-border">
                      <th className="px-6 py-2 text-left font-normal">IP Address</th>
                      <th className="px-6 py-2 text-left font-normal">Hostname</th>
                      <th className="px-6 py-2 text-left font-normal">Status</th>
                      <th className="px-6 py-2 text-left font-normal">Blacklists</th>
                      <th className="px-6 py-2 text-left font-normal">Threat</th>
                      <th className="px-6 py-2 text-left font-normal">Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scan.ip_reputation.map((rep, i) => (
                      <tr
                        key={i}
                        className={`border-t border-shodh-border/40 transition-colors ${
                          rep.is_blacklisted
                            ? "bg-shodh-danger/5 hover:bg-shodh-danger/10"
                            : "hover:bg-shodh-border/20"
                        }`}
                      >
                        <td className="px-6 py-2.5">
                          <span className={`font-mono text-sm ${rep.is_blacklisted ? "text-shodh-danger" : "text-shodh-text"}`}>
                            {rep.ip_address}
                          </span>
                        </td>
                        <td className="px-6 py-2.5 text-shodh-muted text-xs">
                          {rep.hostname ?? "—"}
                        </td>
                        <td className="px-6 py-2.5">
                          {rep.is_blacklisted ? (
                            <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10">
                              <XCircle className="w-3 h-3" />
                              Blacklisted
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border text-shodh-accent border-shodh-accent/40 bg-shodh-accent/10">
                              <CheckCircle2 className="w-3 h-3" />
                              Clean
                            </span>
                          )}
                        </td>
                        <td className="px-6 py-2.5">
                          {rep.blacklists && rep.blacklists.length > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {rep.blacklists.map((bl, j) => (
                                <span key={j} className="text-xs px-1.5 py-0.5 rounded border text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10">
                                  {bl}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-shodh-muted text-xs">—</span>
                          )}
                        </td>
                        <td className="px-6 py-2.5">
                          {rep.threat_type ? (
                            <span className="text-xs text-shodh-danger font-mono capitalize">
                              {rep.threat_type}
                            </span>
                          ) : rep.urlhaus_tags && rep.urlhaus_tags.length > 0 ? (
                            <span className="text-xs text-shodh-warning font-mono">
                              {rep.urlhaus_tags[0]}
                            </span>
                          ) : (
                            <span className="text-shodh-muted text-xs">—</span>
                          )}
                        </td>
                        <td className="px-6 py-2.5">
                          {rep.abuse_score !== null ? (
                            <span className={`text-sm font-bold font-mono ${
                              rep.abuse_score >= 70 ? "text-shodh-danger"
                              : rep.abuse_score >= 40 ? "text-shodh-warning"
                              : "text-shodh-muted"
                            }`}>
                              {rep.abuse_score}
                              <span className="text-xs font-normal text-shodh-muted">/100</span>
                            </span>
                          ) : (
                            <span className="text-shodh-muted text-xs">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <p className="px-6 py-3 text-xs font-mono text-shodh-muted/60 border-t border-shodh-border/40">
              Checked against Spamhaus ZEN, SpamCop, SORBS (DNS blacklists) and URLhaus malware database. All free, no API key.
            </p>
          </motion.div>
        )}

        {/* ── CORS Misconfiguration ── */}
        {scan.status === "completed" && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden"
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
              <div className="flex items-center gap-3">
                <Globe2 className="w-5 h-5 text-shodh-warning" />
                <h2 className="text-sm font-semibold text-shodh-text font-mono uppercase tracking-wider">
                  CORS Misconfiguration
                </h2>
                <span className="text-xs font-mono text-shodh-muted/60">Cross-Origin Resource Sharing</span>
              </div>
              <span className={`text-xs font-mono px-2 py-0.5 rounded border ${
                scan.cors_results.length > 0
                  ? "text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10"
                  : "text-shodh-accent border-shodh-accent/40 bg-shodh-accent/10"
              }`}>
                {scan.cors_results.length > 0
                  ? `${scan.cors_results.length} vulnerable`
                  : "all clean"}
              </span>
            </div>

            {scan.cors_results.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-10 gap-3">
                <Shield className="w-10 h-10 text-shodh-muted opacity-20" />
                <p className="text-sm font-mono text-shodh-muted">No CORS misconfigurations found</p>
                <p className="text-xs font-mono text-shodh-muted/60">Arbitrary origin reflection and null origin tested on all alive subdomains</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] text-sm font-mono">
                  <thead>
                    <tr className="text-xs text-shodh-muted uppercase tracking-wider border-b border-shodh-border">
                      <th className="px-6 py-2 text-left font-normal">Hostname</th>
                      <th className="px-6 py-2 text-left font-normal">Type</th>
                      <th className="px-6 py-2 text-left font-normal">Allowed Origin</th>
                      <th className="px-6 py-2 text-left font-normal">Credentials</th>
                      <th className="px-6 py-2 text-left font-normal">Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scan.cors_results.map((c, i) => (
                      <tr
                        key={i}
                        className={`border-t border-shodh-border/40 transition-colors ${
                          c.severity === "critical"
                            ? "bg-shodh-danger/5 hover:bg-shodh-danger/10"
                            : "hover:bg-shodh-border/20"
                        }`}
                      >
                        <td className="px-6 py-2.5 text-shodh-text">{c.hostname}</td>
                        <td className="px-6 py-2.5">
                          <span className="text-xs px-2 py-0.5 rounded border text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10">
                            {c.misconfig_type && TIPS[c.misconfig_type] ? (
                              <Tooltip
                                text={c.misconfig_type === "arbitrary_origin_reflected" ? "Origin Reflected" : "Null Origin"}
                                tip={TIPS[c.misconfig_type]}
                              />
                            ) : (
                              c.misconfig_type === "arbitrary_origin_reflected"
                                ? "Origin Reflected"
                                : c.misconfig_type === "null_origin"
                                ? "Null Origin"
                                : c.misconfig_type ?? "—"
                            )}
                          </span>
                        </td>
                        <td className="px-6 py-2.5 text-shodh-muted text-xs">
                          <code className="text-shodh-danger">{c.allowed_origin ?? "—"}</code>
                        </td>
                        <td className="px-6 py-2.5">
                          {c.allow_credentials ? (
                            <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10">
                              <XCircle className="w-3 h-3" /> Yes
                            </span>
                          ) : (
                            <span className="text-shodh-muted text-xs">No</span>
                          )}
                        </td>
                        <td className="px-6 py-2.5">
                          <span className={`text-xs font-mono uppercase px-2 py-0.5 rounded border ${
                            c.severity === "critical"
                              ? "text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10"
                              : c.severity === "high"
                              ? "text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10"
                              : "text-shodh-info border-shodh-info/40 bg-shodh-info/10"
                          }`}>
                            {c.severity ?? "—"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="px-6 py-3 text-xs font-mono text-shodh-muted/60 border-t border-shodh-border/40">
              Tests arbitrary origin reflection and null origin acceptance. CRITICAL = credentials exposed to attacker-controlled domain.
            </p>
          </motion.div>
        )}

        {/* ── JavaScript Analysis ── */}
        {scan.status === "completed" && scan.js_findings.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden"
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
              <div className="flex items-center gap-3">
                <Code2 className="w-5 h-5 text-shodh-purple" />
                <h2 className="text-sm font-semibold text-shodh-text font-mono uppercase tracking-wider">
                  JavaScript Analysis
                </h2>
                <span className="text-xs font-mono text-shodh-muted/60">Endpoints &amp; Secrets</span>
              </div>
              <div className="flex items-center gap-2">
                {(() => {
                  const totalSecrets = scan.js_findings.reduce((a, f) => a + f.secret_count, 0);
                  const totalEndpoints = scan.js_findings.reduce((a, f) => a + f.endpoint_count, 0);
                  return (
                    <>
                      {totalSecrets > 0 && (
                        <span className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10">
                          {totalSecrets} secret{totalSecrets !== 1 ? "s" : ""}
                        </span>
                      )}
                      <span className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-purple border-shodh-purple/40 bg-shodh-purple/10">
                        {totalEndpoints} endpoints
                      </span>
                    </>
                  );
                })()}
              </div>
            </div>

            <div className="divide-y divide-shodh-border/40">
              {scan.js_findings.slice((jsPage - 1) * PER_PAGE, jsPage * PER_PAGE).map((f, i) => (
                <div key={i} className="px-6 py-4 hover:bg-shodh-border/10 transition-colors">
                  <div className="flex items-start justify-between gap-4 mb-3">
                    <div className="min-w-0">
                      <p className="text-xs text-shodh-muted mb-0.5">{f.subdomain_hostname}</p>
                      <a
                        href={f.js_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm font-mono text-shodh-purple hover:text-shodh-accent truncate block max-w-xl"
                      >
                        {f.js_url}
                      </a>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {f.secret_count > 0 && (
                        <span className="flex items-center gap-1 text-xs font-mono px-2 py-0.5 rounded border text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10">
                          <Key className="w-3 h-3" /> {f.secret_count} secret{f.secret_count !== 1 ? "s" : ""}
                        </span>
                      )}
                      {f.endpoint_count > 0 && (
                        <span className="flex items-center gap-1 text-xs font-mono px-2 py-0.5 rounded border text-shodh-purple border-shodh-purple/40 bg-shodh-purple/10">
                          {f.endpoint_count} endpoint{f.endpoint_count !== 1 ? "s" : ""}
                        </span>
                      )}
                    </div>
                  </div>

                  {f.secrets && f.secrets.length > 0 && (
                    <div className="mb-2">
                      <p className="text-xs text-shodh-danger font-mono uppercase mb-1.5 tracking-wider">Potential Secrets</p>
                      <div className="flex flex-wrap gap-1.5">
                        {f.secrets.map((s, j) => (
                          <span key={j} className="flex items-center gap-1 text-xs font-mono px-2 py-0.5 rounded border text-shodh-danger border-shodh-danger/30 bg-shodh-danger/5">
                            <Key className="w-2.5 h-2.5" />
                            <span className="text-shodh-muted">{s.type}:</span> {s.value}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {f.endpoints && f.endpoints.length > 0 && (
                    <div>
                      <p className="text-xs text-shodh-purple font-mono uppercase mb-1.5 tracking-wider">API Endpoints</p>
                      <div className="flex flex-wrap gap-1.5">
                        {f.endpoints.slice(0, 20).map((ep, j) => (
                          <code key={j} className="text-xs px-1.5 py-0.5 rounded bg-shodh-border/40 text-shodh-muted border border-shodh-border/60">
                            {ep}
                          </code>
                        ))}
                        {f.endpoints.length > 20 && (
                          <span className="text-xs text-shodh-muted/60 font-mono self-center">
                            +{f.endpoints.length - 20} more
                          </span>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
            <Paginator page={jsPage} total={scan.js_findings.length} onChange={setJsPage} />
            <p className="px-6 py-3 text-xs font-mono text-shodh-muted/60 border-t border-shodh-border/40">
              Secret values are masked (first 6 chars shown). Crawls same-origin JS files only.
            </p>
          </motion.div>
        )}

        {/* ── Directory Discovery ── */}
        {scan.status === "completed" && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden"
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
              <div className="flex items-center gap-3">
                <FolderOpen className="w-5 h-5 text-shodh-warning" />
                <h2 className="text-sm font-semibold text-shodh-text font-mono uppercase tracking-wider">
                  Directory Discovery
                </h2>
                <span className="text-xs font-mono text-shodh-muted/60">Path brute-force</span>
              </div>
              {(() => {
                const critical = scan.dir_findings.filter(f => f.severity === "critical").length;
                const high = scan.dir_findings.filter(f => f.severity === "high").length;
                return (
                  <div className="flex items-center gap-2">
                    {critical > 0 && (
                      <span className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10">
                        {critical} critical
                      </span>
                    )}
                    {high > 0 && (
                      <span className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10">
                        {high} high
                      </span>
                    )}
                    <span className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-muted border-shodh-border bg-shodh-border/40">
                      {scan.dir_findings.length} total
                    </span>
                  </div>
                );
              })()}
            </div>

            {scan.dir_findings.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-10 gap-3">
                <FolderOpen className="w-10 h-10 text-shodh-muted opacity-20" />
                <p className="text-sm font-mono text-shodh-muted">No interesting paths found</p>
                <p className="text-xs font-mono text-shodh-muted/60">
                  {scan.subdomains.filter(s => s.is_alive).length} alive subdomains probed
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] text-sm font-mono">
                  <thead>
                    <tr className="text-xs text-shodh-muted uppercase tracking-wider border-b border-shodh-border">
                      <th className="px-6 py-2 text-left font-normal">Hostname</th>
                      <th className="px-6 py-2 text-left font-normal">Path</th>
                      <th className="px-6 py-2 text-left font-normal">Status</th>
                      <th className="px-6 py-2 text-left font-normal">Type</th>
                      <th className="px-6 py-2 text-left font-normal">Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scan.dir_findings.slice((dirPage-1)*PER_PAGE, dirPage*PER_PAGE).map((f, i) => (
                      <tr
                        key={i}
                        className={`border-t border-shodh-border/40 transition-colors ${
                          f.severity === "critical"
                            ? "bg-shodh-danger/5 hover:bg-shodh-danger/10"
                            : f.severity === "high"
                            ? "bg-shodh-warning/5 hover:bg-shodh-warning/10"
                            : "hover:bg-shodh-border/20"
                        }`}
                      >
                        <td className="px-6 py-2.5 text-shodh-muted text-xs">{f.subdomain_hostname}</td>
                        <td className="px-6 py-2.5">
                          <code className={`text-sm ${
                            f.severity === "critical" ? "text-shodh-danger"
                            : f.severity === "high" ? "text-shodh-warning"
                            : "text-shodh-text"
                          }`}>
                            {f.path}
                          </code>
                        </td>
                        <td className="px-6 py-2.5">
                          <span className={`text-xs font-mono px-1.5 py-0.5 rounded ${
                            f.status_code < 300
                              ? "text-shodh-accent bg-shodh-accent/10"
                              : f.status_code < 400
                              ? "text-shodh-warning bg-shodh-warning/10"
                              : "text-shodh-muted bg-shodh-border/40"
                          }`}>
                            {f.status_code}
                          </span>
                        </td>
                        <td className="px-6 py-2.5">
                          <span className="text-xs text-shodh-muted capitalize">
                            {f.finding_type && TIPS[f.finding_type] ? (
                              <Tooltip text={f.finding_type.replace(/_/g, " ")} tip={TIPS[f.finding_type]} />
                            ) : (
                              f.finding_type?.replace(/_/g, " ") ?? "—"
                            )}
                          </span>
                        </td>
                        <td className="px-6 py-2.5">
                          <span className={`text-xs font-mono uppercase px-2 py-0.5 rounded border ${
                            f.severity === "critical"
                              ? "text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10"
                              : f.severity === "high"
                              ? "text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10"
                              : f.severity === "medium"
                              ? "text-shodh-info border-shodh-info/40 bg-shodh-info/10"
                              : "text-shodh-muted border-shodh-border bg-shodh-border/40"
                          }`}>
                            {f.severity ?? "—"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <Paginator page={dirPage} total={scan.dir_findings.length} onChange={setDirPage} />
            <p className="px-6 py-3 text-xs font-mono text-shodh-muted/60 border-t border-shodh-border/40">
              Probed {scan.dir_findings.length > 0 ? scan.dir_findings.length : "0"} interesting paths across {scan.subdomains.filter(s => s.is_alive).length} alive subdomains. 404s excluded.
            </p>
          </motion.div>
        )}

        {/* ── Historical Endpoints (Wayback Machine) ───────────────── */}
        {scan.status === "completed" && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="bg-shodh-surface/55 backdrop-blur-md border border-shodh-border/70 rounded-xl overflow-hidden"
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-shodh-border">
              <div>
                <h2 className="text-sm font-semibold text-shodh-text font-sans uppercase tracking-wider">
                  Historical Endpoints
                </h2>
                <span className="text-xs font-mono text-shodh-muted/60">Wayback Machine CDX API</span>
              </div>
              <span className="text-xs font-mono px-2 py-0.5 rounded border text-shodh-purple border-shodh-purple/40 bg-shodh-purple/10">
                {scan.wayback_findings.length} found
              </span>
            </div>

            {scan.wayback_findings.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-10 gap-3">
                <Clock className="w-10 h-10 text-shodh-muted opacity-20" />
                <p className="text-sm font-mono text-shodh-muted">No archived security-relevant endpoints found</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm font-mono">
                  <thead>
                    <tr className="text-xs text-shodh-muted uppercase tracking-wider border-b border-shodh-border">
                      <th className="px-6 py-2 text-left font-normal">Category</th>
                      <th className="px-6 py-2 text-left font-normal">URL</th>
                      <th className="px-6 py-2 text-left font-normal">Type</th>
                      <th className="px-6 py-2 text-left font-normal">Last Seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scan.wayback_findings.slice((waybackPage-1)*PER_PAGE, waybackPage*PER_PAGE).map((f, i) => {
                      const catColors: Record<string, string> = {
                        debug: "text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10",
                        admin: "text-shodh-danger border-shodh-danger/40 bg-shodh-danger/10",
                        config: "text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10",
                        backup: "text-shodh-warning border-shodh-warning/40 bg-shodh-warning/10",
                        api: "text-shodh-accent border-shodh-accent/40 bg-shodh-accent/10",
                        auth: "text-shodh-info border-shodh-info/40 bg-shodh-info/10",
                        upload: "text-shodh-purple border-shodh-purple/40 bg-shodh-purple/10",
                        other: "text-shodh-muted border-shodh-border bg-shodh-border/40",
                      };
                      const ts = f.last_seen;
                      const dateStr = ts && ts.length >= 8
                        ? `${ts.slice(0,4)}-${ts.slice(4,6)}-${ts.slice(6,8)}`
                        : (ts ?? "—");
                      return (
                        <tr key={i} className="border-t border-shodh-border/40 hover:bg-shodh-border/20 transition-colors">
                          <td className="px-6 py-2.5">
                            <span className={`text-xs px-2 py-0.5 rounded border ${catColors[f.category ?? "other"] ?? catColors.other}`}>
                              {f.category ?? "other"}
                            </span>
                          </td>
                          <td className="px-6 py-2.5 max-w-md">
                            <a
                              href={f.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-shodh-info hover:underline truncate block max-w-[380px]"
                              title={f.url}
                            >
                              {f.url.length > 80 ? f.url.slice(0, 80) + "…" : f.url}
                            </a>
                          </td>
                          <td className="px-6 py-2.5 text-shodh-muted text-xs">{f.mime_type ?? "—"}</td>
                          <td className="px-6 py-2.5 text-shodh-muted">{dateStr}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
            <Paginator page={waybackPage} total={scan.wayback_findings.length} onChange={setWaybackPage} />
            <p className="px-6 py-3 text-xs font-mono text-shodh-muted/60 border-t border-shodh-border/40">
              Security-relevant paths from {scan.wayback_findings.length} archived snapshots. Historical data may expose forgotten attack surfaces.
            </p>
          </motion.div>
        )}


      </motion.div>
    </div>
  );
}