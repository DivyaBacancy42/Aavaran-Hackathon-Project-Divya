import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Search, Shield, Activity, Globe, Zap,
  ChevronDown, Lock, Server, Eye, AlertTriangle,
  Network, FileSearch, ShieldCheck, BookOpen,
} from "lucide-react";
import axios from "axios";

export default function Dashboard() {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const handleScan = async () => {
    if (!domain.trim()) return;
    setLoading(true);
    setError("");
    try {
      const res = await axios.post("/api/scans/", { domain: domain.trim() });
      navigate(`/scan/${res.data.id}`);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Failed to start scan");
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") handleScan();
  };

  const scrollToExplore = () => {
    window.scrollTo({ top: window.innerHeight, behavior: "smooth" });
  };

  return (
    <div className="relative">

      {/* ── SECTION 1: Hero / Input (full viewport) ────────────────────── */}
      <section className="min-h-screen flex flex-col items-center justify-center px-6 relative">

        {/* Logo & Title */}
        <motion.div
          initial={{ opacity: 0, y: -30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.9 }}
          className="text-center mb-10"
        >
          <div className="flex items-center justify-center gap-3 mb-3">
            <Shield className="w-10 h-10 text-shodh-accent" />
            <h1 className="text-6xl font-bold tracking-tight font-display">
              <span className="text-shodh-accent glow-text-green">Aavaran</span>
            </h1>
          </div>
          <p className="text-shodh-muted text-lg max-w-md font-sans">
            Attack Surface Intelligence Platform
          </p>
          <p className="text-shodh-muted/50 text-sm mt-1.5 font-mono">
            आवरण — One domain in. Full exposure out.
          </p>
          <Link
            to="/understanding"
            className="inline-flex items-center gap-1.5 mt-3 text-xs font-mono text-shodh-muted/50 hover:text-shodh-accent/80 transition-colors group"
          >
            <BookOpen className="w-3 h-3 group-hover:text-shodh-accent/80" />
            How it works — all scan modules explained
          </Link>
        </motion.div>

        {/* Domain Input */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.2 }}
          className="w-full max-w-xl"
        >
          <div className="relative group">
            <div className="absolute -inset-0.5 bg-gradient-to-r from-shodh-accent/20 via-shodh-purple/20 to-shodh-accent/20 rounded-xl blur opacity-0 group-hover:opacity-100 transition duration-500" />
            <div className="relative flex items-center bg-shodh-surface/80 backdrop-blur-sm border border-shodh-border rounded-xl overflow-hidden">
              <Globe className="w-5 h-5 text-shodh-muted ml-4 shrink-0" />
              <input
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Enter target domain... (e.g. example.com)"
                className="flex-1 bg-transparent px-4 py-4 text-lg font-mono text-shodh-text placeholder-shodh-muted/40 input-glow border-none outline-none"
                autoFocus
              />
              <button
                onClick={handleScan}
                disabled={loading || !domain.trim()}
                className="m-2 px-6 py-2.5 bg-shodh-accent text-shodh-bg font-semibold rounded-lg hover:bg-shodh-accent/90 transition-all duration-200 disabled:opacity-30 disabled:cursor-not-allowed flex items-center gap-2"
              >
                {loading ? (
                  <div className="w-5 h-5 border-2 border-shodh-bg/30 border-t-shodh-bg rounded-full animate-spin" />
                ) : (
                  <>
                    <Search className="w-4 h-4" />
                    <span>Scan</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {error && (
            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="text-shodh-danger text-sm mt-3 font-mono text-center"
            >
              {error}
            </motion.p>
          )}
        </motion.div>

        {/* Feature pills */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.8, delay: 0.5 }}
          className="flex flex-wrap justify-center gap-2.5 mt-8 max-w-2xl"
        >
          {[
            { icon: Globe,    label: "Subdomain Discovery" },
            { icon: Activity, label: "Port Scanning" },
            { icon: Shield,   label: "WAF Detection" },
            { icon: Zap,      label: "CVE Lookup" },
            { icon: Search,   label: "Tech Fingerprint" },
          ].map(({ icon: Icon, label }) => (
            <div
              key={label}
              className="flex items-center gap-2 px-3 py-1.5 bg-shodh-surface/40 backdrop-blur-sm border border-shodh-border/50 rounded-full text-xs text-shodh-muted font-mono"
            >
              <Icon className="w-3 h-3 text-shodh-accent/60" />
              {label}
            </div>
          ))}
        </motion.div>

        {/* Scroll indicator */}
        <motion.button
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.2 }}
          onClick={scrollToExplore}
          className="absolute bottom-8 flex flex-col items-center gap-1 text-shodh-muted/40 hover:text-shodh-accent/60 transition-colors cursor-pointer group"
        >
          <span className="text-[10px] font-mono uppercase tracking-widest">Scroll to explore</span>
          <motion.div
            animate={{ y: [0, 6, 0] }}
            transition={{ repeat: Infinity, duration: 2, ease: "easeInOut" }}
          >
            <ChevronDown className="w-5 h-5" />
          </motion.div>
        </motion.button>
      </section>

      {/* ── SECTION 2: Feature showcase (full viewport) ─────────────────── */}
      <section className="min-h-screen flex flex-col justify-center px-6 py-20 relative">

        {/* Subtle divider */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-px h-20 bg-gradient-to-b from-transparent to-shodh-accent/20" />

        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          viewport={{ once: true, margin: "-100px" }}
          className="max-w-5xl mx-auto w-full"
        >
          {/* Section heading */}
          <div className="text-center mb-14">
            <p className="text-xs font-mono text-shodh-accent/70 uppercase tracking-[0.3em] mb-3">
              What Aavaran maps
            </p>
            <h2 className="text-3xl font-bold text-shodh-text font-display">
              Your entire attack surface, in one scan
            </h2>
            <p className="text-shodh-muted text-sm mt-3 max-w-lg mx-auto font-mono">
              Enterprise-grade intelligence without the enterprise price.
              Self-hosted, open-source, zero API keys.
            </p>
          </div>

          {/* Stats row */}
          <div className="grid grid-cols-3 gap-4 mb-12">
            {[
              { value: "45+",   label: "Scan Modules",    color: "text-shodh-accent" },
              { value: "0",     label: "API Keys Needed", color: "text-shodh-info" },
              { value: "100%",  label: "Self-Hosted",     color: "text-shodh-purple" },
            ].map((s) => (
              <div
                key={s.label}
                className="text-center p-5 rounded-xl bg-shodh-surface/30 backdrop-blur-sm border border-shodh-border/40"
              >
                <p className={`text-4xl font-bold font-mono ${s.color} glow-text-green`}>{s.value}</p>
                <p className="text-xs text-shodh-muted font-mono mt-1.5 uppercase tracking-wider">{s.label}</p>
              </div>
            ))}
          </div>

          {/* Feature grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[
              { icon: Globe,       title: "Subdomain Discovery",      desc: "crt.sh + DNS brute-force. Finds every public subdomain." },
              { icon: Activity,    title: "Port & Service Scanning",  desc: "70+ ports, banner grabbing, version detection." },
              { icon: Lock,        title: "SSL / TLS Grading",        desc: "Certificate analysis, protocol support, A+ to F grading." },
              { icon: AlertTriangle, title: "CVE Lookup",             desc: "NVD + OSV.dev — matches detected stack against known CVEs." },
              { icon: Server,      title: "DNS Security",             desc: "DNSSEC validation, CAA records, nameserver resilience." },
              { icon: Eye,         title: "Historical Endpoints",     desc: "Wayback Machine CDX — surfaces forgotten attack paths." },
              { icon: ShieldCheck, title: "Email Security",           desc: "SPF · DKIM · DMARC · MTA-STS enforcement analysis." },
              { icon: Network,     title: "IP Geolocation",           desc: "Country, ISP, ASN, datacenter vs residential detection." },
              { icon: FileSearch,  title: "Directory Discovery",      desc: "120-path wordlist finds exposed .env, admin, git files." },
            ].map((f, i) => (
              <motion.div
                key={f.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: i * 0.05 }}
                viewport={{ once: true }}
                className="p-4 rounded-xl bg-shodh-surface/25 backdrop-blur-sm border border-shodh-border/30 hover:border-shodh-accent/30 hover:bg-shodh-surface/40 transition-all duration-300 group"
              >
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-8 h-8 rounded-lg bg-shodh-accent/10 flex items-center justify-center group-hover:bg-shodh-accent/20 transition-colors">
                    <f.icon className="w-4 h-4 text-shodh-accent" />
                  </div>
                  <h3 className="text-sm font-semibold text-shodh-text font-sans">{f.title}</h3>
                </div>
                <p className="text-xs text-shodh-muted/70 font-mono leading-relaxed">{f.desc}</p>
              </motion.div>
            ))}
          </div>

          {/* Bottom CTA */}
          <motion.div
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.3 }}
            viewport={{ once: true }}
            className="text-center mt-14"
          >
            <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
              <button
                onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
                className="inline-flex items-center gap-2 px-6 py-3 bg-shodh-accent text-shodh-bg font-semibold rounded-xl hover:bg-shodh-accent/90 transition-all duration-200 font-sans"
              >
                <Search className="w-4 h-4" />
                Start scanning
              </button>
              <Link
                to="/understanding"
                className="inline-flex items-center gap-2 px-6 py-3 border border-shodh-border/60 text-shodh-muted rounded-xl hover:border-shodh-accent/40 hover:text-shodh-accent transition-all duration-200 font-sans text-sm"
              >
                <BookOpen className="w-4 h-4" />
                How it works
              </Link>
            </div>
            <p className="text-shodh-muted/30 text-xs font-mono mt-4">
              v0.1.0 — self-hosted — your data stays local
            </p>
          </motion.div>
        </motion.div>
      </section>

    </div>
  );
}
