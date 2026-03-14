# CLAUDE.md — Project Context for Claude Code

## Product: SHODH (शोध) — Attack Surface Intelligence Platform

### What is this?
SHODH is a self-hosted, open-source attack surface mapping tool. User enters a single domain name → it automatically discovers the entire public infrastructure (subdomains, ports, WAF, tech stack, SSL, CVEs, leaked credentials, open cloud buckets) → presents everything as an interactive 3D constellation map with AI-generated risk scoring. One input, full output, zero API keys required.

### Product Definition (2-3 sentences)
SHODH is a self-hosted, open-source attack surface mapping tool — enter any domain name and it automatically discovers the entire public infrastructure (subdomains, ports, WAF, tech stack, CVEs, leaked credentials, open buckets) and presents it as an interactive 3D visual map with AI-generated risk scoring. One input, full output, zero API keys required, runs locally with `docker-compose up`.

### Competitors
- **Shodan** (shodan.io) — IP search engine, NOT an attack surface mapper. No subdomain discovery, no visualization.
- **SpiderFoot** (github.com/smicallef/spiderfoot) — 200+ OSINT modules but dated 2015-era UI, raw data dump with no risk prioritization.
- **Maltego** (maltego.com) — Visual link analysis, but free version capped at 12 objects, paid starts $999/year.

### What makes SHODH unique?
Today a security professional must manually chain 10-15 CLI tools and make sense of raw text. Enterprise platforms that automate this cost $50k-$500k/year. SHODH fills the gap: enterprise-grade intelligence, free, self-hosted, one command deploy.

---

## Tech Stack

| Layer | Technology | Why |
|---|---|---|
| Backend API | Python 3.12 + FastAPI | Security tool ecosystem, async orchestration |
| Database | PostgreSQL 16 | Relational scan data, complex queries, JSONB |
| Frontend | React 18 + TypeScript + Tailwind CSS | Component-based, strong ecosystem |
| 3D Visualization | Three.js + React Three Fiber | WebGL constellation map (must be eye-catching) |
| Animations | Framer Motion | Smooth page transitions and micro-interactions |
| DNS | dnspython | All DNS queries, zone transfer attempts |
| HTTP | httpx (Python lib) | Alive checks, header analysis |
| Icons | lucide-react | Consistent icon set |

### NOT needed yet (add later):
- Redis/Celery — not until multiple concurrent users
- Docker/Nginx — not until production deployment
- AI/Ollama — not until all scan modules produce data
- Playwright — not until screenshot feature

---

## Project Structure

```
shodh/
├── CLAUDE.md                          ← THIS FILE (Claude Code reads this)
├── README.md
├── backend/
│   ├── app/
│   │   ├── main.py                    ← FastAPI entry point
│   │   ├── api/
│   │   │   └── scans.py               ← API route handlers
│   │   ├── core/
│   │   │   ├── config.py              ← Settings from .env
│   │   │   └── database.py            ← PostgreSQL async connection
│   │   ├── models/
│   │   │   └── models.py              ← SQLAlchemy database models (11 tables)
│   │   ├── scanners/                  ← One file per scan module (ISOLATED)
│   │   │   └── dns_scanner.py         ← Feature #2/#4: DNS + Zone Transfer
│   │   ├── schemas/
│   │   │   └── schemas.py             ← Pydantic request/response validation
│   │   └── services/
│   │       └── scan_pipeline.py       ← Orchestrator that runs all scanners
│   ├── alembic/                       ← Database migrations
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── main.tsx                   ← React entry point
│   │   ├── App.tsx                    ← Router
│   │   ├── index.css                  ← Dark theme + glow effects
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx          ← Home page with domain input
│   │   │   └── ScanView.tsx           ← Scan results page
│   │   ├── components/                ← Reusable UI components
│   │   ├── hooks/                     ← Custom React hooks
│   │   └── utils/
│   │       └── api.ts                 ← Axios client
│   ├── package.json
│   ├── tailwind.config.js             ← Custom dark color palette
│   ├── vite.config.ts
│   └── tsconfig.json
└── docs/
    ├── FEATURES.md                    ← Complete 45-feature list with status
    └── ARCHITECTURE.md                ← Technical architecture details
```

---

## How to Run

```bash
# Terminal 1: Backend
cd backend
source venv/bin/activate
uvicorn app.main:app --reload --port 8000

# Terminal 2: Frontend
cd frontend
npm run dev
# Opens at http://localhost:5173
```

Database: PostgreSQL running on localhost:5432, database name: `shodh`

---

## Architecture Pattern — How Features Are Built

Every feature follows this EXACT pattern. Never deviate.

### 1. Scanner Module (backend/app/scanners/)
Each scanner is an INDEPENDENT file. It knows nothing about other scanners.

```python
# backend/app/scanners/example_scanner.py
class ExampleScanner:
    def __init__(self, domain: str):
        self.domain = domain

    async def run(self) -> ExampleResult:
        # Do the scanning work
        # Return a dataclass with results
        pass
```

### 2. Pipeline Integration (backend/app/services/scan_pipeline.py)
Add ONE line to call your scanner:

```python
async def run_pipeline(scan_id: UUID):
    # ... existing code ...
    await _run_dns_scanner(db, scan)
    await _run_example_scanner(db, scan)  # ← add one line
    # ...
```

### 3. API Response (backend/app/schemas/schemas.py)
Add response fields if needed. The ScanDetailResponse returns all data.

### 4. Frontend Display (frontend/src/pages/ScanView.tsx)
Add a new section to display the scanner's results. Each section is a self-contained block.

### CRITICAL RULES:
- Each scanner is ISOLATED — if one fails, others still run
- Never modify existing scanner files when adding new features
- Always handle exceptions — a scanner failure must NOT crash the pipeline
- New database models go in models/models.py (they already exist for all 45 features)
- Frontend polls every 2 seconds for live updates during scan

---

## Design Guidelines — Frontend

### Theme: Dark Hacker Aesthetic with Neon Accents
- Background: `#0a0a0f` (near-black)
- Surface: `#12121a` (dark panels)
- Borders: `#1e1e2e` (subtle)
- Accent: `#00ff88` (neon green — primary)
- Danger: `#ff3355` (red — critical findings)
- Warning: `#ffaa00` (orange)
- Info: `#00aaff` (blue)
- Purple: `#8855ff` (secondary accent)
- Text: `#e2e2e8` (light gray)
- Muted: `#6b6b80` (dim gray)

### Fonts:
- Mono: JetBrains Mono (all data, code, labels)
- Sans: Space Grotesk (headings, UI text)

### Effects:
- `.glow-green` — green box shadow glow
- `.glow-text-green` — green text shadow
- `.grid-bg` — subtle grid background pattern
- Framer Motion for all page transitions and element animations
- Must look EYE-CATCHING — people should screenshot and share it

### UI Components Pattern:
- All cards: `bg-shodh-surface border border-shodh-border rounded-xl`
- All tables: dark rows with hover highlight, mono font
- Record type badges: color-coded by type
- Stats cards: icon + label + large number
- Critical findings: red border, red background tint

---

## Database Models (Already Created)

All 11 tables exist in `backend/app/models/models.py`:

| Model | Purpose |
|---|---|
| Scan | Top-level scan job (one per domain) |
| Subdomain | Discovered subdomains |
| Port | Open ports on subdomains |
| Technology | Detected tech stack |
| WAFResult | WAF/CDN detection |
| SSLInfo | SSL certificate + TLS analysis |
| DNSRecord | DNS records (A, MX, NS, TXT, etc.) |
| CVE | Known vulnerabilities |
| EmailSecurity | SPF/DKIM/DMARC analysis |
| CloudBucket | Discovered S3/Azure/GCS buckets |

---

## Current Feature Status

| # | Feature | Status | Files |
|---|---|---|---|
| 1 | Domain Input | ✅ DONE | Dashboard.tsx, scans.py |
| 2 | DNS Zone Transfer Check | 🔨 NEEDS APPLYING | dns_scanner.py, scan_pipeline.py |
| 4 | DNS Record Extraction | 🔨 NEEDS APPLYING | dns_scanner.py (same module) |
| 3 | Subdomain Discovery | ⏳ NEXT | — |
| 5-45 | Everything else | ⏳ PENDING | — |

### What "NEEDS APPLYING" means for Feature #2:
These files need to be CREATED or UPDATED:

1. **CREATE** `backend/app/scanners/dns_scanner.py` — DNS scanner module
2. **CREATE** `backend/app/services/scan_pipeline.py` — Scan orchestrator
3. **REPLACE** `backend/app/api/scans.py` — Updated to trigger pipeline via BackgroundTasks
4. **REPLACE** `frontend/src/pages/ScanView.tsx` — Fixed missing Activity import + DNS results display

The content for all 4 files is ready in the codebase. Apply them in order.

---

## Complete Feature List (45 Features)

See `docs/FEATURES.md` for the full list with descriptions.

## Integration Tools We Use

### Open Source CLI Tools (installed locally, NOT API dependencies):
- subfinder — passive subdomain enumeration
- amass — deep recon, ASN mapping
- wafw00f — WAF/CDN detection
- testssl.sh — SSL/TLS analysis
- nuclei — vulnerability scanning with templates
- naabu — fast port scanning
- httpx — HTTP probing + tech detection

### Free APIs (no key required):
- crt.sh — Certificate Transparency logs
- Wayback Machine CDX — historical URLs
- NVD API — CVE database

### Optional Paid APIs (tool works WITHOUT these):
- Shodan, SecurityTrails, VirusTotal, HIBP, hunter.io, Censys, GitHub API

---

## Important Conventions

1. **Python**: Use async/await everywhere. Type hints on all functions.
2. **Naming**: snake_case for Python, camelCase for TypeScript, PascalCase for React components.
3. **Error handling**: Every scanner wrapped in try/except. Never let one scanner crash the pipeline.
4. **Database**: Use SQLAlchemy async sessions. Always commit after writes.
5. **Frontend**: All data fetched via `/api/` endpoints. Polling every 2 seconds for live scan updates.
6. **No breaking changes**: When adding Feature N, Features 1 through N-1 must still work.