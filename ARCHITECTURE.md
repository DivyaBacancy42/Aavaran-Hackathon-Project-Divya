# SHODH — Technical Architecture

## System Overview

```
┌─────────────────────────────────────────┐
│            FRONTEND (React)              │
│      localhost:5173 (Vite dev server)    │
│                                          │
│  Dashboard.tsx → Domain Input            │
│  ScanView.tsx  → Results Display         │
│  (Three.js)   → 3D Constellation Map    │
│                                          │
│  Polls GET /api/scans/{id} every 2s     │
└──────────────────┬──────────────────────┘
                   │ HTTP (Vite proxies /api → :8000)
┌──────────────────▼──────────────────────┐
│            BACKEND (FastAPI)             │
│         localhost:8000                   │
│                                          │
│  POST /api/scans/     → Create scan     │
│  GET  /api/scans/     → List scans      │
│  GET  /api/scans/{id} → Scan detail     │
│  DELETE /api/scans/{id} → Delete scan   │
│                                          │
│  On POST: BackgroundTasks.add_task(      │
│    run_pipeline(scan_id)                 │
│  )                                       │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│          SCAN PIPELINE                   │
│   (backend/app/services/scan_pipeline.py)│
│                                          │
│  1. Mark scan as RUNNING                 │
│  2. Run each scanner module:             │
│     ├── dns_scanner.py                   │
│     ├── subdomain_scanner.py (future)    │
│     ├── port_scanner.py (future)         │
│     ├── waf_scanner.py (future)          │
│     ├── tech_scanner.py (future)         │
│     ├── ssl_scanner.py (future)          │
│     └── ... (one file per feature)       │
│  3. Mark scan as COMPLETED               │
│                                          │
│  Each scanner: independent, isolated,    │
│  writes results directly to PostgreSQL   │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│          POSTGRESQL 16                   │
│         localhost:5432                   │
│         Database: shodh                  │
│                                          │
│  Tables:                                 │
│  ├── scans (top-level scan jobs)         │
│  ├── subdomains                          │
│  ├── dns_records                         │
│  ├── ports                               │
│  ├── technologies                        │
│  ├── waf_results                         │
│  ├── ssl_info                            │
│  ├── cves                                │
│  ├── email_security                      │
│  └── cloud_buckets                       │
│                                          │
│  All tables link to scans via scan_id    │
│  CASCADE delete: delete scan = delete all│
└─────────────────────────────────────────┘
```

## Data Flow

1. User types domain in Dashboard.tsx
2. Frontend POSTs to `/api/scans/` with `{ "domain": "example.com" }`
3. Backend creates Scan record (status: PENDING), returns scan ID
4. Frontend navigates to `/scan/{id}`, starts polling every 2 seconds
5. Backend launches `run_pipeline(scan_id)` as BackgroundTask
6. Pipeline marks scan as RUNNING, executes each scanner module
7. Each scanner writes results to its own table(s)
8. Frontend picks up new data on each poll cycle
9. Pipeline marks scan as COMPLETED
10. Frontend shows final results with all data

## Scanner Module Pattern

Every scanner follows this exact pattern:

```python
# backend/app/scanners/{feature}_scanner.py

from dataclasses import dataclass, field
from typing import List

@dataclass
class FeatureResult:
    """Structured result from this scanner."""
    # ... fields specific to this feature

class FeatureScanner:
    def __init__(self, domain: str):
        self.domain = domain

    async def run(self) -> FeatureResult:
        """Execute the scan. Returns structured result."""
        # ... scanning logic
        return FeatureResult(...)
```

Then in scan_pipeline.py:

```python
async def _run_feature_scanner(db: AsyncSession, scan: Scan):
    """Run feature scanner and save results."""
    scanner = FeatureScanner(scan.domain)
    result = await scanner.run()
    # Save to database
    await db.commit()
```

## Database Schema Relationships

```
Scan (1)
 ├── has many → Subdomain (N)
 │    ├── has many → Port (N)
 │    ├── has many → Technology (N)
 │    │    └── has many → CVE (N)
 │    ├── has one  → WAFResult (1)
 │    └── has one  → SSLInfo (1)
 ├── has many → DNSRecord (N)
 ├── has one  → EmailSecurity (1)
 └── has many → CloudBucket (N)
```

## API Endpoints

| Method | Path | Description | Request Body | Response |
|---|---|---|---|---|
| POST | /api/scans/ | Start new scan | `{ "domain": "example.com" }` | ScanResponse |
| GET | /api/scans/ | List all scans | — | ScanListResponse |
| GET | /api/scans/{id} | Get scan with all data | — | ScanDetailResponse |
| DELETE | /api/scans/{id} | Delete scan + all data | — | 204 |

## Frontend Routes

| Path | Component | Description |
|---|---|---|
| / | Dashboard.tsx | Home page with domain input |
| /scan/:id | ScanView.tsx | Scan results page (all features render here) |

## Color Coding Convention

Used consistently across frontend for severity/status:

| Color | Tailwind Class | Meaning |
|---|---|---|
| Green (#00ff88) | text-shodh-accent | Safe, secured, low risk |
| Blue (#00aaff) | text-shodh-info | Informational, scanning |
| Yellow (#ffaa00) | text-shodh-warning | Warning, medium risk |
| Red (#ff3355) | text-shodh-danger | Critical, high risk, vulnerable |
| Purple (#8855ff) | text-shodh-purple | Secondary accent |
| Gray (#6b6b80) | text-shodh-muted | Disabled, unavailable |

## DNS Record Type Colors (ScanView.tsx)

| Type | Color |
|---|---|
| A | Green (accent) |
| AAAA | Blue (info) |
| MX | Yellow (warning) |
| NS | Purple |
| TXT | Gray (muted) |
| CNAME | Cyan |
| SOA | Pink |