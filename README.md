# SHODH — Attack Surface Intelligence Platform

> One domain in. Full attack surface out.

SHODH is a self-hosted attack surface mapping tool. Enter any domain name — it discovers subdomains, open ports, WAF coverage, tech stack, SSL health, CVEs, leaked credentials, and more — visualized as an interactive 3D constellation map with AI-generated risk scoring.

## Quick Start

### Prerequisites
- Python 3.12+
- Node.js 18+
- PostgreSQL 16

### Backend Setup
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
cp .env.example .env      # Edit with your DB credentials
uvicorn app.main:app --reload --port 8000
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

### Database Setup
```bash
# Create database
createdb shodh

# Run migrations
cd backend
alembic upgrade head
```

Open http://localhost:5173 in your browser.

## Project Structure
```
shodh/
├── backend/
│   ├── app/
│   │   ├── api/          # API route handlers
│   │   ├── core/         # Config, database, dependencies
│   │   ├── models/       # SQLAlchemy database models
│   │   ├── scanners/     # Scan engine modules (one per feature)
│   │   ├── schemas/      # Pydantic request/response schemas
│   │   └── services/     # Business logic layer
│   ├── alembic/          # Database migrations
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── components/   # Reusable UI components
│   │   ├── pages/        # Page-level components
│   │   ├── hooks/        # Custom React hooks
│   │   └── utils/        # Helper functions
│   └── package.json
└── README.md
```

## Tech Stack
- **Backend:** Python 3.12 + FastAPI
- **Database:** PostgreSQL 16
- **Frontend:** React 18 + TypeScript + Tailwind CSS + Three.js
- **DNS:** dnspython
- **HTTP:** httpx (Python)
