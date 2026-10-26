# ANVESH — Android Network & Visual Evidence Security Hub

A Cyber Crime & Digital Forensics platform for authorised investigators (themed for
the Economic Offences Unit, Bihar Police) to triage **seized Android application
packages (APKs)**. A specimen is hashed, statically parsed, checked for evasion
techniques, scored, and compiled into a court‑ready evidence record — with the chain
of custody preserved in a tamper‑evident audit log.

> **Demonstration project.** Not an official Government of Bihar website. Sample
> specimens are synthetic and inert; no real malware is included or executed.

---

## Architecture

- **Frontend** — Next.js (`frontend/`): government‑portal landing (`/`), investigator
  console with login + dashboard (`/console`), feedback page (`/feedback`).
- **Backend** — FastAPI (`backend/`): `POST /api/login`, `POST /api/analyze-apk`,
  report + similarity endpoints. SQLite for users, analyses, IOCs and the audit log.
- **Pipeline** (runs for every uploaded `.apk`):
  `parser.py` (manifest / permissions / strings) → anti‑evasion unpacking + simulated
  sandbox → `scoring.py` (explainable risk score & severity) → `ai.py` (executive
  briefing via a local Ollama LLM, with a rule‑based fallback) → similarity + IOC
  matching → persisted to SQLite.

## Prerequisites

- **Python 3.11+**
- **Node.js 18+** (Node 20+ recommended)
- *(optional)* **[Ollama](https://ollama.com)** running `qwen2.5-coder` for the LLM
  briefing. Without it, the briefing uses a clear rule‑based fallback — everything
  else works unchanged.

## Setup & run

### 1. Backend (port 8000)
```bash
cd backend
pip install -r requirements.txt
python seed_demo.py          # optional: load demo IOC indicators (see below)
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```
On first start the `users` table is auto‑seeded with demo accounts.

### 2. Frontend (port 3000)
```bash
cd frontend
npm install
npm run dev
```
Open **http://localhost:3000**.

## Demo accounts

| Username | Password | Role | Role switch |
|---|---|---|---|
| `analyst` | `analyst@123` | LVL‑3 Analyst | ✅ step‑down |
| `chief` | `chief@123` | Chief Forensic Comm. | ✅ step‑down |
| `officer` | `officer@123` | LVL‑2 Investigator | 🔒 locked (junior) |
| `constable` | `constable@123` | LVL‑1 Junior | 🔒 locked (junior) |

Passwords are stored as PBKDF2‑salted hashes (`backend/auth.py`). Role and station are
assigned from the account record; junior ranks cannot change their clearance.

## Demo specimens (`samples/`)

Three inert synthetic APKs give a full low → medium → critical spread:

| File | Result | Shows |
|---|---|---|
| `ANVESH_demo_malicious.apk` | **CRITICAL (100)** | dangerous permissions, C2 indicators, **known‑malicious hash** |
| `ANVESH_demo_suspicious.apk` | **MEDIUM** | some sensitive permissions, mild indicators |
| `ANVESH_demo_benign.apk` | **LOW (0)** | nothing flagged |

**Walkthrough:** log in as `analyst` → *Active Specimen Analysis* → drag in
`samples/ANVESH_demo_malicious.apk` → review the score, Permissions / Code & Evasion /
Network IOCs tabs, the IOC match, then *Court‑Ready Reports* for the PDF / dossier.

The malicious specimen's IOC match requires the demo indicators to be loaded once:
```bash
python backend/seed_demo.py
```
(The C2 IP, domain and the sample's SHA‑256 are tagged `SYNTHETIC-DEMO-FIXTURE`.)

## Tests
```bash
cd backend
python -m pytest -q
```

## Notes & limitations

- `scoring.py` is a **deterministic, explainable rule engine** (not a trained ML
  model). The LLM component is the Ollama briefing in `ai.py` (optional).
- `androguard` is optional; without it the parser uses a built‑in static fallback.
- Only `.apk` files that are valid Android archives (contain `AndroidManifest.xml`)
  are accepted; anything else is rejected.
- Recorded hashes support integrity verification; they do not by themselves establish
  authenticity or a complete chain of custody.
