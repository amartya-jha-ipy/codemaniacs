# `analysis_engine`

Isolated, reusable backend modules for the SENTINEL-CRS static-analysis pipeline:
behavioral similarity, IOC matching, and the forensic evidence pipeline. The package
integrates additively with the existing FastAPI app in `backend/main.py` — the
original API contract and the frontend keep working even if any sub-feature is
unavailable.

Import style matches the rest of the backend (run from `backend/`):

```python
from analysis_engine import feature_extractor, similarity, ioc_service, evidence_report
```

## Modules

| Module | Responsibility |
|---|---|
| `config.py` | Env-overridable settings: DB path, reports dir, similarity threshold, tool version, neutral report branding. |
| `store.py` | Shared SQLite connection + schema for the new tables (`analyses`, `feature_vectors`, `iocs`, `audit_events`). Leaves the legacy `audit_logs` table untouched. |
| `feature_extractor.py` | Verifiable static extraction from APK bytes — permissions, suspicious-API string presence, URLs/IPs/domains. Never fabricates values. |
| `similarity.py` | `extract_feature_vector`, `calculate_similarity` (cosine), `find_similar_apks`, and optional DBSCAN + TF-IDF `cluster_corpus`. |
| `ioc_service.py` | Local IOC store and matching: `initialize_ioc_database`, `add_ioc`, `match_iocs`, `check_file_hash`. Ships empty; no fabricated intel. |
| `evidence_report.py` | `build_json_report` + `generate_pdf_report` (ReportLab). Reports only collected data; missing fields are explicit `null`/empty. |
| `audit_trail.py` | Append-only event log (`record_event`, `get_events`). |
| `chain_audit.py` | Bridge to the tamper-evident HMAC audit chain. |
| `unpacker.py` | Anti-evasion static unpacking. |
| `sandbox.py` | Simulated dynamic sandbox / telemetry layer. |

## API endpoints (served by `main.py`)

| Method & path | Purpose |
|---|---|
| `POST /api/analyze-apk` | Existing contract **preserved**; adds optional `analysis_id`, `static_indicators`, `similar_apks`, `ioc_matches`. |
| `GET /api/analysis/{id}/similar` | Static-feature similarity for a prior analysis. |
| `GET /api/analysis/{id}/report.json` | Machine-readable evidence report. |
| `GET /api/analysis/{id}/report.pdf` | Print-friendly PDF evidence report. |

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `SENTINEL_DB_PATH` | `database/sentinel_audit.db` | SQLite database file. |
| `SENTINEL_REPORTS_DIR` | `reports` | Output directory for generated reports. |
| `SENTINEL_SIMILARITY_THRESHOLD` | `0.80` | Cosine threshold above which APKs are reported as similar. |
| `SENTINEL_MIN_CLUSTER_VECTORS` | `4` | Minimum stored vectors before DBSCAN clustering is attempted. |

## Tests

```bash
cd backend
pip install -r requirements.txt
python -m pytest -q
```

## Scope & limitations

- Static analysis only; where a full AXML/DEX parser is unavailable, features are
  recovered heuristically from archive bytes.
- The IOC database is empty by default — matches depend on locally loaded,
  provenance-tagged indicators.
- Similarity reflects shared static characteristics only; it does **not** establish
  common authorship. Recorded hashes support integrity checks, not a complete chain
  of custody.
