from fastapi import FastAPI, UploadFile, File, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import hashlib
import zipfile
import io
import os
import tempfile
import logging
from report_generator import generate_forensic_pdf
from database import init_db, log_analysis

# Real static APK parser + LLM briefing + DB-backed auth (all imported defensively).
try:
    import parser as apk_parser
    PARSER_AVAILABLE = True
except Exception as _parser_exc:  # pragma: no cover
    logging.warning("apk parser unavailable: %s", _parser_exc)
    PARSER_AVAILABLE = False

try:
    import ai as ai_briefing
    AI_AVAILABLE = True
except Exception as _ai_exc:  # pragma: no cover
    logging.warning("ai briefing unavailable: %s", _ai_exc)
    AI_AVAILABLE = False

try:
    import auth
    AUTH_AVAILABLE = True
except Exception as _auth_exc:  # pragma: no cover
    logging.warning("auth unavailable: %s", _auth_exc)
    AUTH_AVAILABLE = False

# --- Analysis engine (AI/ML Engineer 2 modules) ------------------------------
# Imported defensively: if the optional engine is unavailable the existing API
# keeps working unchanged.
try:
    from analysis_engine import (feature_extractor, similarity, ioc_service,
                                  evidence_report, audit_trail, unpacker,
                                  sandbox, chain_audit)
    from analysis_engine import store as engine_store
    ENGINE_AVAILABLE = True
except Exception as _engine_exc:  # pragma: no cover - import guard
    logging.warning("analysis_engine unavailable: %s", _engine_exc)
    ENGINE_AVAILABLE = False

# Explainable risk scorer (AI/ML & static-parsing lead). Imported defensively so
# the dynamic layer degrades gracefully if the module is absent.
try:
    import scoring as scoring_engine
    SCORING_AVAILABLE = True
except Exception as _scoring_exc:  # pragma: no cover - import guard
    logging.warning("scoring engine unavailable: %s", _scoring_exc)
    SCORING_AVAILABLE = False

logger = logging.getLogger("sentinel.main")

app = FastAPI(
    title="ANVESH v2.0 API",
    description="Bihar Police Cyber Cell Malware Analysis & Digital Forensics Engine",
    version="2.0.0"
)

# Initialize database on startup
init_db()

# Initialize the username/password auth store (seeds demo accounts if empty).
if AUTH_AVAILABLE:
    try:
        auth.init_users()
    except Exception as exc:  # pragma: no cover - startup guard
        logger.warning("auth init failed: %s", exc)

# Initialize the analysis-engine tables (additive; leaves audit_logs untouched).
if ENGINE_AVAILABLE:
    try:
        engine_store.init_schema()
        ioc_service.initialize_ioc_database()
    except Exception as exc:  # pragma: no cover - startup guard
        logger.warning("analysis_engine init failed: %s", exc)

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_SEVERITY_LABEL = {
    "LOW": "Low Risk",
    "MEDIUM": "Elevated Risk",
    "HIGH": "High Risk",
    "CRITICAL": "Critical Threat / Likely Malware",
}


@app.get("/")
def read_root():
    return {
        "status": "online",
        "system": "ANVESH v2.0 Backend",
        "agency": "Bihar Police Cyber Cell",
        "jurisdiction": "Digital Forensics & Malware Analysis"
    }


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/login")
def login(req: LoginRequest):
    """Authenticate an officer against the SQLite users table."""
    if not AUTH_AVAILABLE:
        raise HTTPException(status_code=503, detail="Authentication service unavailable.")
    user = auth.verify_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    return {"ok": True, **user}

@app.post("/api/analyze-apk")
async def analyze_apk(file: UploadFile = File(...), x_user_role: str = Header(default="Analyst")):
    # Only genuine .apk specimens are accepted.
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Invalid file format. Only .apk specimens are accepted.")

    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Empty file uploaded.")
    file_size_mb = round(len(contents) / (1024 * 1024), 2)
    sha256_hash = hashlib.sha256(contents).hexdigest()

    # Validate it is really an APK: a ZIP archive containing AndroidManifest.xml.
    try:
        with zipfile.ZipFile(io.BytesIO(contents)) as zf:
            if "AndroidManifest.xml" not in zf.namelist():
                raise HTTPException(status_code=400, detail="Not a valid APK: AndroidManifest.xml not found in the archive.")
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Not a valid APK: the file is not a valid Android package archive.")

    # --- Real static parse (parser.py): permissions, package, strings ------------
    parser_data = None
    permissions = []
    package_name = "unknown.package.name"
    if PARSER_AVAILABLE:
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(prefix="sentinel_", suffix=".apk", delete=False) as tmp:
                tmp.write(contents)
                tmp_path = tmp.name
            parser_data = apk_parser.parse_apk(tmp_path)
        except Exception as exc:
            logger.exception("apk parser failed")
            parser_data = {"status": "error", "error_message": str(exc)}
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

        if parser_data.get("status") != "success":
            raise HTTPException(status_code=400,
                                detail=f"Not a valid APK: {parser_data.get('error_message') or 'manifest could not be parsed'}")

        package_name = parser_data.get("package_name") or package_name
        perm_names = parser_data.get("requested_permissions") or []
        classify = feature_extractor.classify_permission if ENGINE_AVAILABLE else (lambda _p: "Info")
        permissions = [{"name": p, "level": classify(p)} for p in perm_names]

    # --- Static feature extraction for indicators / similarity / IOC -------------
    features = None
    if ENGINE_AVAILABLE:
        features = feature_extractor.extract_static_features(contents, file.filename)
        if not permissions:
            permissions = features["permissions"]

    # --- Anti-evasion + simulated sandbox (signals for the scorer) ---------------
    anti_evasion = None
    sandbox_report = None
    if ENGINE_AVAILABLE:
        try:
            anti_evasion = unpacker.analyze_anti_evasion(contents)
            sandbox_report = sandbox.simulate(contents, features, anti_evasion,
                                              case_id="BR-CYBER-2026-9048")
        except Exception:
            logger.exception("anti-evasion / sandbox failed")

    # --- Risk scoring (scoring.py rule engine over the real signals) -------------
    merged_indicators = []
    if anti_evasion and sandbox_report:
        merged_indicators = sorted(set(anti_evasion["indicators"] + sandbox_report["dynamic_indicators"]))
    elif features:
        merged_indicators = sorted(set(features.get("suspicious_apis", [])))

    risk_score, severity, score_result = 0, "LOW", None
    if SCORING_AVAILABLE:
        try:
            score_result = scoring_engine.calculate_risk_score({
                "status": "success",
                "requested_permissions": [p["name"] for p in permissions],
                "suspicious_indicators": merged_indicators,
            })
            risk_score = score_result["risk_score"]
            severity = score_result["severity"]
        except Exception:
            logger.exception("scoring failed")
    classification = _SEVERITY_LABEL.get(severity, severity)

    # --- Executive briefing (ai.py: local Ollama LLM, rule-based fallback) -------
    executive_briefing = (f"Static analysis of '{file.filename}' produced a composite risk score of "
                          f"{risk_score}/100 ({severity}).")
    briefing_source = "static"
    if AI_AVAILABLE:
        try:
            brief = ai_briefing.generate_executive_briefing(parser_data, score_result)
            executive_briefing = brief.get("briefing") or executive_briefing
            briefing_source = brief.get("source", "ai")
        except Exception:
            logger.exception("ai briefing failed")

    # --- Chain-of-custody log (SQLite) -------------------------------------------
    log_analysis(case_id="BR-CYBER-2026-9048", filename=file.filename, sha256=sha256_hash,
                 risk_score=risk_score, classification=classification, role=x_user_role)

    response = {
        "filename": file.filename,
        "size_mb": file_size_mb,
        "sha256": sha256_hash,
        "risk_score": risk_score,
        "severity": severity,
        "classification": classification,
        "manifest": {
            "package_name": package_name,
            "target_sdk": (parser_data or {}).get("target_sdk", 33),
            "min_sdk": (parser_data or {}).get("min_sdk", 21),
            "permissions": permissions,
        },
        "executive_briefing": executive_briefing,
        "briefing_source": briefing_source,
        "engines": {
            "parser": (parser_data or {}).get("engine", "unavailable"),
            "scoring": "deterministic_rules" if SCORING_AVAILABLE else "unavailable",
            "ai": briefing_source,
        },
    }

    # --- Persist findings + similarity / IOC / audit (engine) --------------------
    if ENGINE_AVAILABLE and features is not None:
        try:
            findings = dict(features)
            findings["permissions"] = permissions
            findings.update({
                "risk_score": risk_score,
                "severity": severity,
                "classification": classification,
                "risk_explanation": (score_result or {}).get("risk_contributors"),
                "executive_briefing": executive_briefing,
                "package_name": package_name,
            })
            analysis_id = engine_store.save_analysis(sha256_hash, file.filename, findings)
            similarity.persist_feature_vector(analysis_id, findings)
            audit_trail.record_event("analysis_created", analysis_id, sha256_hash,
                                     {"filename": file.filename, "role": x_user_role})

            similar = similarity.find_similar_apks(analysis_id)
            ioc_result = ioc_service.match_iocs(features)
            ioc_result["file_hash_match"] = ioc_service.check_file_hash(sha256_hash)
            audit_trail.record_event("analysis_completed", analysis_id, sha256_hash,
                                     {"ioc_matches": ioc_result["match_count"],
                                      "similar_found": len(similar["similar"]),
                                      "risk_score": risk_score})

            response["analysis_id"] = analysis_id
            response["static_indicators"] = {
                "permissions": permissions,
                "suspicious_apis": features["suspicious_apis"],
                "urls": features["urls"],
                "ips": features["ips"],
                "domains": features["domains"],
                "extraction_notes": features["extraction_notes"],
            }
            response["similar_apks"] = similar
            response["ioc_matches"] = ioc_result

            if anti_evasion is not None:
                response["anti_evasion"] = anti_evasion
                audit_trail.record_event("unpacking_completed", analysis_id, sha256_hash,
                                         {"indicators": anti_evasion["indicators"],
                                          "embedded_payloads": len(anti_evasion["embedded_payloads"])})
            if sandbox_report is not None:
                response["dynamic_sandbox"] = sandbox_report
                sandbox_event = {
                    "behavioral_flags": [b["name"] for b in sandbox_report["behavioral_flags"]],
                    "dynamic_indicators": sandbox_report["dynamic_indicators"],
                    "telemetry_log": sandbox_report["telemetry_log"],
                    "simulated": True,
                }
                audit_trail.record_event("sandbox_simulation", analysis_id, sha256_hash, sandbox_event)
                chain_entry = chain_audit.append_stage("BR-CYBER-2026-9048", "SANDBOX_SIM", sandbox_event)
                if chain_entry:
                    response["dynamic_sandbox"]["chain_audit"] = chain_entry
            if score_result is not None:
                response["composite_risk"] = score_result
                audit_trail.record_event("risk_grading", analysis_id, sha256_hash,
                                         {"risk_score": risk_score, "severity": severity,
                                          "indicators": merged_indicators})
        except Exception:
            logger.exception("engine augmentation failed")
            response["engine_status"] = "degraded"

    return response

@app.get("/api/download-report")
async def download_report(case_id: str = "BR-CYBER-2026-9048", filename: str = "specimen.apk", sha256: str = "85a03afa45cac81dd5d44a2a441ed1f00f844c6d4f15b0c4bd69da876394d156", risk_score: int = 92, classification: str = "Financial Extortion / RAT"):
    pdf_path = generate_forensic_pdf(
        case_id=case_id,
        filename=filename,
        sha256=sha256,
        risk_score=risk_score,
        classification=classification,
        briefing="This application exhibits high-risk indicators characteristic of malicious Android trojans. Permanently recorded in audit logs."
    )
    return FileResponse(pdf_path, media_type='application/pdf', filename=f"SENTINEL_Evidence_Report_{case_id}.pdf")

def _require_engine():
    if not ENGINE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Analysis engine is not available.")


def _load_analysis_or_404(analysis_id: int):
    record = engine_store.get_analysis(analysis_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return record


@app.get("/api/analysis/{analysis_id}/similar")
async def get_similar(analysis_id: int, threshold: float | None = None):
    """Return APKs with similar static features to the given analysis."""
    _require_engine()
    _load_analysis_or_404(analysis_id)
    try:
        return similarity.find_similar_apks(analysis_id, threshold=threshold)
    except Exception:
        logger.exception("similarity lookup failed")
        raise HTTPException(status_code=500, detail="Similarity lookup failed.")


@app.get("/api/analysis/{analysis_id}/report.json")
async def get_report_json(analysis_id: int):
    """Build the machine-readable evidence report from stored analysis data."""
    _require_engine()
    record = _load_analysis_or_404(analysis_id)
    try:
        features = record["findings"]
        sim = similarity.find_similar_apks(analysis_id)
        ioc = ioc_service.match_iocs(features)
        ioc["file_hash_match"] = ioc_service.check_file_hash(record["sha256"])
        events = audit_trail.get_events(analysis_id)
        return evidence_report.build_json_report(record, similarity=sim,
                                                 ioc_result=ioc, audit_events=events)
    except Exception:
        logger.exception("JSON report build failed")
        raise HTTPException(status_code=500, detail="Report generation failed.")


@app.get("/api/analysis/{analysis_id}/report.pdf")
async def get_report_pdf(analysis_id: int):
    """Generate (or regenerate) the PDF evidence report for an analysis."""
    _require_engine()
    record = _load_analysis_or_404(analysis_id)
    try:
        features = record["findings"]
        sim = similarity.find_similar_apks(analysis_id)
        ioc = ioc_service.match_iocs(features)
        ioc["file_hash_match"] = ioc_service.check_file_hash(record["sha256"])
        events = audit_trail.get_events(analysis_id)
        report = evidence_report.build_json_report(record, similarity=sim,
                                                   ioc_result=ioc, audit_events=events)
        meta = evidence_report.generate_pdf_report(report)
        audit_trail.record_event("report_generated", analysis_id, record["sha256"],
                                 {"report_sha256": meta["sha256"], "filename": meta["filename"]})
    except Exception:
        logger.exception("PDF report generation failed")
        raise HTTPException(status_code=500, detail="Report generation failed.")
    return FileResponse(meta["path"], media_type="application/pdf", filename=meta["filename"])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)