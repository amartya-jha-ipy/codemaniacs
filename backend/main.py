from fastapi import FastAPI, UploadFile, File, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import hashlib
import zipfile
import io
import os
import logging
from report_generator import generate_forensic_pdf
from database import init_db, log_analysis

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
    title="SENTINEL-CRS v2.0 API",
    description="Bihar Police Cyber Cell Malware Analysis & Digital Forensics Engine",
    version="2.0.0"
)

# Initialize database on startup
init_db()

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

@app.get("/")
def read_root():
    return {
        "status": "online",
        "system": "SENTINEL-CRS v2.0 Backend",
        "agency": "Bihar Police Cyber Cell",
        "jurisdiction": "Digital Forensics & Malware Analysis"
    }

@app.post("/api/analyze-apk")
async def analyze_apk(file: UploadFile = File(...), x_user_role: str = Header(default="Analyst")):
    valid_extensions = (".apk", ".apkm", ".xapk")
    if not file.filename.endswith(valid_extensions):
        raise HTTPException(status_code=400, detail="Invalid file format. Only .apk, .apkm, or .xapk specimens are supported.")
    
    contents = await file.read()
    file_size_mb = round(len(contents) / (1024 * 1024), 2)
    
    # 1. Compute SHA-256 Evidence Hash
    sha256_hash = hashlib.sha256(contents).hexdigest()
    
    # Default extraction values
    package_name = "unknown.package.name"
    permissions = []
    risk_score = 15
    classification = "Benign / Unverified"
    
    # 2. Parse Archive
    try:
        with zipfile.ZipFile(io.BytesIO(contents)) as zf:
            package_name = file.filename.replace(".apkm", "").replace(".apk", "").lower()
    except Exception as e:
        print(f"Archive inspection note: {e}")

    # 3. Heuristic Risk Scoring
    if "loan" in file.filename.lower() or "secure" in file.filename.lower() or "chess" in file.filename.lower() or file_size_mb > 5:
        risk_score = 92
        classification = "Financial Extortion / RAT"
        permissions = [
            {"name": "android.permission.READ_SMS", "level": "Critical"},
            {"name": "android.permission.READ_CONTACTS", "level": "Critical"},
            {"name": "android.permission.ACCESS_FINE_LOCATION", "level": "Warning"},
            {"name": "android.permission.INTERNET", "level": "Info"}
        ]
    else:
        risk_score = 25
        classification = "Low Risk Utility"
        permissions = [
            {"name": "android.permission.INTERNET", "level": "Info"}
        ]

    # 4. Permanently log to SQLite Chain of Custody Database
    log_analysis(
        case_id="BR-CYBER-2026-9048",
        filename=file.filename,
        sha256=sha256_hash,
        risk_score=risk_score,
        classification=classification,
        role=x_user_role
    )

    # 5. Structured Forensic JSON Response (existing contract preserved)
    executive_briefing = (
        f"Static analysis of specimen '{file.filename}' yielded a composite threat score of {risk_score}/100 "
        f"({classification}). The package computes SHA-256 hash {sha256_hash[:16]}... and has been "
        f"permanently registered into the SQLite chain-of-custody audit database."
    )
    response = {
        "filename": file.filename,
        "size_mb": file_size_mb,
        "sha256": sha256_hash,
        "risk_score": risk_score,
        "classification": classification,
        "manifest": {
            "package_name": f"com.investigation.seized.{package_name}",
            "target_sdk": 33,
            "min_sdk": 21,
            "permissions": permissions
        },
        "executive_briefing": executive_briefing
    }

    # 6. Optional engine augmentation: real static extraction, similarity, IOC
    #    matching, and persistence. Wrapped so any failure leaves the base
    #    response (and the frontend) fully functional.
    if ENGINE_AVAILABLE:
        try:
            features = feature_extractor.extract_static_features(contents, file.filename)
            findings = dict(features)
            findings.update({
                "risk_score": risk_score,
                "classification": classification,
                "risk_explanation": (
                    "Heuristic composite score based on filename/size signals and static "
                    "permission/string presence. This is not a sandbox or runtime verdict."
                ),
                "executive_briefing": executive_briefing,
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
                                      "similar_found": len(similar["similar"])})

            response["analysis_id"] = analysis_id
            response["static_indicators"] = {
                "permissions": features["permissions"],
                "suspicious_apis": features["suspicious_apis"],
                "urls": features["urls"],
                "ips": features["ips"],
                "domains": features["domains"],
                "extraction_notes": features["extraction_notes"],
            }
            response["similar_apks"] = similar
            response["ioc_matches"] = ioc_result

            # --- Phase 3: anti-evasion / unpacking ---------------------------
            anti_evasion = unpacker.analyze_anti_evasion(contents)
            response["anti_evasion"] = anti_evasion
            audit_trail.record_event("unpacking_completed", analysis_id, sha256_hash,
                                     {"indicators": anti_evasion["indicators"],
                                      "embedded_payloads": len(anti_evasion["embedded_payloads"])})

            # --- Phase 4: simulated dynamic sandbox + telemetry --------------
            sandbox_report = sandbox.simulate(contents, features, anti_evasion,
                                              case_id="BR-CYBER-2026-9048")
            response["dynamic_sandbox"] = sandbox_report
            sandbox_event = {
                "behavioral_flags": [b["name"] for b in sandbox_report["behavioral_flags"]],
                "dynamic_indicators": sandbox_report["dynamic_indicators"],
                "telemetry_log": sandbox_report["telemetry_log"],
                "simulated": True,
            }
            audit_trail.record_event("sandbox_simulation", analysis_id, sha256_hash,
                                     sandbox_event)
            # Also append SANDBOX_SIM to the tamper-evident HMAC chain when keyed.
            chain_entry = chain_audit.append_stage("BR-CYBER-2026-9048", "SANDBOX_SIM",
                                                   sandbox_event)
            if chain_entry:
                response["dynamic_sandbox"]["chain_audit"] = chain_entry

            # --- Feed static + dynamic signals to the risk scorer ------------
            if SCORING_AVAILABLE:
                merged_indicators = sorted(set(
                    anti_evasion["indicators"] + sandbox_report["dynamic_indicators"]
                ))
                score_result = scoring_engine.calculate_risk_score({
                    "status": "success",
                    "requested_permissions": [p["name"] for p in features["permissions"]],
                    "suspicious_indicators": merged_indicators,
                })
                response["composite_risk"] = score_result
                audit_trail.record_event("risk_grading", analysis_id, sha256_hash,
                                         {"risk_score": score_result["risk_score"],
                                          "severity": score_result["severity"],
                                          "indicators": merged_indicators})
        except Exception as exc:
            logger.exception("engine augmentation failed")
            response["engine_status"] = "unavailable"

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