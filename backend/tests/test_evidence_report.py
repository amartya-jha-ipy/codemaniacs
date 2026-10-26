import hashlib
import os

from analysis_engine import evidence_report, store


def _record(perms=True):
    findings = {
        "filename": "sample.apk",
        "sha256": "d" * 64,
        "size_mb": 1.5,
        "is_valid_zip": True,
        "permissions": [{"name": "android.permission.READ_SMS", "level": "Critical"}] if perms else [],
        "suspicious_apis": ["sendTextMessage"] if perms else [],
        "urls": ["http://evil.example.com"] if perms else [],
        "ips": [], "domains": ["evil.example.com"] if perms else [],
        "risk_score": 92,
        "classification": "Financial Extortion / RAT",
        "risk_explanation": "heuristic",
        "executive_briefing": "summary text",
    }
    aid = store.save_analysis(findings["sha256"], findings["filename"], findings)
    return store.get_analysis(aid)


def test_json_report_has_stable_schema_and_no_fabricated_runtime():
    report = evidence_report.build_json_report(_record())
    for key in ("report_schema_version", "file_identity", "findings", "risk",
                "runtime_observations", "limitations", "missing_data", "tool_versions"):
        assert key in report
    assert report["runtime_observations"]["collected"] is False
    assert report["file_identity"]["sha256"] == "d" * 64


def test_missing_data_is_recorded_explicitly():
    report = evidence_report.build_json_report(_record(perms=False))
    assert "permissions" in report["missing_data"]
    assert "network_indicators" in report["missing_data"]
    assert "similarity_analysis" in report["missing_data"]
    assert "ioc_matching" in report["missing_data"]


def test_pdf_is_created_non_empty_and_hash_verifies(isolated_storage):
    report = evidence_report.build_json_report(_record())
    meta = evidence_report.generate_pdf_report(report)
    assert os.path.exists(meta["path"])
    assert os.path.getsize(meta["path"]) > 0
    # Output stays inside the configured reports directory (no path traversal).
    assert os.path.abspath(meta["path"]).startswith(os.path.abspath(isolated_storage["reports_dir"]))
    # Reported hash matches the actual file bytes.
    with open(meta["path"], "rb") as fh:
        assert hashlib.sha256(fh.read()).hexdigest() == meta["sha256"]
    assert len(meta["sha256"]) == 64


def test_pdf_filename_is_safe():
    report = evidence_report.build_json_report(_record())
    meta = evidence_report.generate_pdf_report(report)
    assert meta["filename"].endswith(".pdf")
    assert "/" not in meta["filename"] and "\\" not in meta["filename"]
    assert ".." not in meta["filename"]
