"""Integration tests exercising the live FastAPI app via TestClient.

These confirm the existing API contract is preserved and the new engine fields and
endpoints work end-to-end, without touching the real database (storage is
redirected by the autouse fixture; cwd is moved so legacy relative paths stay in
the temp dir too).
"""
import pytest
from fastapi.testclient import TestClient

from tests.conftest import build_fake_apk


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # keep database.py's relative paths inside tmp
    import main
    return TestClient(main.app)


def test_root_status_still_works(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.json()["status"] == "online"


def test_rejects_non_apk_upload(client):
    r = client.post("/api/analyze-apk",
                    files={"file": ("notes.txt", b"hello", "text/plain")})
    assert r.status_code == 400


def test_analyze_preserves_contract_and_adds_engine_fields(client):
    apk = build_fake_apk()
    r = client.post("/api/analyze-apk",
                    files={"file": ("loan_app.apk", apk, "application/octet-stream")},
                    headers={"x-user-role": "Analyst"})
    assert r.status_code == 200
    body = r.json()

    # Existing contract preserved exactly.
    for key in ("filename", "size_mb", "sha256", "risk_score", "classification",
                "manifest", "executive_briefing"):
        assert key in body
    assert "permissions" in body["manifest"]

    # New additive engine fields.
    assert "analysis_id" in body
    assert "static_indicators" in body
    perm_names = {p["name"] for p in body["static_indicators"]["permissions"]}
    assert "android.permission.READ_SMS" in perm_names
    assert "185.220.101.5" in body["static_indicators"]["ips"]
    assert "similar_apks" in body
    assert "ioc_matches" in body
    # No IOCs loaded -> neutral message, never "safe".
    assert body["ioc_matches"]["message"] == "No matching IOC found in the local database"


def test_report_json_and_pdf_endpoints(client):
    apk = build_fake_apk()
    r = client.post("/api/analyze-apk",
                    files={"file": ("sample.apk", apk, "application/octet-stream")})
    analysis_id = r.json()["analysis_id"]

    rj = client.get(f"/api/analysis/{analysis_id}/report.json")
    assert rj.status_code == 200
    report = rj.json()
    assert report["file_identity"]["sha256"] == r.json()["sha256"]
    assert report["runtime_observations"]["collected"] is False

    rp = client.get(f"/api/analysis/{analysis_id}/report.pdf")
    assert rp.status_code == 200
    assert rp.headers["content-type"] == "application/pdf"
    assert len(rp.content) > 0


def test_unknown_analysis_returns_404_without_corrupting_state(client):
    # A prior good analysis exists.
    apk = build_fake_apk()
    good = client.post("/api/analyze-apk",
                       files={"file": ("sample.apk", apk, "application/octet-stream")}).json()
    # Requesting a report for a non-existent id fails cleanly.
    assert client.get("/api/analysis/999999/report.pdf").status_code == 404
    # The prior analysis is still retrievable.
    assert client.get(f"/api/analysis/{good['analysis_id']}/report.json").status_code == 200


def test_similar_endpoint(client):
    apk = build_fake_apk()
    a1 = client.post("/api/analyze-apk",
                     files={"file": ("one.apk", apk, "application/octet-stream")}).json()
    client.post("/api/analyze-apk",
                files={"file": ("two.apk", apk, "application/octet-stream")})
    r = client.get(f"/api/analysis/{a1['analysis_id']}/similar", params={"threshold": 0.5})
    assert r.status_code == 200
    assert r.json()["total_compared"] >= 1
