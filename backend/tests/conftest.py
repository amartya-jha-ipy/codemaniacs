"""Shared pytest fixtures for the analysis-engine tests.

Each test runs against a fresh temporary SQLite database and reports directory, so
nothing touches the real ``database/sentinel_audit.db``. Isolation works by
pointing ``analysis_engine.config`` at temp paths (the engine reads these at call
time, so reassigning the attributes is sufficient).
"""
import io
import os
import sys
import zipfile

import pytest

# Make the backend package root importable (analysis_engine, main, ...).
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from analysis_engine import config  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_storage(tmp_path, monkeypatch):
    """Redirect engine storage to a unique temp DB + reports dir per test."""
    db_path = str(tmp_path / "test_sentinel.db")
    reports_dir = str(tmp_path / "reports")
    monkeypatch.setattr(config, "DB_PATH", db_path)
    monkeypatch.setattr(config, "REPORTS_DIR", reports_dir)
    yield {"db_path": db_path, "reports_dir": reports_dir}


def build_fake_apk(permissions=None, strings=None, valid_zip=True):
    """Construct in-memory APK-like bytes for deterministic static extraction.

    ``permissions`` are embedded in a plaintext AndroidManifest.xml entry and
    ``strings`` in a classes.dex entry, so the extractor recovers them by regex.
    """
    if not valid_zip:
        return b"this is definitely not a zip archive"

    if permissions is None:
        permissions = ["android.permission.READ_SMS", "android.permission.INTERNET"]
    if strings is None:
        strings = [
            "sendTextMessage", "DexClassLoader", "getDeviceId",
            "http://evil.example.com/c2/beacon", "185.220.101.5",
        ]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        manifest = "<manifest>" + "".join(f"<uses-permission name='{p}'/>" for p in permissions) + "</manifest>"
        zf.writestr("AndroidManifest.xml", manifest.encode("ascii"))
        zf.writestr("classes.dex", ("\x00".join(strings)).encode("ascii"))
        zf.writestr("resources.arsc", b"\x00\x01\x02")
    return buf.getvalue()


@pytest.fixture
def fake_apk():
    return build_fake_apk()
