"""Tests for the Phase 3 anti-evasion / unpacking module."""
import io
import os
import zipfile

from analysis_engine import unpacker


def _build_apk(entries: dict, manifest: bytes | None = b"<manifest/>"):
    """Build in-memory APK-like bytes from {name: bytes} plus an optional manifest."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        if manifest is not None:
            zf.writestr("AndroidManifest.xml", manifest)
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_shannon_entropy_bounds():
    assert unpacker.shannon_entropy(b"") == 0.0
    assert unpacker.shannon_entropy(b"\x00" * 100) == 0.0  # single symbol -> 0 bits
    assert unpacker.shannon_entropy(os.urandom(8192)) > 7.5  # random -> near 8 bits


def test_invalid_zip_is_handled():
    report = unpacker.analyze_anti_evasion(b"not a zip at all")
    assert report["is_valid_zip"] is False
    assert report["indicators"] == []
    assert report["notes"]


def test_secondary_dex_and_hidden_payload_flagged():
    apk = _build_apk({
        "classes.dex": b"dex\n035\x00" + b"benign",
        "classes2.dex": b"dex\n035\x00" + b"secondary",
        "assets/payload.bin": os.urandom(4096),  # high-entropy encrypted blob
    })
    report = unpacker.analyze_anti_evasion(apk)
    assert report["is_valid_zip"] is True
    assert report["multidex"]["has_secondary_dex"] is True
    assert report["multidex"]["dex_count"] == 2
    assert any(p["name"] == "assets/payload.bin" for p in report["embedded_payloads"])
    assert "secondary_dex_payload" in report["indicators"]
    assert "hidden_encrypted_payload" in report["indicators"]


def test_dynamic_code_loading_detected():
    apk = _build_apk({
        "classes.dex": b"dex\n035\x00 some DexClassLoader loadDex reference",
    })
    report = unpacker.analyze_anti_evasion(apk)
    assert report["dynamic_code_loading"]["detected"] is True
    assert "DexClassLoader" in report["dynamic_code_loading"]["signatures"]
    assert "dynamic_code_loading" in report["indicators"]


def test_string_encryption_detected():
    apk = _build_apk({
        "classes.dex": b"dex\n035\x00 SecretKeySpec doFinal android/util/Base64 AES/CBC",
    })
    report = unpacker.analyze_anti_evasion(apk)
    assert report["string_encryption"]["detected"] is True
    assert "string_encryption" in report["indicators"]


def test_benign_apk_has_no_evasion_indicators():
    apk = _build_apk({
        "classes.dex": b"dex\n035\x00 just some normal strings and HttpURLConnection",
        "res/layout/main.xml": b"<LinearLayout/>",
    })
    report = unpacker.analyze_anti_evasion(apk)
    assert report["indicators"] == []
    assert report["dynamic_code_loading"]["detected"] is False
    assert report["string_encryption"]["detected"] is False


def test_manifest_axml_padding_flagged():
    # AXML header: magic (03 00 08 00) + declared size 16, but entry is 32 bytes.
    manifest = unpacker._AXML_MAGIC + (16).to_bytes(4, "little") + b"\x00" * 24
    apk = _build_apk({"classes.dex": b"dex\n035\x00"}, manifest=manifest)
    report = unpacker.analyze_anti_evasion(apk)
    assert report["manifest"]["magic_valid"] is True
    assert report["manifest"]["padding_bytes"] == 16
    assert "manifest_anomaly" in report["indicators"]


def test_missing_manifest_noted():
    apk = _build_apk({"classes.dex": b"dex\n035\x00"}, manifest=None)
    report = unpacker.analyze_anti_evasion(apk)
    assert report["manifest"]["present"] is False
    assert any("missing" in a for a in report["manifest"]["anomalies"])
