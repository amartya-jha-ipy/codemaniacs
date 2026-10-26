"""Tests for the Phase 4 simulated dynamic sandbox + telemetry module."""
import hashlib

from analysis_engine import sandbox


def _features(permissions=None, apis=None):
    permissions = permissions or []
    apis = apis or []
    return {
        "sha256": hashlib.sha256(b"specimen").hexdigest(),
        "permissions": [{"name": p, "level": "Critical"} for p in permissions],
        "suspicious_apis": apis,
    }


def test_mock_telemetry_is_deterministic():
    seed = "0123456789abcdef"
    a = sandbox.generate_mock_telemetry(seed)
    b = sandbox.generate_mock_telemetry(seed)
    assert a == b


def test_mock_telemetry_defeats_emulator_tells():
    tele = sandbox.generate_mock_telemetry("0123456789abcdef")
    # Battery must vary and never be a stuck 100%.
    levels = [b["level"] for b in tele["battery"]]
    assert len(set(round(l) for l in levels)) > 1
    assert all(l < 100 for l in levels)
    assert all(b["charging"] is False for b in tele["battery"])
    # Accelerometer must show motion, not a frozen reading.
    assert any(abs(s["x"]) > 0.05 or abs(s["y"]) > 0.05 for s in tele["accelerometer"])
    assert tele["touch_events"]


def test_overlay_accessibility_behaviour():
    feats = _features(
        permissions=["android.permission.SYSTEM_ALERT_WINDOW",
                     "android.permission.BIND_ACCESSIBILITY_SERVICE"],
        apis=["addView", "AccessibilityService"],
    )
    behaviours = sandbox.derive_behavioral_sequences(feats)
    indicators = {b["indicator"] for b in behaviours}
    assert "overlay_accessibility_abuse" in indicators


def test_sms_and_dcl_and_recon_behaviours():
    feats = _features(
        permissions=["android.permission.READ_SMS"],
        apis=["sendTextMessage", "DexClassLoader", "getDeviceId", "Runtime;->exec"],
    )
    behaviours = sandbox.derive_behavioral_sequences(feats)
    indicators = {b["indicator"] for b in behaviours}
    assert {"sms_exfiltration", "dynamic_code_loading",
            "device_fingerprinting", "runtime_command_execution"} <= indicators
    # Each behaviour must carry a concrete API-call sequence.
    assert all(b["api_sequence"] for b in behaviours)


def test_benign_features_yield_no_behaviours():
    feats = _features(permissions=["android.permission.INTERNET"], apis=["HttpURLConnection"])
    behaviours = sandbox.derive_behavioral_sequences(feats)
    assert behaviours == []


def test_simulate_full_report_shape():
    feats = _features(
        permissions=["android.permission.READ_SMS"],
        apis=["sendTextMessage", "DexClassLoader"],
    )
    anti = {"dynamic_code_loading": {"detected": True}}
    report = sandbox.simulate(b"specimen", feats, anti, case_id="BR-TEST-1")
    assert report["simulated"] is True
    assert "NOT" in report["disclaimer"]  # clearly labelled as not executed
    assert report["case_id"] == "BR-TEST-1"
    assert report["dynamic_indicators"]  # non-empty for a malicious sample
    assert report["api_call_sequences"]
    assert report["telemetry_log"]
    assert len(report["anti_sandbox_evasions_defeated"]) == 3


def test_simulate_is_reproducible_per_specimen():
    feats = _features(apis=["DexClassLoader"])
    r1 = sandbox.simulate(b"same-bytes", feats)
    r2 = sandbox.simulate(b"same-bytes", feats)
    assert r1["telemetry"] == r2["telemetry"]
    assert r1["seed"] == r2["seed"]
