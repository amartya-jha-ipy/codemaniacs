import hashlib

from analysis_engine import feature_extractor
from tests.conftest import build_fake_apk


def test_extracts_permissions_apis_and_network_indicators(fake_apk):
    f = feature_extractor.extract_static_features(fake_apk, "sample.apk")
    assert f["is_valid_zip"] is True
    assert f["sha256"] == hashlib.sha256(fake_apk).hexdigest()

    perm_names = {p["name"] for p in f["permissions"]}
    assert "android.permission.READ_SMS" in perm_names
    assert "android.permission.INTERNET" in perm_names
    # READ_SMS is dangerous -> Critical; INTERNET -> Info.
    levels = {p["name"]: p["level"] for p in f["permissions"]}
    assert levels["android.permission.READ_SMS"] == "Critical"
    assert levels["android.permission.INTERNET"] == "Info"

    assert "sendTextMessage" in f["suspicious_apis"]
    assert "DexClassLoader" in f["suspicious_apis"]
    assert any("evil.example.com" in u for u in f["urls"])
    assert "evil.example.com" in f["domains"]
    assert "185.220.101.5" in f["ips"]


def test_invalid_zip_is_handled_without_fabrication():
    bad = build_fake_apk(valid_zip=False)
    f = feature_extractor.extract_static_features(bad, "broken.apk")
    assert f["is_valid_zip"] is False
    assert f["permissions"] == []
    assert f["suspicious_apis"] == []
    assert f["urls"] == [] and f["ips"] == [] and f["domains"] == []
    assert f["extraction_notes"]  # a note explains why nothing was extracted
    # Hash is still computed over the raw bytes.
    assert f["sha256"] == hashlib.sha256(bad).hexdigest()


def test_empty_feature_apk_yields_empty_collections():
    apk = build_fake_apk(permissions=[], strings=["hello", "world"])
    f = feature_extractor.extract_static_features(apk, "benign.apk")
    assert f["is_valid_zip"] is True
    assert f["permissions"] == []
    assert f["suspicious_apis"] == []


def test_url_path_is_not_treated_as_domain():
    # A URL whose host is an IP must not produce a bogus domain token.
    apk = build_fake_apk(permissions=[], strings=["http://185.220.101.5/evil/path"])
    f = feature_extractor.extract_static_features(apk, "ip_url.apk")
    assert "185.220.101.5" in f["ips"]
    assert f["domains"] == []  # the path segment is never a domain
