import pytest

from analysis_engine import ioc_service

SYNTH = "SYNTHETIC-TEST-FIXTURE"


def test_database_initializes_empty():
    ioc_service.initialize_ioc_database()
    assert ioc_service.count_iocs() == 0


def test_exact_ip_domain_and_hash_match():
    ioc_service.add_ioc("ip", "185.220.101.5", SYNTH, {"threat_category": "c2"})
    ioc_service.add_ioc("domain", "evil.example.com", SYNTH)
    h = "a" * 64
    ioc_service.add_ioc("sha256", h, SYNTH)

    result = ioc_service.match_iocs({
        "ips": ["185.220.101.5"],
        "domains": ["evil.example.com"],
        "sha256": [h],
    })
    assert result["match_count"] == 3
    kinds = {m["type"] for m in result["matches"]}
    assert kinds == {"ip", "domain", "sha256"}
    assert all(m["source"] == SYNTH for m in result["matches"])


def test_domain_normalization_matches_mixed_case_and_trailing_dot():
    ioc_service.add_ioc("domain", "Evil.Example.COM.", SYNTH)
    result = ioc_service.match_iocs({"domains": ["evil.example.com"]})
    assert result["match_count"] == 1


def test_no_match_reports_neutral_message():
    result = ioc_service.match_iocs({"ips": ["8.8.8.8"]})
    assert result["match_count"] == 0
    assert result["message"] == "No matching IOC found in the local database"


def test_invalid_indicators_go_to_unchecked():
    result = ioc_service.match_iocs({"ips": ["999.1.1.1"], "domains": ["not a domain"]})
    assert result["match_count"] == 0
    assert len(result["unchecked"]) == 2


def test_duplicate_insertion_does_not_duplicate_rows():
    ioc_service.add_ioc("ip", "10.0.0.1", SYNTH)
    ioc_service.add_ioc("ip", "10.0.0.1", SYNTH)
    assert ioc_service.count_iocs() == 1


def test_missing_provenance_is_rejected():
    with pytest.raises(ioc_service.IOCValidationError):
        ioc_service.add_ioc("ip", "10.0.0.1", "")


def test_url_is_rejected_as_domain():
    with pytest.raises(ioc_service.IOCValidationError):
        ioc_service.normalize_ioc("domain", "http://evil.example.com/path")


def test_sql_injection_style_input_is_safe():
    ioc_service.add_ioc("ip", "1.2.3.4", SYNTH)
    injection = "'; DROP TABLE iocs; --"
    # Used as a file hash lookup: must not match and must not harm the table.
    assert ioc_service.check_file_hash(injection) is None
    # Table still intact and row still present.
    assert ioc_service.count_iocs() == 1


def test_check_file_hash_exact():
    h = "b" * 64
    ioc_service.add_ioc("sha256", h, SYNTH, {"threat_category": "trojan"})
    row = ioc_service.check_file_hash(h)
    assert row is not None
    assert row["threat_category"] == "trojan"
    assert ioc_service.check_file_hash("c" * 64) is None
