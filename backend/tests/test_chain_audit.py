"""Tests for the SANDBOX_SIM bridge into the tamper-evident HMAC audit chain."""
import os

from analysis_engine import chain_audit

_KEY = "x" * 40  # >= 32 bytes, satisfies audit_log.MIN_KEY_LENGTH


def _load_chain_module():
    # Reuse the module the bridge already loads correctly (handles the frozen
    # dataclass / sys.modules registration quirk for us).
    return chain_audit._load_chain_module()


def test_append_stage_writes_sandbox_sim_and_chain_verifies(tmp_path):
    db = str(tmp_path / "chain.db")
    entry = chain_audit.append_stage(
        "BR-TEST-9", "SANDBOX_SIM",
        {"dynamic_indicators": ["dynamic_code_loading"], "simulated": True},
        key=_KEY, db_path=db,
    )
    assert entry is not None
    assert entry["stage"] == "SANDBOX_SIM"
    assert len(entry["entry_hash"]) == 64

    # The written chain must verify with the same key.
    import sqlite3
    mod = _load_chain_module()
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        ok, bad_id = mod.verify_chain(conn, _KEY)
    finally:
        conn.close()
    assert ok is True
    assert bad_id is None


def test_append_stage_noop_without_key(tmp_path, monkeypatch):
    monkeypatch.delenv("AUDIT_LOG_KEY", raising=False)
    db = str(tmp_path / "chain.db")
    entry = chain_audit.append_stage("BR-TEST-9", "SANDBOX_SIM", {"x": 1}, db_path=db)
    assert entry is None
    assert not os.path.exists(db) or os.path.getsize(db) == 0


def test_is_available_reflects_key(monkeypatch):
    monkeypatch.delenv("AUDIT_LOG_KEY", raising=False)
    assert chain_audit.is_available() is False
    assert chain_audit.is_available(_KEY) is True
