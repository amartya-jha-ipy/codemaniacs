"""
Tamper-evident audit log for the APK analysis pipeline.

Every pipeline stage appends one entry. Each entry stores an HMAC-SHA256 of its
content plus the previous entry's HMAC, so changing or removing any past entry
breaks the chain and verify_chain() reports where.

Protections:
  1. Triggers block UPDATE and DELETE on the log table.
  2. Each hash is an HMAC keyed with a secret held OUTSIDE the database
     (environment variable AUDIT_LOG_KEY). Someone with only the .sqlite file
     cannot recompute a valid chain, even after dropping the triggers.
  3. Each entry covers the previous entry's hash, so deletion or reordering
     is detected.
  4. verify_chain() recomputes every HMAC and checks every link.

Still record latest_hash() outside the database (e.g. in the evidence PDF)
so that a whole-chain rewrite made with the key is also detectable.

Losing AUDIT_LOG_KEY means the chain can no longer be verified. Keep a copy
in a secure store, and never commit it to git.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

STAGES = (
    "INGESTION",
    "UNPACKING",
    "STATIC_SCAN",
    "SANDBOX_SIM",
    "RISK_GRADING",
    "EVIDENCE_EXPORT",
)

KEY_ENV_VAR = "AUDIT_LOG_KEY"
MIN_KEY_LENGTH = 32

GENESIS_HASH = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    case_id       TEXT NOT NULL,
    stage         TEXT NOT NULL CHECK (stage IN (
                      'INGESTION', 'UNPACKING', 'STATIC_SCAN',
                      'SANDBOX_SIM', 'RISK_GRADING', 'EVIDENCE_EXPORT')),
    payload_json  TEXT NOT NULL,
    prev_hash     TEXT NOT NULL,
    entry_hash    TEXT NOT NULL UNIQUE
);

CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE blocked');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: DELETE blocked');
END;
"""


@dataclass(frozen=True)
class AuditEntry:
    id: int
    ts: str
    case_id: str
    stage: str
    payload_json: str
    prev_hash: str
    entry_hash: str


def load_key(key: Optional[str | bytes] = None) -> bytes:
    """
    Return the HMAC key. If not passed in, read it from AUDIT_LOG_KEY.
    Raises ValueError if the key is missing or too short.
    """
    if key is None:
        key = os.environ.get(KEY_ENV_VAR)
    if key is None:
        raise ValueError(f"No audit key: set the {KEY_ENV_VAR} environment variable")
    raw = key.encode("utf-8") if isinstance(key, str) else bytes(key)
    if len(raw) < MIN_KEY_LENGTH:
        raise ValueError(f"Audit key must be at least {MIN_KEY_LENGTH} bytes")
    return raw


def _compute_hash(key: bytes, prev_hash: str, ts: str, case_id: str, stage: str, payload_json: str) -> str:
    material = "|".join([prev_hash, ts, case_id, stage, payload_json]).encode("utf-8")
    return hmac.new(key, material, hashlib.sha256).hexdigest()


def init_audit_log(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def _last_hash(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    return row["entry_hash"] if row else GENESIS_HASH


def append_entry(
    conn: sqlite3.Connection,
    key: Optional[str | bytes],
    case_id: str,
    stage: str,
    payload: dict[str, Any],
    ts: Optional[str] = None,
) -> AuditEntry:
    """Append one entry to the chain. Raises ValueError for bad input."""
    hmac_key = load_key(key)
    if not case_id.strip():
        raise ValueError("case_id is required")
    if stage not in STAGES:
        raise ValueError(f"stage must be one of {STAGES}")
    try:
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"payload must be JSON-serialisable: {exc}") from exc

    stamp = ts or datetime.now(timezone.utc).isoformat(timespec="microseconds")

    # BEGIN IMMEDIATE takes the write lock first, so two writers cannot
    # both read the same last hash and fork the chain.
    conn.execute("BEGIN IMMEDIATE")
    try:
        prev = _last_hash(conn)
        entry_hash = _compute_hash(hmac_key, prev, stamp, case_id, stage, payload_json)
        cur = conn.execute(
            "INSERT INTO audit_log (ts, case_id, stage, payload_json, prev_hash, entry_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (stamp, case_id, stage, payload_json, prev, entry_hash),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    return AuditEntry(cur.lastrowid, stamp, case_id, stage, payload_json, prev, entry_hash)


def get_entries(conn: sqlite3.Connection, case_id: Optional[str] = None) -> list[AuditEntry]:
    if case_id is None:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE case_id = ? ORDER BY id", (case_id,)
        ).fetchall()
    return [AuditEntry(r["id"], r["ts"], r["case_id"], r["stage"],
                       r["payload_json"], r["prev_hash"], r["entry_hash"]) for r in rows]


def verify_chain(conn: sqlite3.Connection, key: Optional[str | bytes] = None) -> tuple[bool, Optional[int]]:
    """
    Recheck the whole log with the key. Returns (True, None) if intact, or
    (False, id) with the first entry that fails (bad HMAC or broken link).
    A chain rebuilt with a different key fails on the first entry.
    """
    hmac_key = load_key(key)
    expected_prev = GENESIS_HASH
    for e in get_entries(conn):
        if e.prev_hash != expected_prev:
            return False, e.id
        recomputed = _compute_hash(hmac_key, e.prev_hash, e.ts, e.case_id, e.stage, e.payload_json)
        if not hmac.compare_digest(recomputed, e.entry_hash):
            return False, e.id
        expected_prev = e.entry_hash
    return True, None


def latest_hash(conn: sqlite3.Connection) -> str:
    """
    The current chain head. Record this outside the database (evidence PDF,
    external log). It does not need the key to read.
    """
    return _last_hash(conn)
