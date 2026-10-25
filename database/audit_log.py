"""
Tamper-evident audit log for the APK analysis pipeline.

Every pipeline stage appends one entry. Each entry stores the SHA-256 hash of
the previous entry, so changing or removing any past entry breaks the chain
and verify_chain() reports where.

Protections:
  1. Triggers block UPDATE and DELETE on the log table.
  2. Each entry's hash covers its content AND the previous entry's hash.
  3. verify_chain() recomputes every hash and checks every link.

Limit: anyone with write access to the .sqlite file can drop the triggers and
rewrite the chain. For stronger evidence, periodically record the latest
entry_hash somewhere outside this file (e.g. in the evidence bundle PDF or an
external log) and compare it later.
"""

from __future__ import annotations

import hashlib
import json
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


def _compute_hash(prev_hash: str, ts: str, case_id: str, stage: str, payload_json: str) -> str:
    material = "|".join([prev_hash, ts, case_id, stage, payload_json])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def init_audit_log(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def _last_hash(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    return row["entry_hash"] if row else GENESIS_HASH


def append_entry(
    conn: sqlite3.Connection,
    case_id: str,
    stage: str,
    payload: dict[str, Any],
    ts: Optional[str] = None,
) -> AuditEntry:
    """Append one entry to the chain. Raises ValueError for bad input."""
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
        entry_hash = _compute_hash(prev, stamp, case_id, stage, payload_json)
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


def verify_chain(conn: sqlite3.Connection) -> tuple[bool, Optional[int]]:
    """
    Recheck the whole log. Returns (True, None) if intact, or (False, id)
    with the id of the first entry that fails (bad hash or broken link).
    Entries that were deleted, or whose triggers were dropped and rewritten,
    are caught by the link check.
    """
    expected_prev = GENESIS_HASH
    for e in get_entries(conn):
        if e.prev_hash != expected_prev:
            return False, e.id
        recomputed = _compute_hash(e.prev_hash, e.ts, e.case_id, e.stage, e.payload_json)
        if recomputed != e.entry_hash:
            return False, e.id
        expected_prev = e.entry_hash
    return True, None


def latest_hash(conn: sqlite3.Connection) -> str:
    """The current chain head. Record this outside the database for stronger evidence."""
    return _last_hash(conn)
