"""SQLite persistence shared by the analysis-engine modules.

This module owns the *new* tables introduced by AI/ML Engineer 2. It never touches
the existing ``audit_logs`` table managed by ``database.py`` -- it only adds tables
to the same database file. All public helpers accept an optional ``db_path`` so
tests can run against a temporary database.
"""
import json
import os
import sqlite3
from datetime import datetime, timezone

from . import config


def _resolve(db_path=None):
    return db_path or config.DB_PATH


def utc_now():
    """ISO-8601 UTC timestamp used consistently across the engine."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_conn(db_path=None):
    """Return a SQLite connection, creating the parent directory if needed."""
    path = _resolve(db_path)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(db_path=None):
    """Create every analysis-engine table if it does not already exist.

    Idempotent and additive: existing tables (e.g. ``audit_logs``) are left intact.
    """
    conn = get_conn(db_path)
    try:
        cur = conn.cursor()

        # One row per analysed specimen; stores the full findings payload so reports
        # can be regenerated without re-uploading the APK.
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256      TEXT NOT NULL,
                filename    TEXT,
                findings    TEXT NOT NULL,
                created_at  TEXT NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_analyses_sha256 ON analyses(sha256)")

        # Normalised static feature tokens per analysis, used for similarity.
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS feature_vectors (
                analysis_id INTEGER PRIMARY KEY,
                sha256      TEXT NOT NULL,
                filename    TEXT,
                tokens      TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES analyses(id)
            )
            """
        )

        # Local indicator-of-compromise store.
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS iocs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type        TEXT NOT NULL,
                value           TEXT NOT NULL,
                source          TEXT NOT NULL,
                threat_category TEXT,
                confidence      TEXT,
                first_seen      TEXT,
                last_seen       TEXT,
                created_at      TEXT NOT NULL,
                UNIQUE (ioc_type, value)
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(ioc_type, value)")

        # Append-only audit trail.
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type   TEXT NOT NULL,
                analysis_id  INTEGER,
                sha256       TEXT,
                details      TEXT,
                tool_version TEXT,
                created_at   TEXT NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_analysis ON audit_events(analysis_id)")

        conn.commit()
    finally:
        conn.close()


def save_analysis(sha256, filename, findings, db_path=None):
    """Persist a findings payload and return the new analysis id."""
    init_schema(db_path)
    conn = get_conn(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO analyses (sha256, filename, findings, created_at) VALUES (?, ?, ?, ?)",
            (sha256, filename, json.dumps(findings), utc_now()),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_analysis(analysis_id, db_path=None):
    """Return the stored findings dict for an analysis id, or ``None``."""
    conn = get_conn(db_path)
    try:
        row = conn.execute(
            "SELECT id, sha256, filename, findings, created_at FROM analyses WHERE id = ?",
            (analysis_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return {
        "analysis_id": row["id"],
        "sha256": row["sha256"],
        "filename": row["filename"],
        "findings": json.loads(row["findings"]),
        "created_at": row["created_at"],
    }
