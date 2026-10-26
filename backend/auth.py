"""Username/password authentication backed by SQLite.

Stores officer accounts in a ``users`` table in the same SQLite database used by the
rest of the backend. Passwords are never stored in plaintext: each is hashed with
PBKDF2-HMAC-SHA256 over a per-user random salt.

On first run the table is seeded with demonstration accounts (one per clearance
level) so the login flow works out of the box. Replace or extend these for a real
deployment.
"""
import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.environ.get("SENTINEL_DB_PATH", os.path.join("database", "sentinel_audit.db"))

_PBKDF2_ROUNDS = 120_000

# Demonstration accounts: (username, password, clearance/role, station, full name).
_SEED_USERS = [
    ("analyst",   "analyst@123",   "LVL-3 ANALYST",         "Kotwali Cyber Cell, Patna (HQ)", "Cyber Cell Analyst"),
    ("officer",   "officer@123",   "LVL-2 INVESTIGATOR",    "Muzaffarpur Cyber PS",          "Investigating Officer"),
    ("chief",     "chief@123",     "CHIEF FORENSIC COMM.",  "Kotwali Cyber Cell, Patna (HQ)", "Chief Forensic Commander"),
    ("constable", "constable@123", "LVL-1 JUNIOR",          "Gaya Cyber Crime Unit",         "Duty Constable"),
]


def _conn():
    parent = os.path.dirname(DB_PATH)
    if parent:
        os.makedirs(parent, exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               bytes.fromhex(salt), _PBKDF2_ROUNDS).hex()


def init_users():
    """Create the users table and seed demo accounts if empty. Idempotent."""
    conn = _conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT NOT NULL UNIQUE,
                salt       TEXT NOT NULL,
                pw_hash    TEXT NOT NULL,
                role       TEXT NOT NULL,
                station    TEXT,
                full_name  TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
        count = cur.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        if count == 0:
            for username, pw, role, station, name in _SEED_USERS:
                create_user(username, pw, role, station, name, _conn_override=conn)
            conn.commit()
    finally:
        conn.close()


def create_user(username, password, role, station=None, full_name=None, _conn_override=None):
    """Insert a user with a salted PBKDF2 password hash."""
    conn = _conn_override or _conn()
    try:
        salt = secrets.token_hex(16)
        pw_hash = _hash_password(password, salt)
        conn.execute(
            "INSERT INTO users (username, salt, pw_hash, role, station, full_name, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username.strip().lower(), salt, pw_hash, role, station, full_name,
             datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
        )
        if _conn_override is None:
            conn.commit()
    finally:
        if _conn_override is None:
            conn.close()


def verify_user(username, password):
    """Return the user record (without secrets) if credentials are valid, else None."""
    if not username or not password:
        return None
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username.strip().lower(),)
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    expected = _hash_password(password, row["salt"])
    # Constant-time comparison to avoid timing leaks.
    if not secrets.compare_digest(expected, row["pw_hash"]):
        return None
    return {
        "username": row["username"],
        "role": row["role"],
        "station": row["station"],
        "full_name": row["full_name"],
    }
