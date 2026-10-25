"""
SQLite IOC (Indicators of Compromise) store for cross-referencing APK artifacts.

Stores C2 domains, malicious IPs and file hashes. Lookups accept the
domains/IPs/hashes extracted from an APK and return the matching IOC rows.

Domain matching also checks parent domains, so an APK that contacts
"api.evil-c2.example" matches an IOC for "evil-c2.example".
"""

from __future__ import annotations

import ipaddress
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

VALID_TYPES = ("domain", "ip", "hash")

SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type    TEXT NOT NULL CHECK (ioc_type IN ('domain', 'ip', 'hash')),
    value       TEXT NOT NULL,
    source      TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    UNIQUE (ioc_type, value)
);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs (value);
"""

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$")


@dataclass(frozen=True)
class IOC:
    ioc_type: str
    value: str
    source: str
    first_seen: str


@dataclass(frozen=True)
class IOCMatch:
    ioc: IOC
    observed: str  # the value found in the APK (can be a subdomain of ioc.value)


def normalize_domain(value: str) -> str:
    v = value.strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(v):
        raise ValueError(f"Invalid domain: {value!r}")
    return v


def normalize_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


def normalize_hash(value: str) -> str:
    v = value.strip().lower()
    if not _HASH_RE.match(v):
        raise ValueError(f"Invalid MD5/SHA1/SHA256 hash: {value!r}")
    return v


_NORMALIZERS = {
    "domain": normalize_domain,
    "ip": normalize_ip,
    "hash": normalize_hash,
}


def connect(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def add_ioc(
    conn: sqlite3.Connection,
    ioc_type: str,
    value: str,
    source: str,
    first_seen: Optional[str] = None,
) -> bool:
    """Insert one IOC. Returns True if inserted, False if it already existed."""
    if ioc_type not in VALID_TYPES:
        raise ValueError(f"ioc_type must be one of {VALID_TYPES}")
    if not source.strip():
        raise ValueError("source is required for every IOC (for chain of custody)")
    clean = _NORMALIZERS[ioc_type](value)
    stamp = first_seen or datetime.now(timezone.utc).isoformat(timespec="seconds")
    cur = conn.execute(
        "INSERT OR IGNORE INTO iocs (ioc_type, value, source, first_seen) VALUES (?, ?, ?, ?)",
        (ioc_type, clean, source.strip(), stamp),
    )
    conn.commit()
    return cur.rowcount == 1


def add_many(conn: sqlite3.Connection, rows: Iterable[tuple[str, str, str]]) -> int:
    """rows: (ioc_type, value, source). Returns the number of newly inserted IOCs."""
    inserted = 0
    for ioc_type, value, source in rows:
        if add_ioc(conn, ioc_type, value, source):
            inserted += 1
    return inserted


def count_iocs(conn: sqlite3.Connection) -> dict[str, int]:
    rows = conn.execute("SELECT ioc_type, COUNT(*) AS n FROM iocs GROUP BY ioc_type").fetchall()
    counts = {t: 0 for t in VALID_TYPES}
    counts.update({r["ioc_type"]: r["n"] for r in rows})
    return counts


def _parent_domains(domain: str) -> list[str]:
    """'a.b.evil.example' -> ['a.b.evil.example', 'b.evil.example', 'evil.example']"""
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


def _row_to_ioc(row: sqlite3.Row) -> IOC:
    return IOC(row["ioc_type"], row["value"], row["source"], row["first_seen"])


def find_matches(
    conn: sqlite3.Connection,
    domains: Iterable[str] = (),
    ips: Iterable[str] = (),
    hashes: Iterable[str] = (),
) -> list[IOCMatch]:
    """
    Cross-reference values extracted from an APK against the IOC store.
    Invalid values are skipped (they cannot be IOCs), not raised, because
    APK strings are noisy.
    """
    matches: list[IOCMatch] = []

    for raw in domains:
        try:
            domain = normalize_domain(raw)
        except ValueError:
            continue
        for candidate in _parent_domains(domain):
            row = conn.execute(
                "SELECT * FROM iocs WHERE ioc_type = 'domain' AND value = ?", (candidate,)
            ).fetchone()
            if row:
                matches.append(IOCMatch(_row_to_ioc(row), observed=domain))

    for raw in ips:
        try:
            ip = normalize_ip(raw)
        except ValueError:
            continue
        row = conn.execute(
            "SELECT * FROM iocs WHERE ioc_type = 'ip' AND value = ?", (ip,)
        ).fetchone()
        if row:
            matches.append(IOCMatch(_row_to_ioc(row), observed=ip))

    for raw in hashes:
        try:
            h = normalize_hash(raw)
        except ValueError:
            continue
        row = conn.execute(
            "SELECT * FROM iocs WHERE ioc_type = 'hash' AND value = ?", (h,)
        ).fetchone()
        if row:
            matches.append(IOCMatch(_row_to_ioc(row), observed=h))

    # De-duplicate (same IOC can be reached via several observed strings)
    seen = set()
    unique: list[IOCMatch] = []
    for m in matches:
        key = (m.ioc.ioc_type, m.ioc.value, m.observed)
        if key not in seen:
            seen.add(key)
            unique.append(m)
    return unique
