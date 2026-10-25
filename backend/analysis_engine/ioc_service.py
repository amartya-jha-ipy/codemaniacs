"""Local indicator-of-compromise (IOC) store and matching.

Compares indicators extracted from an APK against a local SQLite table. The table
ships **empty** -- no threat-intelligence records are fabricated. Operators load
their own trusted feed via :func:`add_ioc`; the test-suite loads clearly-marked
synthetic fixtures (``source="SYNTHETIC-TEST-FIXTURE"``) only.

Supported IOC types: ``ip`` (IPv4/IPv6), ``domain`` (hostname), ``sha256``.

Matching rules
--------------
* All values are normalised consistently before storage and before lookup.
* Lookups use parameterised SQL (no string interpolation) -> injection-safe.
* A hostname is never confused with a URL path; callers pass hostnames/IPs/hashes.
* "No match" is reported as *"No matching IOC found in the local database"* -- it is
  explicitly **not** a statement that the APK is safe.
"""
import ipaddress
import re

from . import store

VALID_TYPES = ("ip", "domain", "sha256")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$")


class IOCValidationError(ValueError):
    """Raised when an IOC value is malformed for its declared type."""


def initialize_ioc_database(db_path=None):
    """Create the (empty) IOC schema if absent. Idempotent."""
    store.init_schema(db_path)


def normalize_ioc(ioc_type, value):
    """Normalise and validate an IOC value for its type.

    Returns the canonical string. Raises :class:`IOCValidationError` on bad input.
    """
    if value is None:
        raise IOCValidationError("empty IOC value")
    raw = str(value).strip()
    if not raw:
        raise IOCValidationError("empty IOC value")

    if ioc_type == "ip":
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            raise IOCValidationError(f"invalid IP address: {raw!r}")

    if ioc_type == "domain":
        host = raw.lower().rstrip(".")
        if "://" in host or "/" in host:
            raise IOCValidationError(f"domain must be a hostname, not a URL: {raw!r}")
        host = host.split(":", 1)[0]  # strip any :port
        if not _DOMAIN_RE.match(host):
            raise IOCValidationError(f"invalid domain: {raw!r}")
        return host

    if ioc_type == "sha256":
        h = raw.lower()
        if not _SHA256_RE.match(h):
            raise IOCValidationError(f"invalid SHA-256 hash: {raw!r}")
        return h

    raise IOCValidationError(f"unsupported IOC type: {ioc_type!r}")


def add_ioc(ioc_type, value, source, metadata=None, db_path=None):
    """Insert or update a single IOC. Returns the normalised value.

    ``source`` (provenance) is required -- an IOC with no provenance is rejected,
    because an unattributed indicator is not usable as evidence. Re-inserting an
    existing ``(type, value)`` refreshes ``last_seen`` and metadata rather than
    duplicating the row.
    """
    if ioc_type not in VALID_TYPES:
        raise IOCValidationError(f"unsupported IOC type: {ioc_type!r}")
    if not source or not str(source).strip():
        raise IOCValidationError("IOC source/provenance is required")

    normalized = normalize_ioc(ioc_type, value)
    metadata = metadata or {}
    now = store.utc_now()
    threat_category = metadata.get("threat_category")
    confidence = metadata.get("confidence")
    first_seen = metadata.get("first_seen", now)
    last_seen = metadata.get("last_seen", now)

    store.init_schema(db_path)
    conn = store.get_conn(db_path)
    try:
        conn.execute(
            """
            INSERT INTO iocs (ioc_type, value, source, threat_category, confidence,
                              first_seen, last_seen, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ioc_type, value) DO UPDATE SET
                source=excluded.source,
                threat_category=excluded.threat_category,
                confidence=excluded.confidence,
                last_seen=excluded.last_seen
            """,
            (ioc_type, normalized, str(source).strip(), threat_category, confidence,
             first_seen, last_seen, now),
        )
        conn.commit()
    finally:
        conn.close()
    return normalized


def _lookup(ioc_type, normalized, db_path=None):
    conn = store.get_conn(db_path)
    try:
        return conn.execute(
            """SELECT ioc_type, value, source, threat_category, confidence,
                      first_seen, last_seen
               FROM iocs WHERE ioc_type = ? AND value = ?""",
            (ioc_type, normalized),
        ).fetchone()
    finally:
        conn.close()


def check_file_hash(sha256, db_path=None):
    """Return the matching IOC record for a file hash, or ``None``."""
    try:
        normalized = normalize_ioc("sha256", sha256)
    except IOCValidationError:
        return None
    row = _lookup("sha256", normalized, db_path)
    return dict(row) if row else None


def match_iocs(extracted_indicators, db_path=None):
    """Match extracted indicators against the local database.

    ``extracted_indicators`` is a dict that may contain ``ips``, ``domains`` and
    ``sha256`` (or ``hashes``). Returns a structured result separating confirmed
    exact matches from values that could not be checked (invalid/unsupported).
    """
    store.init_schema(db_path)

    def _as_list(value):
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return list(value)

    ips = _as_list(extracted_indicators.get("ips"))
    domains = _as_list(extracted_indicators.get("domains"))
    hashes = _as_list(extracted_indicators.get("sha256", extracted_indicators.get("hashes")))

    matches = []
    unchecked = []

    for ioc_type, values in (("ip", ips), ("domain", domains), ("sha256", hashes)):
        for value in values:
            try:
                normalized = normalize_ioc(ioc_type, value)
            except IOCValidationError as exc:
                unchecked.append({"type": ioc_type, "value": value, "reason": str(exc)})
                continue
            row = _lookup(ioc_type, normalized, db_path)
            if row:
                matches.append({
                    "type": ioc_type,
                    "value": normalized,
                    "match": "exact",
                    "source": row["source"],
                    "threat_category": row["threat_category"],
                    "confidence": row["confidence"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                })

    result = {
        "checked": {"ips": len(ips), "domains": len(domains), "hashes": len(hashes)},
        "matches": matches,
        "unchecked": unchecked,
        "match_count": len(matches),
    }
    if not matches:
        result["message"] = "No matching IOC found in the local database"
    return result


def count_iocs(db_path=None):
    """Return the number of stored IOCs (useful for provenance / snapshot refs)."""
    store.init_schema(db_path)
    conn = store.get_conn(db_path)
    try:
        return conn.execute("SELECT COUNT(*) AS n FROM iocs").fetchone()["n"]
    finally:
        conn.close()
