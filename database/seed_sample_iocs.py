"""
Load DUMMY sample IOCs for development and testing.

All values use reserved documentation ranges and reserved TLDs
(RFC 5737 IPs, RFC 2606 .example names). They are NOT real indicators.
Replace with the agency's real IOC feed before any real case use.

Usage:
    python seed_sample_iocs.py [path/to/iocs.sqlite]
"""

import hashlib
import sys
from pathlib import Path

from ioc_db import add_many, connect, count_iocs, init_db

DEFAULT_DB = Path(__file__).resolve().parent / "iocs.sqlite"

SAMPLE_SOURCE = "SAMPLE-DUMMY-DEV-ONLY"

SAMPLE_IOCS = [
    ("domain", "sample-c2.example", SAMPLE_SOURCE),
    ("domain", "update-cdn.example", SAMPLE_SOURCE),
    ("domain", "payload-drop.example", SAMPLE_SOURCE),
    ("ip", "198.51.100.23", SAMPLE_SOURCE),
    ("ip", "203.0.113.45", SAMPLE_SOURCE),
    ("hash", hashlib.sha256(b"sample-malicious-apk-1").hexdigest(), SAMPLE_SOURCE),
    ("hash", hashlib.sha256(b"sample-malicious-apk-2").hexdigest(), SAMPLE_SOURCE),
]


def main() -> None:
    db_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DB
    conn = connect(db_path)
    init_db(conn)
    inserted = add_many(conn, SAMPLE_IOCS)
    print(f"Inserted {inserted} new sample IOCs into {db_path}")
    print("Counts by type:", count_iocs(conn))
    conn.close()


if __name__ == "__main__":
    main()
