"""Append-only audit trail for analysis and report events.

Records events (analysis created/completed, IOC snapshot reference, report
generated, report hash, ...) into the ``audit_events`` table. Rows are only ever
inserted -- there is no update/delete path in this module.

Integrity note (documented deliberately): the recorded SHA-256 hashes let a
reviewer verify that a stored artefact has not changed since it was recorded. They
do **not**, on their own, prove authenticity, lawful acquisition, or a complete
chain of custody. Those require controls outside this software.
"""
import json

from . import config, store


def record_event(event_type, analysis_id=None, sha256=None, details=None, db_path=None):
    """Append one audit event. Returns the new event id."""
    store.init_schema(db_path)
    conn = store.get_conn(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO audit_events (event_type, analysis_id, sha256, details,
                                      tool_version, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (event_type, analysis_id, sha256,
             json.dumps(details) if details is not None else None,
             config.TOOL_VERSION, store.utc_now()),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_events(analysis_id=None, db_path=None):
    """Return audit events, optionally filtered to one analysis, oldest first."""
    store.init_schema(db_path)
    conn = store.get_conn(db_path)
    try:
        if analysis_id is None:
            rows = conn.execute(
                "SELECT * FROM audit_events ORDER BY id ASC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_events WHERE analysis_id = ? ORDER BY id ASC",
                (analysis_id,),
            ).fetchall()
    finally:
        conn.close()
    events = []
    for r in rows:
        event = dict(r)
        if event.get("details"):
            try:
                event["details"] = json.loads(event["details"])
            except (ValueError, TypeError):
                pass
        events.append(event)
    return events
