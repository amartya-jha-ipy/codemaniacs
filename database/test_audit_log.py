"""Tests for the HMAC-keyed audit log. Run: python -m unittest test_audit_log -v"""

import hashlib
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from audit_log import (
    GENESIS_HASH,
    KEY_ENV_VAR,
    append_entry,
    get_entries,
    init_audit_log,
    latest_hash,
    verify_chain,
)
from ioc_db import connect

KEY = "k" * 32  # test key only, never use a key like this for real cases
WRONG_KEY = "x" * 32


class AuditLogTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        self.conn = connect(self.path)
        init_audit_log(self.conn)

    def tearDown(self):
        self.conn.close()
        os.remove(self.path)

    def _add_pipeline(self, case="CASE-1"):
        append_entry(self.conn, KEY, case, "INGESTION", {"file": "a.apk", "sha256": "ab" * 32})
        append_entry(self.conn, KEY, case, "STATIC_SCAN", {"permissions": ["READ_SMS"]})
        append_entry(self.conn, KEY, case, "RISK_GRADING", {"score": 82})

    def test_first_entry_links_to_genesis(self):
        e = append_entry(self.conn, KEY, "CASE-1", "INGESTION", {"x": 1})
        self.assertEqual(e.prev_hash, GENESIS_HASH)

    def test_entries_chain_together(self):
        self._add_pipeline()
        entries = get_entries(self.conn)
        self.assertEqual(len(entries), 3)
        for prev, cur in zip(entries, entries[1:]):
            self.assertEqual(cur.prev_hash, prev.entry_hash)

    def test_intact_chain_verifies(self):
        self._add_pipeline()
        self.assertEqual(verify_chain(self.conn, KEY), (True, None))

    def test_empty_log_verifies(self):
        self.assertEqual(verify_chain(self.conn, KEY), (True, None))
        self.assertEqual(latest_hash(self.conn), GENESIS_HASH)

    def test_update_is_blocked_by_trigger(self):
        self._add_pipeline()
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("UPDATE audit_log SET stage = 'INGESTION' WHERE id = 2")

    def test_delete_is_blocked_by_trigger(self):
        self._add_pipeline()
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("DELETE FROM audit_log WHERE id = 1")

    def test_tamper_detected_after_trigger_dropped(self):
        self._add_pipeline()
        self.conn.execute("DROP TRIGGER audit_log_no_update")
        self.conn.execute("UPDATE audit_log SET payload_json = '{\"score\":5}' WHERE id = 3")
        self.conn.commit()
        self.assertEqual(verify_chain(self.conn, KEY), (False, 3))

    def test_deletion_detected_after_trigger_dropped(self):
        self._add_pipeline()
        self.conn.execute("DROP TRIGGER audit_log_no_delete")
        self.conn.execute("DELETE FROM audit_log WHERE id = 2")
        self.conn.commit()
        ok, bad = verify_chain(self.conn, KEY)
        self.assertFalse(ok)
        self.assertEqual(bad, 3)  # entry 3 no longer links to entry 1

    def test_attacker_without_key_cannot_forge_chain(self):
        """Attacker drops triggers, edits an entry, and recomputes plain SHA-256 links."""
        self._add_pipeline()
        self.conn.execute("DROP TRIGGER audit_log_no_update")
        rows = get_entries(self.conn)
        forged_prev = GENESIS_HASH
        for e in rows:
            payload = e.payload_json.replace("82", "5") if e.id == 3 else e.payload_json
            material = "|".join([forged_prev, e.ts, e.case_id, e.stage, payload])
            forged = hashlib.sha256(material.encode()).hexdigest()
            self.conn.execute(
                "UPDATE audit_log SET payload_json = ?, prev_hash = ?, entry_hash = ? WHERE id = ?",
                (payload, forged_prev, forged, e.id),
            )
            forged_prev = forged
        self.conn.commit()
        ok, bad = verify_chain(self.conn, KEY)
        self.assertFalse(ok)
        self.assertEqual(bad, 1)

    def test_rewrite_with_wrong_key_fails_verification(self):
        self._add_pipeline()
        # Attacker drops the triggers, wipes the log, and rebuilds it with their own key.
        self.conn.execute("DROP TRIGGER audit_log_no_update")
        self.conn.execute("DROP TRIGGER audit_log_no_delete")
        self.conn.execute("DELETE FROM audit_log")
        self.conn.commit()
        forged = append_entry(self.conn, WRONG_KEY, "CASE-1", "INGESTION", {"file": "fake.apk"})
        # IDs are not reused after DELETE (AUTOINCREMENT), so the forged entry keeps its new id.
        self.assertEqual(verify_chain(self.conn, KEY), (False, forged.id))

    def test_wrong_key_does_not_verify(self):
        self._add_pipeline()
        self.assertEqual(verify_chain(self.conn, WRONG_KEY), (False, 1))

    def test_key_read_from_environment(self):
        with mock.patch.dict(os.environ, {KEY_ENV_VAR: KEY}):
            append_entry(self.conn, None, "CASE-1", "INGESTION", {})
            self.assertEqual(verify_chain(self.conn, None), (True, None))

    def test_missing_key_rejected(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                append_entry(self.conn, None, "CASE-1", "INGESTION", {})

    def test_short_key_rejected(self):
        with self.assertRaises(ValueError):
            append_entry(self.conn, "short", "CASE-1", "INGESTION", {})

    def test_invalid_stage_rejected(self):
        with self.assertRaises(ValueError):
            append_entry(self.conn, KEY, "CASE-1", "MADE_UP_STAGE", {})

    def test_empty_case_id_rejected(self):
        with self.assertRaises(ValueError):
            append_entry(self.conn, KEY, "  ", "INGESTION", {})

    def test_non_serialisable_payload_rejected(self):
        with self.assertRaises(ValueError):
            append_entry(self.conn, KEY, "CASE-1", "INGESTION", {"bad": object()})

    def test_payload_is_canonical(self):
        a = append_entry(self.conn, KEY, "CASE-1", "INGESTION", {"b": 2, "a": 1})
        self.assertEqual(a.payload_json, '{"a":1,"b":2}')

    def test_cases_share_one_chain(self):
        append_entry(self.conn, KEY, "CASE-1", "INGESTION", {})
        append_entry(self.conn, KEY, "CASE-2", "INGESTION", {})
        self.assertEqual(verify_chain(self.conn, KEY), (True, None))
        self.assertEqual(len(get_entries(self.conn, "CASE-1")), 1)
        self.assertEqual(len(get_entries(self.conn, "CASE-2")), 1)

    def test_latest_hash_matches_last_entry_and_needs_no_key(self):
        self._add_pipeline()
        self.assertEqual(latest_hash(self.conn), get_entries(self.conn)[-1].entry_hash)


if __name__ == "__main__":
    unittest.main()
