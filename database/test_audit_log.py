"""Tests for the tamper-evident audit log. Run: python -m unittest test_audit_log -v"""

import os
import sqlite3
import tempfile
import unittest

from audit_log import (
    GENESIS_HASH,
    append_entry,
    get_entries,
    init_audit_log,
    latest_hash,
    verify_chain,
)
from ioc_db import connect


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
        append_entry(self.conn, case, "INGESTION", {"file": "a.apk", "sha256": "ab" * 32})
        append_entry(self.conn, case, "STATIC_SCAN", {"permissions": ["READ_SMS"]})
        append_entry(self.conn, case, "RISK_GRADING", {"score": 82})

    def test_first_entry_links_to_genesis(self):
        e = append_entry(self.conn, "CASE-1", "INGESTION", {"x": 1})
        self.assertEqual(e.prev_hash, GENESIS_HASH)

    def test_entries_chain_together(self):
        self._add_pipeline()
        entries = get_entries(self.conn)
        self.assertEqual(len(entries), 3)
        for prev, cur in zip(entries, entries[1:]):
            self.assertEqual(cur.prev_hash, prev.entry_hash)

    def test_intact_chain_verifies(self):
        self._add_pipeline()
        self.assertEqual(verify_chain(self.conn), (True, None))

    def test_empty_log_verifies(self):
        self.assertEqual(verify_chain(self.conn), (True, None))
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
        # Simulate someone with file access bypassing the protection.
        self.conn.execute("DROP TRIGGER audit_log_no_update")
        self.conn.execute("UPDATE audit_log SET payload_json = '{\"score\":5}' WHERE id = 3")
        self.conn.commit()
        self.assertEqual(verify_chain(self.conn), (False, 3))

    def test_deletion_detected_after_trigger_dropped(self):
        self._add_pipeline()
        self.conn.execute("DROP TRIGGER audit_log_no_delete")
        self.conn.execute("DELETE FROM audit_log WHERE id = 2")
        self.conn.commit()
        ok, bad = verify_chain(self.conn)
        self.assertFalse(ok)
        self.assertEqual(bad, 3)  # entry 3 no longer links to entry 1

    def test_invalid_stage_rejected(self):
        with self.assertRaises(ValueError):
            append_entry(self.conn, "CASE-1", "MADE_UP_STAGE", {})

    def test_empty_case_id_rejected(self):
        with self.assertRaises(ValueError):
            append_entry(self.conn, "  ", "INGESTION", {})

    def test_non_serialisable_payload_rejected(self):
        with self.assertRaises(ValueError):
            append_entry(self.conn, "CASE-1", "INGESTION", {"bad": object()})

    def test_payload_is_canonical(self):
        a = append_entry(self.conn, "CASE-1", "INGESTION", {"b": 2, "a": 1})
        self.assertEqual(a.payload_json, '{"a":1,"b":2}')

    def test_cases_share_one_chain(self):
        append_entry(self.conn, "CASE-1", "INGESTION", {})
        append_entry(self.conn, "CASE-2", "INGESTION", {})
        self.assertEqual(verify_chain(self.conn), (True, None))
        self.assertEqual(len(get_entries(self.conn, "CASE-1")), 1)
        self.assertEqual(len(get_entries(self.conn, "CASE-2")), 1)

    def test_latest_hash_matches_last_entry(self):
        self._add_pipeline()
        self.assertEqual(latest_hash(self.conn), get_entries(self.conn)[-1].entry_hash)


if __name__ == "__main__":
    unittest.main()
