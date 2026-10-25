"""Tests for the IOC cross-referencing store. Run: python -m unittest test_ioc_db -v"""

import hashlib
import os
import tempfile
import unittest

from ioc_db import (
    add_ioc,
    add_many,
    connect,
    count_iocs,
    find_matches,
    init_db,
)

SAMPLE_HASH = hashlib.sha256(b"test-apk").hexdigest()


class IOCDatabaseTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        self.conn = connect(self.path)
        init_db(self.conn)
        add_many(
            self.conn,
            [
                ("domain", "evil-c2.example", "TEST"),
                ("ip", "198.51.100.23", "TEST"),
                ("hash", SAMPLE_HASH, "TEST"),
            ],
        )

    def tearDown(self):
        self.conn.close()
        os.remove(self.path)

    def test_counts(self):
        self.assertEqual(count_iocs(self.conn), {"domain": 1, "ip": 1, "hash": 1})

    def test_duplicate_is_ignored(self):
        self.assertFalse(add_ioc(self.conn, "ip", "198.51.100.23", "TEST"))
        self.assertEqual(count_iocs(self.conn)["ip"], 1)

    def test_exact_domain_match_case_insensitive(self):
        matches = find_matches(self.conn, domains=["EVIL-C2.example."])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].ioc.value, "evil-c2.example")

    def test_subdomain_matches_parent_ioc(self):
        matches = find_matches(self.conn, domains=["api.evil-c2.example"])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].observed, "api.evil-c2.example")

    def test_unrelated_domain_does_not_match(self):
        self.assertEqual(find_matches(self.conn, domains=["notevil-c2.example"]), [])
        self.assertEqual(find_matches(self.conn, domains=["google.com"]), [])

    def test_ip_match(self):
        matches = find_matches(self.conn, ips=["198.51.100.23", "10.0.0.1"])
        self.assertEqual([m.ioc.value for m in matches], ["198.51.100.23"])

    def test_hash_match_case_insensitive(self):
        matches = find_matches(self.conn, hashes=[SAMPLE_HASH.upper()])
        self.assertEqual(len(matches), 1)

    def test_invalid_apk_strings_are_skipped_not_raised(self):
        matches = find_matches(
            self.conn,
            domains=["not a domain", "", "a..b"],
            ips=["999.1.1.1", "hello"],
            hashes=["zzz"],
        )
        self.assertEqual(matches, [])

    def test_invalid_ioc_rejected_on_insert(self):
        with self.assertRaises(ValueError):
            add_ioc(self.conn, "ip", "not-an-ip", "TEST")
        with self.assertRaises(ValueError):
            add_ioc(self.conn, "hash", "1234", "TEST")
        with self.assertRaises(ValueError):
            add_ioc(self.conn, "domain", "bad domain", "TEST")

    def test_source_required_for_chain_of_custody(self):
        with self.assertRaises(ValueError):
            add_ioc(self.conn, "ip", "203.0.113.45", "   ")

    def test_unknown_type_rejected(self):
        with self.assertRaises(ValueError):
            add_ioc(self.conn, "url", "http://x.example", "TEST")

    def test_duplicate_matches_collapsed(self):
        matches = find_matches(
            self.conn,
            domains=["evil-c2.example", "api.evil-c2.example", "evil-c2.example"],
        )
        observed = sorted(m.observed for m in matches)
        self.assertEqual(observed, ["api.evil-c2.example", "evil-c2.example"])


if __name__ == "__main__":
    unittest.main()
