"""Tests for the evidence PDF generator. Run: python -m unittest test_evidence_pdf -v"""

import hashlib
import os
import tempfile
import unittest

from evidence_pdf import CaseReport, IOCHit, build_evidence_pdf

SAMPLE_SHA = hashlib.sha256(b"dummy-apk").hexdigest()


def make_report(**overrides) -> CaseReport:
    base = dict(
        case_number="CC-TEST-0001/2026",
        fir_number="FIR-TEST-000",
        police_station="TEST STATION",
        investigating_officer="TEST OFFICER",
        apk_filename="sample.apk",
        apk_sha256=SAMPLE_SHA,
        apk_size_bytes=123456,
        risk_score=82,
        ai_briefing="Sentence one. Sentence two.",
        permissions=["android.permission.READ_SMS", "android.permission.RECORD_AUDIO"],
        suspicious_strings=["http://198.51.100.23/gate.php"],
        ioc_hits=[IOCHit("ip", "198.51.100.23", "198.51.100.23", "SAMPLE-DUMMY-DEV-ONLY")],
        analyst_notes="Dummy test notes.",
    )
    base.update(overrides)
    return CaseReport(**base)


class EvidencePDFTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _pdf_path(self, name="bundle.pdf"):
        return os.path.join(self.tmp, name)

    def test_generates_valid_pdf(self):
        out = build_evidence_pdf(make_report(), self._pdf_path())
        with open(out, "rb") as f:
            self.assertEqual(f.read(5), b"%PDF-")
        self.assertGreater(os.path.getsize(out), 2000)

    def test_empty_optional_sections_still_render(self):
        report = make_report(permissions=[], suspicious_strings=[], ioc_hits=[], analyst_notes="", ai_briefing="")
        out = build_evidence_pdf(report, self._pdf_path("empty.pdf"))
        self.assertTrue(os.path.exists(out))

    def test_logo_missing_path_does_not_crash(self):
        out = build_evidence_pdf(make_report(), self._pdf_path("nologo.pdf"), logo_path="/no/such/logo.png")
        self.assertTrue(os.path.exists(out))

    def test_risk_score_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            build_evidence_pdf(make_report(risk_score=101), self._pdf_path())
        with self.assertRaises(ValueError):
            build_evidence_pdf(make_report(risk_score=-1), self._pdf_path())

    def test_bad_sha256_rejected(self):
        with self.assertRaises(ValueError):
            build_evidence_pdf(make_report(apk_sha256="abc"), self._pdf_path())

    def test_case_number_required(self):
        with self.assertRaises(ValueError):
            build_evidence_pdf(make_report(case_number="  "), self._pdf_path())


if __name__ == "__main__":
    unittest.main()
