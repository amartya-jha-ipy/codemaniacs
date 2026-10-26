"""
ANVESH v2.0 - Unit Tests for Static APK Parser
===================================================
Module: tests/test_parser.py
Author: Developer 3 — AI/ML & Static Parsing Lead

Focused unit tests utilizing synthetic in-memory/temporary test fixtures.
Does not require or execute any real malware APK specimens.
Covers:
- Missing files and empty inputs
- Invalid APK formats and corrupted archives
- Missing AndroidManifest.xml
- Empty and malformed manifests
- Arbitrary binary data rejection (never treated as confirmed permissions)
- Truncated AXML structures
- Missing Androguard fallback behavior
- Mocked Androguard engine execution
- Strict integrity guarantee (zero invented permissions/strings on failure)
"""

import io
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zipfile

from backend.parser import (
    calculate_sha256,
    is_androguard_available,
    parse_apk,
    StaticAPKParser,
)


def _build_synthetic_axml(package_name: str, permissions: list[str]) -> bytes:
    """Construct a well-formed Android Binary XML (AXML) with a valid StringPool."""
    strings = ["manifest", "uses-permission", "name", package_name] + permissions
    encoded_strings = []
    offsets = []
    cur_offset = 0

    for s in strings:
        enc = s.encode("utf-16-le")
        # uint16 character length, followed by utf-16-le bytes and null terminator (2 bytes)
        s_data = struct.pack("<H", len(s)) + enc + b"\x00\x00"
        offsets.append(cur_offset)
        cur_offset += len(s_data)
        encoded_strings.append(s_data)

    str_data_bytes = b"".join(encoded_strings)
    num_strings = len(strings)
    sp_header_size = 28
    offsets_len = num_strings * 4
    strings_start = sp_header_size + offsets_len
    sp_chunk_size = strings_start + len(str_data_bytes)

    # StringPool header: chunk type = 0x0001, header_size = 28, flags = 0 (UTF-16)
    sp_header = struct.pack(
        "<HHIIIIII",
        0x0001,
        sp_header_size,
        sp_chunk_size,
        num_strings,
        0,  # style count
        0,  # flags (UTF-16)
        strings_start,
        0,  # styles start
    )
    offsets_data = b"".join(struct.pack("<I", off) for off in offsets)
    sp_chunk = sp_header + offsets_data + str_data_bytes

    # AXML file header: type = 0x0003, header_size = 8
    file_header = struct.pack("<HHI", 0x0003, 8, 8 + len(sp_chunk))
    return file_header + sp_chunk


def _build_synthetic_apk(
    permissions: list[str] | None = None,
    dex_strings: list[str] | None = None,
    include_manifest: bool = True,
    package_name: str = "org.biharpolice.cyberinvestigation.sample",
    manifest_bytes: bytes | None = None,
) -> bytes:
    """Helper to assemble a synthetic APK zip archive in memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        if include_manifest:
            if manifest_bytes is not None:
                zf.writestr("AndroidManifest.xml", manifest_bytes)
            else:
                perms = permissions or []
                axml_data = _build_synthetic_axml(package_name, perms)
                zf.writestr("AndroidManifest.xml", axml_data)

        # Build synthetic classes.dex with valid DEX header and string pool
        if dex_strings is not None:
            dex_buf = bytearray(1024)
            dex_buf[0:8] = b"dex\n035\x00"

            string_count = len(dex_strings)
            string_ids_off = 0x70
            struct.pack_into("<II", dex_buf, 0x38, string_count, string_ids_off)

            data_cursor = string_ids_off + (string_count * 4) + 16
            for i, s in enumerate(dex_strings):
                struct.pack_into("<I", dex_buf, string_ids_off + (i * 4), data_cursor)
                encoded = s.encode("utf-8")
                # ULEB128 length followed by null-terminated string
                dex_buf[data_cursor] = len(encoded)
                data_cursor += 1
                dex_buf[data_cursor : data_cursor + len(encoded)] = encoded
                data_cursor += len(encoded)
                dex_buf[data_cursor] = 0
                data_cursor += 1

            zf.writestr("classes.dex", bytes(dex_buf))

    return buf.getvalue()


class TestStaticAPKParser(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parse_valid_synthetic_axml_apk(self):
        """Test static parsing of a well-formed synthetic APK containing AXML binary."""
        expected_perms = [
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.INTERNET",
            "android.permission.RECEIVE_SMS",
        ]
        sample_dex_strings = [
            "HttpEndpointConnection",
            "SmsBroadcastReceiver",
            "CryptoKeyVault",
        ]
        apk_bytes = _build_synthetic_apk(
            permissions=expected_perms,
            dex_strings=sample_dex_strings,
        )

        apk_file = self.temp_path / "specimen_sample.apk"
        apk_file.write_bytes(apk_bytes)

        res = parse_apk(apk_file, max_strings=50)

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["filename"], "specimen_sample.apk")
        self.assertIsNone(res["error_message"])
        self.assertIsNotNone(res["sha256"])
        self.assertEqual(len(res["sha256"]), 64)
        self.assertGreater(res["file_size_bytes"], 0)
        self.assertEqual(res["package_name"], "org.biharpolice.cyberinvestigation.sample")

        for perm in expected_perms:
            self.assertIn(perm, res["requested_permissions"])

        for s in sample_dex_strings:
            self.assertIn(s, res["extracted_strings"])

    def test_parse_plaintext_xml_synthetic_apk(self):
        """Test parsing of an APK containing an uncompiled plaintext XML manifest."""
        xml_content = (
            b'<?xml version="1.0" encoding="utf-8"?>\n'
            b'<manifest package="org.biharpolice.plaintext">\n'
            b'    <uses-permission android:name="android.permission.READ_PHONE_STATE" />\n'
            b'    <uses-permission android:name="android.permission.SEND_SMS" />\n'
            b'</manifest>'
        )
        apk_bytes = _build_synthetic_apk(
            manifest_bytes=xml_content,
            dex_strings=["TestPlaintextString"],
        )
        apk_file = self.temp_path / "plaintext_manifest.apk"
        apk_file.write_bytes(apk_bytes)

        res = parse_apk(apk_file)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["package_name"], "org.biharpolice.plaintext")
        self.assertIn("android.permission.READ_PHONE_STATE", res["requested_permissions"])
        self.assertIn("android.permission.SEND_SMS", res["requested_permissions"])
        self.assertIn("TestPlaintextString", res["extracted_strings"])

    def test_max_strings_limit(self):
        """Verify that max_strings parameter strictly limits returned strings."""
        sample_dex_strings = [f"IdentString_{i}" for i in range(20)]
        apk_bytes = _build_synthetic_apk(
            permissions=["android.permission.INTERNET"],
            dex_strings=sample_dex_strings,
        )

        apk_file = self.temp_path / "capped_strings.apk"
        apk_file.write_bytes(apk_bytes)

        res = parse_apk(apk_file, max_strings=5)
        self.assertEqual(res["status"], "success")
        self.assertLessEqual(len(res["extracted_strings"]), 5)

        res_zero = parse_apk(apk_file, max_strings=0)
        self.assertEqual(res_zero["status"], "success")
        self.assertEqual(len(res_zero["extracted_strings"]), 0)

    def test_missing_file(self):
        """Verify graceful error reporting when the APK file does not exist."""
        non_existent = self.temp_path / "ghost_file.apk"
        res = parse_apk(non_existent)

        self.assertEqual(res["status"], "error")
        self.assertIn("File does not exist", res["error_message"])
        self.assertEqual(res["requested_permissions"], [])
        self.assertEqual(res["extracted_strings"], [])
        self.assertIsNone(res["sha256"])

    def test_empty_file(self):
        """Verify handling of 0-byte empty files."""
        empty_file = self.temp_path / "empty.apk"
        empty_file.write_bytes(b"")

        res = parse_apk(empty_file)
        self.assertEqual(res["status"], "error")
        self.assertIn("File is empty", res["error_message"])
        self.assertEqual(res["requested_permissions"], [])
        self.assertEqual(res["extracted_strings"], [])

    def test_invalid_zip_format(self):
        """Verify handling of corrupted or non-zip file masquerading as APK."""
        junk_file = self.temp_path / "corrupt.apk"
        junk_file.write_bytes(b"THIS IS NOT A ZIP ARCHIVE AND NOT AN APK SPECIMEN")

        res = parse_apk(junk_file)
        self.assertEqual(res["status"], "error")
        self.assertIn("Invalid file format", res["error_message"])
        self.assertEqual(res["requested_permissions"], [])
        self.assertEqual(res["extracted_strings"], [])

    def test_corrupt_zip_archive(self):
        """Verify handling of truncated/bad zip archive."""
        apk_bytes = _build_synthetic_apk(permissions=["android.permission.INTERNET"])
        corrupted_bytes = apk_bytes[: len(apk_bytes) // 2]
        bad_zip = self.temp_path / "truncated.apk"
        bad_zip.write_bytes(corrupted_bytes)

        res = parse_apk(bad_zip)
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["requested_permissions"], [])
        self.assertEqual(res["extracted_strings"], [])

    def test_zip_missing_manifest(self):
        """Verify handling of a zip archive lacking AndroidManifest.xml."""
        apk_bytes = _build_synthetic_apk(include_manifest=False)
        invalid_apk = self.temp_path / "no_manifest.apk"
        invalid_apk.write_bytes(apk_bytes)

        res = parse_apk(invalid_apk)
        self.assertEqual(res["status"], "error")
        self.assertIn("AndroidManifest.xml not found", res["error_message"])
        self.assertEqual(res["requested_permissions"], [])
        self.assertEqual(res["extracted_strings"], [])

    def test_empty_manifest_in_apk(self):
        """Verify handling of an APK whose AndroidManifest.xml is 0 bytes."""
        apk_bytes = _build_synthetic_apk(manifest_bytes=b"")
        empty_manifest_apk = self.temp_path / "empty_manifest.apk"
        empty_manifest_apk.write_bytes(apk_bytes)

        res = parse_apk(empty_manifest_apk)
        self.assertEqual(res["status"], "error")
        self.assertIn("empty or too short", res["error_message"])
        self.assertEqual(res["requested_permissions"], [])
        self.assertEqual(res["extracted_strings"], [])

    def test_arbitrary_binary_manifest_rejected(self):
        """
        Verify that arbitrary binary noise in AndroidManifest.xml is rejected,
        even if it contains sequences resembling permission strings.
        Arbitrary binary data MUST NEVER be treated as confirmed manifest permissions.
        """
        fake_binary_noise = (
            b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"
            b"ARBITRARY_BINARY_NOISE_CONTAINING_"
            b"android.permission.RECEIVE_SMS_AND_MORE_JUNK_BYTES"
            b"\x00\x01\x02\x03\x04\x05\x06\x07"
        )
        apk_bytes = _build_synthetic_apk(manifest_bytes=fake_binary_noise)
        noise_apk = self.temp_path / "arbitrary_binary_manifest.apk"
        noise_apk.write_bytes(apk_bytes)

        res = parse_apk(noise_apk)
        self.assertEqual(res["status"], "error")
        self.assertIn("neither valid Android Binary XML nor XML text", res["error_message"])
        self.assertEqual(res["requested_permissions"], [])
        self.assertEqual(res["extracted_strings"], [])

    def test_truncated_axml_manifest_rejected(self):
        """Verify that truncated AXML header is rejected gracefully."""
        truncated_axml = b"\x03\x00\x08\x00\x10\x00\x00\x00\x01\x00"  # 10 bytes, truncated
        apk_bytes = _build_synthetic_apk(manifest_bytes=truncated_axml)
        trunc_apk = self.temp_path / "truncated_axml.apk"
        trunc_apk.write_bytes(apk_bytes)

        res = parse_apk(trunc_apk)
        self.assertEqual(res["status"], "error")
        self.assertIn("Malformed APK", res["error_message"])
        self.assertEqual(res["requested_permissions"], [])
        self.assertEqual(res["extracted_strings"], [])

    def test_directory_as_target(self):
        """Verify rejection when a directory path is passed instead of a file."""
        res = parse_apk(self.temp_path)
        self.assertEqual(res["status"], "error")
        self.assertIn("directory", res["error_message"])
        self.assertEqual(res["requested_permissions"], [])
        self.assertEqual(res["extracted_strings"], [])

    def test_empty_or_none_path(self):
        """Verify rejection of empty or None paths."""
        res_none = parse_apk("")
        self.assertEqual(res_none["status"], "error")
        self.assertIn("must not be empty", res_none["error_message"])
        self.assertEqual(res_none["requested_permissions"], [])
        self.assertEqual(res_none["extracted_strings"], [])

    def test_sha256_calculation(self):
        """Verify SHA-256 calculation accuracy."""
        test_file = self.temp_path / "hash_check.apk"
        content = b"Bihar Police Cybercrime Specimen Test 2026"
        test_file.write_bytes(content)

        computed = calculate_sha256(test_file)
        import hashlib

        expected = hashlib.sha256(content).hexdigest()
        self.assertEqual(computed, expected)

    def test_oop_wrapper(self):
        """Verify StaticAPKParser OOP wrapper."""
        apk_bytes = _build_synthetic_apk(
            permissions=["android.permission.INTERNET"],
            dex_strings=["TestString"],
        )
        apk_file = self.temp_path / "oop_test.apk"
        apk_file.write_bytes(apk_bytes)

        parser = StaticAPKParser(default_max_strings=10)
        res = parser.parse(apk_file)
        self.assertEqual(res["status"], "success")
        self.assertIn("android.permission.INTERNET", res["requested_permissions"])

    def test_missing_androguard_fallback(self):
        """
        Verify that when Androguard is absent (ANDROGUARD_AVAILABLE=False),
        the parser cleanly executes using the built-in fallback engine.
        """
        apk_bytes = _build_synthetic_apk(
            permissions=["android.permission.ACCESS_NETWORK_STATE"],
            dex_strings=["FallbackString"],
        )
        apk_file = self.temp_path / "fallback_engine.apk"
        apk_file.write_bytes(apk_bytes)

        with patch("backend.parser.ANDROGUARD_AVAILABLE", False), patch(
            "backend.parser.AndroguardAPK", None
        ):
            res = parse_apk(apk_file)
            self.assertEqual(res["status"], "success")
            self.assertEqual(res["engine"], "static_fallback")
            self.assertIn("android.permission.ACCESS_NETWORK_STATE", res["requested_permissions"])
            self.assertIn("FallbackString", res["extracted_strings"])

    def test_androguard_mock_engine(self):
        """Verify that when Androguard is present, the parser routes to it properly."""
        apk_bytes = _build_synthetic_apk(permissions=["android.permission.CAMERA"])
        apk_file = self.temp_path / "mock_androguard.apk"
        apk_file.write_bytes(apk_bytes)

        mock_apk_instance = MagicMock()
        mock_apk_instance.get_permissions.return_value = ["android.permission.CAMERA"]
        mock_apk_instance.get_package.return_value = "com.mock.androguard.app"

        with patch("backend.parser.ANDROGUARD_AVAILABLE", True), patch(
            "backend.parser.AndroguardAPK", return_value=mock_apk_instance
        ):
            res = parse_apk(apk_file)
            self.assertEqual(res["status"], "success")
            self.assertEqual(res["engine"], "androguard")
            self.assertEqual(res["requested_permissions"], ["android.permission.CAMERA"])
            self.assertEqual(res["package_name"], "com.mock.androguard.app")

    def test_never_invent_permissions_or_strings_on_failure(self):
        """
        Comprehensive property test: Verify that across all failure cases,
        requested_permissions and extracted_strings are strictly empty lists.
        """
        cases = [
            self.temp_path / "non_existent.apk",
            self.temp_path / "empty.apk",
            self.temp_path / "corrupt.apk",
            self.temp_path / "no_manifest.apk",
            self.temp_path / "arbitrary_binary.apk",
        ]

        # Setup files
        (self.temp_path / "empty.apk").write_bytes(b"")
        (self.temp_path / "corrupt.apk").write_bytes(b"NOT A ZIP")
        (self.temp_path / "no_manifest.apk").write_bytes(_build_synthetic_apk(include_manifest=False))
        (self.temp_path / "arbitrary_binary.apk").write_bytes(
            _build_synthetic_apk(manifest_bytes=b"RANDOM_BYTES_NO_AXML_HEADER")
        )

        for case_path in cases:
            res = parse_apk(case_path)
            self.assertEqual(res["status"], "error", f"Failed for {case_path.name}")
            self.assertEqual(
                res["requested_permissions"],
                [],
                f"Invented permissions on failure for {case_path.name}: {res['requested_permissions']}",
            )
            self.assertEqual(
                res["extracted_strings"],
                [],
                f"Invented strings on failure for {case_path.name}: {res['extracted_strings']}",
            )


if __name__ == "__main__":
    unittest.main()
