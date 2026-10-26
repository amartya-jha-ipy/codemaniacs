"""
ANVESH v2.0 - Static Android APK Parser
=============================================
Module: backend/parser.py
Lead: Developer 3 — AI/ML & Static Parsing Lead
Branch: feature/ml-parser-scoring

Purely static Android APK inspection module.
Extracts AndroidManifest permissions, package metadata, and embedded strings
from APK archives without executing code or invoking dynamic sandboxing.

Features:
- Primary engine: Androguard (if installed in environment)
- Fallback engine: Built-in static zip & binary AXML / DEX string parser
- Strict validation: Rejects arbitrary binary data and malformed manifests
- Integrity guarantee: Never invents permissions or strings on parse failure
- Output format: Consistent structured Python dictionary
"""

import hashlib
import logging
import os
from pathlib import Path
import re
import struct
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import zipfile

logger = logging.getLogger(__name__)

# Check for Androguard availability
ANDROGUARD_AVAILABLE = False
AndroguardAPK = None

try:
    from androguard.core.bytecodes.apk import APK as _APK1
    AndroguardAPK = _APK1
    ANDROGUARD_AVAILABLE = True
except ImportError:
    try:
        from androguard.core.apk import APK as _APK2
        AndroguardAPK = _APK2
        ANDROGUARD_AVAILABLE = True
    except ImportError:
        ANDROGUARD_AVAILABLE = False
        AndroguardAPK = None

# Regex pattern for Android permissions (both standard android.permission.* and custom names)
PERMISSION_PATTERN = re.compile(
    r"^(?:android\.permission\.[A-Za-z0-9_]+|"
    r"[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+\.(?:permission|permissions)\.[A-Za-z0-9_]+|"
    r"com\.google\.android\.[a-zA-Z0-9_.]+\.permission\.[A-Za-z0-9_]+)$",
    re.IGNORECASE,
)

# Regex pattern for potential package name (reverse-domain notation)
PACKAGE_PATTERN = re.compile(
    r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
    re.IGNORECASE,
)


def is_androguard_available() -> bool:
    """Return whether Androguard is importable in the current environment."""
    return ANDROGUARD_AVAILABLE


def calculate_sha256(file_path: Union[str, Path]) -> str:
    """Compute SHA-256 hash of a file safely in 64KB chunks."""
    path = Path(file_path)
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def _read_uleb128(data: bytes, offset: int) -> Tuple[int, int]:
    """
    Read unsigned LEB128 encoded integer from byte array.
    Returns (value, new_offset).
    """
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result, offset


def _extract_dex_strings(dex_bytes: bytes, max_strings: int) -> List[str]:
    """
    Parse string_ids table from Dalvik Executable (DEX) header.
    Returns decoded printable strings up to max_strings.
    """
    if len(dex_bytes) < 0x70 or not dex_bytes.startswith(b"dex\n"):
        return []

    try:
        string_ids_size, string_ids_off = struct.unpack_from("<II", dex_bytes, 0x38)
    except struct.error:
        return []

    strings: List[str] = []
    seen: Set[str] = set()
    limit = min(string_ids_size, max_strings * 2)

    for i in range(limit):
        if len(strings) >= max_strings:
            break

        offset = string_ids_off + i * 4
        if offset + 4 > len(dex_bytes):
            break

        try:
            (str_data_off,) = struct.unpack_from("<I", dex_bytes, offset)
            if str_data_off >= len(dex_bytes):
                continue

            _, cur = _read_uleb128(dex_bytes, str_data_off)
            end = dex_bytes.find(b"\x00", cur)
            if end != -1:
                raw_str = dex_bytes[cur:end]
                decoded = raw_str.decode("utf-8", errors="ignore").strip()
                if len(decoded) >= 3 and decoded.isprintable() and decoded not in seen:
                    seen.add(decoded)
                    strings.append(decoded)
        except Exception:
            continue

    return strings


def _extract_printable_strings(raw_bytes: bytes, min_len: int = 4, max_count: int = 100) -> List[str]:
    """Extract printable ASCII strings as a fallback for non-standard binaries."""
    pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    matches = pattern.finditer(raw_bytes)
    result: List[str] = []
    seen: Set[str] = set()

    for match in matches:
        if len(result) >= max_count:
            break
        try:
            text = match.group(0).decode("ascii").strip()
            if text and text not in seen:
                seen.add(text)
                result.append(text)
        except UnicodeDecodeError:
            continue

    return result


def _parse_axml_string_pool(data: bytes) -> Tuple[Optional[List[str]], Optional[str]]:
    """
    Parse the StringPool chunk from Android Binary XML (AXML).
    Returns (strings_list, error_message).
    Validates the AXML header and StringPool structure. Rejects arbitrary binary data.
    """
    if len(data) < 8:
        return None, "AXML data is truncated (less than 8 bytes)"

    try:
        res_type, header_size, file_size = struct.unpack_from("<HHI", data, 0)
    except struct.error:
        return None, "Corrupt AXML header structure"

    # Android Binary XML magic number: type = 0x0003 (RES_XML_TYPE), header_size = 8
    if res_type != 0x0003 or header_size != 8:
        return None, "Not an Android Binary XML file (header magic mismatch)"

    sp_off = header_size
    if sp_off + 28 > len(data):
        return None, "AXML StringPool chunk header is truncated"

    try:
        sp_type, sp_header_size, sp_chunk_size, string_count, style_count, flags, strings_start, styles_start = (
            struct.unpack_from("<HHIIIIII", data, sp_off)
        )
    except struct.error:
        return None, "Corrupt AXML StringPool header"

    if sp_type != 0x0001:  # RES_STRING_POOL_TYPE
        return None, "AXML StringPool chunk type mismatch"

    is_utf8 = bool(flags & 0x0100)
    offsets_start = sp_off + sp_header_size
    if offsets_start + (string_count * 4) > len(data):
        return None, "AXML StringPool offset table is truncated"

    pool_data_start = sp_off + strings_start
    strings: List[str] = []

    for i in range(string_count):
        (s_off,) = struct.unpack_from("<I", data, offsets_start + i * 4)
        target_off = pool_data_start + s_off
        if target_off >= len(data):
            continue

        try:
            if is_utf8:
                cur = target_off
                while cur < len(data) and (data[cur] & 0x80):
                    cur += 1
                cur += 1
                b_len = 0
                shift = 0
                while cur < len(data):
                    b = data[cur]
                    cur += 1
                    b_len |= (b & 0x7F) << shift
                    if not (b & 0x80):
                        break
                    shift += 7
                s_bytes = data[cur : cur + b_len]
                strings.append(s_bytes.decode("utf-8", errors="ignore"))
            else:
                if target_off + 2 <= len(data):
                    (u16_len,) = struct.unpack_from("<H", data, target_off)
                    s_bytes = data[target_off + 2 : target_off + 2 + (u16_len * 2)]
                    strings.append(s_bytes.decode("utf-16-le", errors="ignore"))
        except Exception:
            continue

    return strings, None


def _parse_xml_manifest(data: bytes) -> Tuple[Optional[List[str]], Optional[str], Optional[str]]:
    """
    Parse plaintext XML manifest if uncompiled.
    Returns (permissions, package_name, error_message).
    """
    trimmed = data.lstrip()
    if not (trimmed.startswith(b"<?xml") or trimmed.startswith(b"<manifest")):
        return None, None, "Not a plaintext XML document"

    try:
        decoded = trimmed.decode("utf-8", errors="ignore")
        pkg_match = re.search(r'package\s*=\s*["\']([^"\']+)["\']', decoded)
        pkg_name = pkg_match.group(1) if pkg_match else None

        perm_pattern = re.compile(
            r'<(?:uses-permission|permission)[^>]+(?:android:name|name)\s*=\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        found_perms = sorted(list(set(perm_pattern.findall(decoded))))
        return found_perms, pkg_name, None
    except Exception as e:
        return None, None, f"Failed to parse XML manifest: {e}"


def _extract_manifest_metadata(manifest_bytes: bytes) -> Tuple[List[str], Optional[str], Optional[str]]:
    """
    Safely extract permissions and package name from AndroidManifest.xml bytes.
    Validates that the file is either valid AXML binary or valid XML text.
    Rejects arbitrary binary noise to prevent false-positive permission detection.

    Returns:
    --------
    (permissions, package_name, error_message)
    """
    if not manifest_bytes or len(manifest_bytes) < 8:
        return [], None, "AndroidManifest.xml is empty or too short to be a valid manifest"

    # 1. Check for Android Binary XML (AXML)
    if manifest_bytes.startswith(b"\x03\x00\x08\x00"):
        strings, err = _parse_axml_string_pool(manifest_bytes)
        if err or strings is None:
            return [], None, f"Malformed APK: AndroidManifest.xml has corrupt AXML structure ({err})"

        permissions = sorted(list(set(s for s in strings if PERMISSION_PATTERN.match(s))))

        package_name = None
        for s in strings:
            if PACKAGE_PATTERN.match(s) and not s.startswith("android.") and not s.startswith("http"):
                if "." in s and not s.endswith(".xml") and not s.endswith(".permission"):
                    package_name = s
                    break

        return permissions, package_name, None

    # 2. Check for plaintext XML manifest
    trimmed = manifest_bytes.lstrip()
    if trimmed.startswith(b"<?xml") or trimmed.startswith(b"<manifest"):
        perms, pkg_name, err = _parse_xml_manifest(manifest_bytes)
        if err or perms is None:
            return [], None, f"Malformed APK: AndroidManifest.xml is corrupt XML ({err})"
        return perms, pkg_name, None

    # 3. Neither valid AXML nor valid XML: strictly reject arbitrary binary data
    return [], None, "Malformed APK: AndroidManifest.xml is neither valid Android Binary XML nor XML text"


def _parse_with_androguard(apk_path: Path, max_strings: int) -> Dict[str, Any]:
    """Parse APK using Androguard engine."""
    try:
        a = AndroguardAPK(str(apk_path))
        raw_perms = a.get_permissions() or []
        permissions = sorted(list(set(raw_perms)))
        package_name = a.get_package()

        extracted_strings: List[str] = []
        seen_strings: Set[str] = set()

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                dex_names = [name for name in zf.namelist() if name.endswith(".dex")]
                for dex_name in dex_names:
                    if len(extracted_strings) >= max_strings:
                        break
                    dex_data = zf.read(dex_name)
                    dex_strings = _extract_dex_strings(dex_data, max_strings - len(extracted_strings))
                    for s in dex_strings:
                        if s not in seen_strings:
                            seen_strings.add(s)
                            extracted_strings.append(s)
        except Exception as e:
            logger.warning("Failed secondary DEX extraction under Androguard: %s", e)

        file_size = apk_path.stat().st_size
        sha256_hash = calculate_sha256(apk_path)

        return {
            "filename": apk_path.name,
            "file_name": apk_path.name,
            "file_path": str(apk_path.resolve()),
            "status": "success",
            "requested_permissions": permissions,
            "extracted_strings": extracted_strings[:max_strings],
            "error_message": None,
            "file_size_bytes": file_size,
            "sha256": sha256_hash,
            "package_name": package_name,
            "engine": "androguard",
        }
    except Exception as e:
        logger.error("Androguard parsing failed: %s", e)
        raise e


def _parse_with_fallback(apk_path: Path, max_strings: int) -> Dict[str, Any]:
    """
    Parse APK using built-in static inspection (zipfile + AXML/DEX byte analysis).
    Never invents permissions or strings when parsing fails.
    """
    if not zipfile.is_zipfile(apk_path):
        return {
            "filename": apk_path.name,
            "file_name": apk_path.name,
            "file_path": str(apk_path.resolve()),
            "status": "error",
            "requested_permissions": [],
            "extracted_strings": [],
            "error_message": "Invalid file format: not a valid zip archive or APK",
            "file_size_bytes": apk_path.stat().st_size if apk_path.exists() else None,
            "sha256": None,
            "package_name": None,
            "engine": "static_fallback",
        }

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            namelist = zf.namelist()

            if "AndroidManifest.xml" not in namelist:
                return {
                    "filename": apk_path.name,
                    "file_name": apk_path.name,
                    "file_path": str(apk_path.resolve()),
                    "status": "error",
                    "requested_permissions": [],
                    "extracted_strings": [],
                    "error_message": "Malformed APK: AndroidManifest.xml not found in archive",
                    "file_size_bytes": apk_path.stat().st_size,
                    "sha256": calculate_sha256(apk_path),
                    "package_name": None,
                    "engine": "static_fallback",
                }

            # 1. Parse and validate AndroidManifest.xml
            manifest_bytes = zf.read("AndroidManifest.xml")
            permissions, package_name, manifest_err = _extract_manifest_metadata(manifest_bytes)

            # If manifest is malformed, reject the APK without inventing data
            if manifest_err is not None:
                return {
                    "filename": apk_path.name,
                    "file_name": apk_path.name,
                    "file_path": str(apk_path.resolve()),
                    "status": "error",
                    "requested_permissions": [],
                    "extracted_strings": [],
                    "error_message": manifest_err,
                    "file_size_bytes": apk_path.stat().st_size,
                    "sha256": calculate_sha256(apk_path),
                    "package_name": None,
                    "engine": "static_fallback",
                }

            # 2. Extract strings from all available .dex files
            extracted_strings: List[str] = []
            seen_strings: Set[str] = set()

            dex_files = [n for n in namelist if n.endswith(".dex")]
            for dex_file in dex_files:
                if len(extracted_strings) >= max_strings:
                    break
                dex_bytes = zf.read(dex_file)
                dex_strs = _extract_dex_strings(dex_bytes, max_strings - len(extracted_strings))
                for s in dex_strs:
                    if s not in seen_strings:
                        seen_strings.add(s)
                        extracted_strings.append(s)

            # 3. If DEX yielded less than requested max_strings, extract printable strings from manifest
            if len(extracted_strings) < max_strings:
                fallback_strs = _extract_printable_strings(
                    manifest_bytes, min_len=4, max_count=max_strings - len(extracted_strings)
                )
                for s in fallback_strs:
                    if s not in seen_strings:
                        seen_strings.add(s)
                        extracted_strings.append(s)

            file_size = apk_path.stat().st_size
            sha256_hash = calculate_sha256(apk_path)

            return {
                "filename": apk_path.name,
                "file_name": apk_path.name,
                "file_path": str(apk_path.resolve()),
                "status": "success",
                "requested_permissions": permissions,
                "extracted_strings": extracted_strings[:max_strings],
                "error_message": None,
                "file_size_bytes": file_size,
                "sha256": sha256_hash,
                "package_name": package_name,
                "engine": "static_fallback",
            }
    except zipfile.BadZipFile as e:
        return {
            "filename": apk_path.name,
            "file_name": apk_path.name,
            "file_path": str(apk_path.resolve()),
            "status": "error",
            "requested_permissions": [],
            "extracted_strings": [],
            "error_message": f"Corrupt or truncated APK archive: {str(e)}",
            "file_size_bytes": apk_path.stat().st_size if apk_path.exists() else None,
            "sha256": None,
            "package_name": None,
            "engine": "static_fallback",
        }
    except Exception as e:
        return {
            "filename": apk_path.name,
            "file_name": apk_path.name,
            "file_path": str(apk_path.resolve()),
            "status": "error",
            "requested_permissions": [],
            "extracted_strings": [],
            "error_message": f"Parser failure: {str(e)}",
            "file_size_bytes": apk_path.stat().st_size if apk_path.exists() else None,
            "sha256": None,
            "package_name": None,
            "engine": "static_fallback",
        }


def parse_apk(apk_path: Union[str, Path], max_strings: int = 100) -> Dict[str, Any]:
    """
    Statically parse an Android APK file and extract manifest permissions and strings.

    Parameters:
    -----------
    apk_path: str or Path
        Filesystem path to the APK specimen.
    max_strings: int, default=100
        Maximum number of extracted strings to return (capped to non-negative).

    Returns:
    --------
    dict:
        {
            "filename": str,
            "file_name": str,
            "file_path": str or None,
            "status": "success" | "error",
            "requested_permissions": List[str],
            "extracted_strings": List[str],
            "error_message": Optional[str],
            "file_size_bytes": Optional[int],
            "sha256": Optional[str],
            "package_name": Optional[str],
            "engine": str ("androguard" | "static_fallback" | "none")
        }
    """
    if not apk_path:
        return {
            "filename": "",
            "file_name": "",
            "file_path": None,
            "status": "error",
            "requested_permissions": [],
            "extracted_strings": [],
            "error_message": "APK file path must not be empty or None",
            "file_size_bytes": None,
            "sha256": None,
            "package_name": None,
            "engine": "none",
        }

    path = Path(apk_path)
    filename = path.name

    if not path.exists():
        return {
            "filename": filename,
            "file_name": filename,
            "file_path": str(path),
            "status": "error",
            "requested_permissions": [],
            "extracted_strings": [],
            "error_message": f"File does not exist: {path}",
            "file_size_bytes": None,
            "sha256": None,
            "package_name": None,
            "engine": "none",
        }

    if path.is_dir():
        return {
            "filename": filename,
            "file_name": filename,
            "file_path": str(path),
            "status": "error",
            "requested_permissions": [],
            "extracted_strings": [],
            "error_message": f"Specified path is a directory, expected an APK file: {path}",
            "file_size_bytes": None,
            "sha256": None,
            "package_name": None,
            "engine": "none",
        }

    try:
        size = path.stat().st_size
        if size == 0:
            return {
                "filename": filename,
                "file_name": filename,
                "file_path": str(path),
                "status": "error",
                "requested_permissions": [],
                "extracted_strings": [],
                "error_message": f"File is empty (0 bytes): {path}",
                "file_size_bytes": 0,
                "sha256": None,
                "package_name": None,
                "engine": "none",
            }
    except OSError as e:
        return {
            "filename": filename,
            "file_name": filename,
            "file_path": str(path),
            "status": "error",
            "requested_permissions": [],
            "extracted_strings": [],
            "error_message": f"Cannot access file: {str(e)}",
            "file_size_bytes": None,
            "sha256": None,
            "package_name": None,
            "engine": "none",
        }

    effective_max_strings = max(0, int(max_strings))

    # Attempt parsing with Androguard if available
    if ANDROGUARD_AVAILABLE and AndroguardAPK is not None:
        try:
            return _parse_with_androguard(path, effective_max_strings)
        except Exception as e:
            logger.warning("Androguard failed (%s); falling back to static zip analysis.", e)

    # Static fallback engine
    return _parse_with_fallback(path, effective_max_strings)


class StaticAPKParser:
    """Object-oriented wrapper for static Android APK analysis."""

    def __init__(self, default_max_strings: int = 100):
        self.default_max_strings = max(0, default_max_strings)

    def parse(self, apk_path: Union[str, Path], max_strings: Optional[int] = None) -> Dict[str, Any]:
        """Parse an APK file and return structured results."""
        limit = self.default_max_strings if max_strings is None else max(0, max_strings)
        return parse_apk(apk_path, max_strings=limit)
