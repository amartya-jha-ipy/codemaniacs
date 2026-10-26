"""Anti-evasion static unpacking (Phase 3).

Advanced Android malware hides behind three tricks this module is built to unmask,
*without executing any code*:

1. **Manifest padding / header anomalies** -- a malformed or bloated
   ``AndroidManifest.xml`` designed to crash naive parsers. We verify the binary
   AXML magic and the self-declared chunk size against the real entry size.
2. **Multi-DEX and hidden payloads** -- secondary ``.dex`` files plus encrypted
   blobs (``.dex`` / ``.jar`` / ``.apk`` / ``.so`` / ``.bin``) stashed under
   ``assets/`` or ``res/raw/`` and loaded at runtime. High Shannon entropy on a
   disguised entry is the tell for an encrypted payload.
3. **Dynamic code loading & string encryption** -- ``DexClassLoader`` /
   ``PathClassLoader`` / ``loadDex`` references, and custom decryption routines
   (``Cipher`` / ``AES`` / ``Base64.decode`` / ``char[]`` assembly) used to hide
   command-and-control URLs until runtime.

Everything returned here is derived from the uploaded bytes. When a check cannot
run (e.g. the file is not a valid zip) the relevant field is empty, never invented.
The ``indicators`` list uses lowercase tokens that feed directly into
``backend.scoring.calculate_risk_score`` as ``suspicious_indicators``.
"""
from __future__ import annotations

import io
import math
import zipfile
from collections import Counter

# AXML (binary AndroidManifest.xml) starts with a chunk header:
#   u16 type (0x0003), u16 header size (0x0008), u32 total chunk size.
# As a little-endian byte stream the first 8 bytes are therefore 03 00 08 00 <size LE>.
_AXML_MAGIC = b"\x03\x00\x08\x00"

# Entries whose extension is "legitimate" for binary content. A high-entropy blob
# with one of these extensions is expected; a high-entropy blob WITHOUT one, or one
# masquerading under an innocuous name, is what we flag.
_EXECUTABLE_EXTS = (".dex", ".jar", ".apk", ".so", ".zip", ".bin", ".dat", ".db")
_PAYLOAD_DIRS = ("assets/", "res/raw/", "raw/", "lib/")

# Dynamic Code Loading (DCL) signatures -- presence of the symbol string in bytecode.
_DCL_SIGNATURES = (
    b"DexClassLoader",
    b"PathClassLoader",
    b"InMemoryDexClassLoader",
    b"BaseDexClassLoader",
    b"loadDex",
    b"loadClass",
)

# String-encryption / dynamic-string-assembly signals. Each is a genuine static
# observation of a symbol commonly used to hide C2 URLs behind runtime decryption.
_CRYPTO_SIGNATURES = (
    b"javax/crypto/Cipher",
    b"Cipher",
    b"SecretKeySpec",
    b"AES/CBC",
    b"AES/ECB",
    b"DESKeySpec",
    b"doFinal",
    b"android/util/Base64",
    b"Base64",
)

# Scan at most this many bytes per entry, and at most this many entries, so a
# hostile archive cannot exhaust memory.
_MAX_ENTRY_BYTES = 8 * 1024 * 1024
_MAX_ENTRIES = 256
# Entropy (bits/byte) above which a blob is treated as compressed/encrypted.
_ENCRYPTED_ENTROPY = 7.2


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 for empty input, max 8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 4)


def _verify_manifest(zf: zipfile.ZipFile, names: list[str]) -> dict:
    """Check AndroidManifest.xml for the AXML magic and header-size consistency."""
    result = {
        "present": False,
        "magic_valid": False,
        "declared_size": None,
        "actual_size": None,
        "padding_bytes": 0,
        "anomalies": [],
    }
    if "AndroidManifest.xml" not in names:
        result["anomalies"].append("AndroidManifest.xml missing from archive")
        return result

    result["present"] = True
    try:
        blob = zf.read("AndroidManifest.xml")[:_MAX_ENTRY_BYTES]
    except Exception as exc:  # pragma: no cover - defensive
        result["anomalies"].append(f"manifest unreadable: {exc}")
        return result

    actual = len(blob)
    result["actual_size"] = actual

    if actual < 8:
        result["anomalies"].append("manifest truncated: shorter than an AXML header (8 bytes)")
        return result

    if blob[:4] == _AXML_MAGIC:
        result["magic_valid"] = True
        declared = int.from_bytes(blob[4:8], "little")
        result["declared_size"] = declared
        if declared > actual:
            result["anomalies"].append(
                f"manifest truncated: header declares {declared} bytes but entry holds {actual}"
            )
        elif declared < actual:
            # Trailing bytes beyond the declared chunk = padding used to bloat the
            # file or desync lazy parsers.
            result["padding_bytes"] = actual - declared
            result["anomalies"].append(
                f"manifest padded: {actual - declared} trailing bytes beyond declared chunk size"
            )
    else:
        # A plaintext <manifest> (common in test fixtures / un-compiled APKs) is not
        # an anomaly by itself; a random header, however, is suspicious.
        if blob.lstrip()[:1] in (b"<",):
            result["anomalies"].append("manifest is plaintext XML (not compiled AXML)")
        else:
            result["anomalies"].append("manifest header does not match AXML magic bytes")
    return result


def _scan_payloads(zf: zipfile.ZipFile, names: list[str]) -> tuple[list[dict], dict]:
    """Find secondary DEX files and high-entropy hidden payloads."""
    embedded: list[dict] = []
    dex_entries = []

    scanned = 0
    for name in names:
        if scanned >= _MAX_ENTRIES:
            break
        lower = name.lower()
        if lower.endswith("/"):
            continue

        is_dex = lower.endswith(".dex")
        in_payload_dir = lower.startswith(_PAYLOAD_DIRS)
        has_exec_ext = lower.endswith(_EXECUTABLE_EXTS)

        if is_dex:
            dex_entries.append(name)

        # Only read entries worth inspecting: any dex, or anything living in a
        # payload directory, or anything with an executable extension.
        if not (is_dex or in_payload_dir or has_exec_ext):
            continue

        try:
            blob = zf.read(name)[:_MAX_ENTRY_BYTES]
        except Exception:
            continue
        scanned += 1

        entropy = shannon_entropy(blob)
        magic = blob[:4]
        looks_dex = magic[:3] == b"dex"
        looks_zip = magic[:2] == b"PK"
        looks_elf = magic == b"\x7fELF"

        suspicious = False
        reasons = []
        # Secondary dex (classes2.dex, or a .dex hidden in assets) is a payload stage.
        if is_dex and name != "classes.dex":
            suspicious = True
            reasons.append("secondary DEX outside primary classes.dex")
        # A disguised payload: high entropy but NOT a recognised container type, or
        # sitting in assets/raw where real executable code should not normally live.
        if entropy >= _ENCRYPTED_ENTROPY and not (looks_zip or looks_elf):
            if in_payload_dir or not has_exec_ext:
                suspicious = True
                reasons.append(f"high-entropy blob (entropy={entropy}) consistent with encryption/packing")
        # A real DEX/ELF hiding under a non-code extension in assets/.
        if in_payload_dir and (looks_dex or looks_elf) and not has_exec_ext:
            suspicious = True
            reasons.append("executable file disguised under a non-code name")

        if suspicious:
            embedded.append({
                "name": name,
                "size": len(blob),
                "entropy": entropy,
                "reasons": reasons,
            })

    multidex = {
        "dex_count": len(dex_entries),
        "dex_entries": sorted(dex_entries),
        "has_secondary_dex": len(dex_entries) > 1
        or any(d != "classes.dex" and d.endswith(".dex") for d in dex_entries),
    }
    return embedded, multidex


def _scan_code_signatures(zf: zipfile.ZipFile, names: list[str]) -> tuple[dict, dict]:
    """Scan code/resource entries for DCL and string-encryption signatures."""
    dcl_found: set[str] = set()
    crypto_found: set[str] = set()

    scanned = 0
    for name in names:
        if scanned >= _MAX_ENTRIES:
            break
        lower = name.lower()
        if not (lower.endswith(".dex") or lower.endswith(".so")
                or lower.startswith(_PAYLOAD_DIRS)):
            continue
        try:
            blob = zf.read(name)[:_MAX_ENTRY_BYTES]
        except Exception:
            continue
        scanned += 1
        for sig in _DCL_SIGNATURES:
            if sig in blob:
                dcl_found.add(sig.decode("ascii"))
        for sig in _CRYPTO_SIGNATURES:
            if sig in blob:
                crypto_found.add(sig.decode("ascii"))

    dynamic_code_loading = {
        "detected": bool(dcl_found),
        "signatures": sorted(dcl_found),
    }
    # String encryption is only asserted when a crypto primitive co-occurs with a
    # Base64/key-spec symbol -- a single "Cipher" string is too weak on its own.
    strong = {"SecretKeySpec", "doFinal", "AES/CBC", "AES/ECB", "DESKeySpec"}
    base64 = {"Base64", "android/util/Base64"}
    detected = bool((crypto_found & strong) and (crypto_found & base64)) or len(crypto_found) >= 3
    string_encryption = {
        "detected": detected,
        "signals": sorted(crypto_found),
    }
    return dynamic_code_loading, string_encryption


def analyze_anti_evasion(contents: bytes) -> dict:
    """Run every Phase 3 anti-evasion check over raw APK bytes.

    Returns a stable report dict. ``indicators`` holds lowercase tokens suitable for
    ``scoring.calculate_risk_score(suspicious_indicators=...)``.
    """
    report = {
        "is_valid_zip": False,
        "manifest": {"present": False, "magic_valid": False, "anomalies": []},
        "embedded_payloads": [],
        "multidex": {"dex_count": 0, "dex_entries": [], "has_secondary_dex": False},
        "dynamic_code_loading": {"detected": False, "signatures": []},
        "string_encryption": {"detected": False, "signals": []},
        "indicators": [],
        "notes": [],
    }

    try:
        with zipfile.ZipFile(io.BytesIO(contents)) as zf:
            report["is_valid_zip"] = True
            names = zf.namelist()[: _MAX_ENTRIES * 2]
            report["manifest"] = _verify_manifest(zf, names)
            report["embedded_payloads"], report["multidex"] = _scan_payloads(zf, names)
            report["dynamic_code_loading"], report["string_encryption"] = _scan_code_signatures(zf, names)
    except zipfile.BadZipFile:
        report["notes"].append("not a valid zip/APK archive; anti-evasion scan skipped")
        return report
    except Exception as exc:  # pragma: no cover - defensive
        report["notes"].append(f"anti-evasion scan error: {exc}")
        return report

    indicators: list[str] = []
    if report["manifest"]["anomalies"] and not report["manifest"].get("magic_valid", False):
        # Only count a *binary* anomaly as evasion; plaintext XML fixtures are benign.
        if any("padded" in a or "truncated" in a or "magic" in a
               for a in report["manifest"]["anomalies"]):
            indicators.append("manifest_anomaly")
    elif report["manifest"].get("padding_bytes", 0) > 0:
        indicators.append("manifest_anomaly")

    if report["multidex"]["has_secondary_dex"]:
        indicators.append("secondary_dex_payload")
    if report["embedded_payloads"]:
        indicators.append("hidden_encrypted_payload")
    if report["dynamic_code_loading"]["detected"]:
        indicators.append("dynamic_code_loading")
    if report["string_encryption"]["detected"]:
        indicators.append("string_encryption")

    report["indicators"] = sorted(set(indicators))
    return report
