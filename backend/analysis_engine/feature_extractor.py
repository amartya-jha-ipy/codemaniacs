"""Real static feature extraction from APK bytes.

``androguard`` is not available in this environment, so this module performs a
best-effort, *verifiable* static scan of the APK archive:

* Android permissions are recovered by scanning ``AndroidManifest.xml`` (and, as a
  fallback, the whole archive) for ``android.permission.*`` tokens. The binary AXML
  format keeps these permission strings in the string pool as readable ASCII, so a
  regex recovers them reliably even without a full AXML parser.
* URLs / IPv4 addresses / domains are extracted from the archive's string content
  (classes.dex, resources, assets).
* A fixed catalogue of suspicious API signatures is checked for *string presence*
  only -- this records that a symbol appears in the sample, which is a genuine
  static observation. It is NOT a claim that the code path executes at runtime.

Every value returned here is derived from the uploaded bytes. Nothing is invented.
When a feature cannot be recovered (e.g. the file is not a valid zip) the relevant
field is returned empty, never fabricated.
"""
import hashlib
import io
import re
import zipfile
from urllib.parse import urlparse

# Dangerous permissions get a severity hint for the UI / report. Anything not listed
# is reported with level "Info" rather than guessed at.
_CRITICAL_PERMISSIONS = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CONTACTS", "WRITE_CONTACTS",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "RECORD_AUDIO", "READ_PHONE_STATE",
    "PROCESS_OUTGOING_CALLS", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES",
    "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN",
}
_WARNING_PERMISSIONS = {
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "CAMERA", "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE", "GET_ACCOUNTS", "READ_CALENDAR", "WRITE_CALENDAR",
    "QUERY_ALL_PACKAGES",
}

# Static API signatures commonly associated with abuse. Presence of the *string* is
# recorded as a static indicator only.
_SUSPICIOUS_API_SIGNATURES = [
    "sendTextMessage",            # SMS exfiltration / premium SMS
    "getDeviceId",                # IMEI harvesting
    "getSubscriberId",            # IMSI harvesting
    "getLine1Number",             # phone number harvesting
    "DexClassLoader",             # dynamic code loading
    "PathClassLoader",            # dynamic code loading
    "loadDex",                    # dynamic code loading
    "Ljava/lang/reflect",         # reflection
    "Runtime;->exec",             # command execution
    "getInstalledPackages",       # installed-app enumeration
    "TelephonyManager",           # device/telephony introspection
    "AccessibilityService",       # accessibility abuse
    "addView",                    # overlay construction
    "Cipher",                     # crypto (possible ransomware/obfuscation)
    "HttpURLConnection",          # network egress
]

_PERMISSION_RE = re.compile(rb"android\.permission\.([A-Z0-9_]{3,40})")
_URL_RE = re.compile(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,200}")
_IPV4_RE = re.compile(rb"(?<!\d)((?:\d{1,3}\.){3}\d{1,3})(?!\d)")

# Scan at most this many bytes per archive entry to keep extraction bounded.
_MAX_ENTRY_BYTES = 8 * 1024 * 1024


def _valid_ipv4(raw):
    parts = raw.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _looks_like_domain(host):
    if not host or len(host) > 253:
        return False
    if _valid_ipv4(host):
        return False  # IPs are tracked separately
    if "." not in host:
        return False
    tld = host.rsplit(".", 1)[-1]
    # Require an alphabetic TLD of a plausible length to cut noise like "1.2".
    return tld.isalpha() and 2 <= len(tld) <= 24


def _classify_permission(short_name):
    if short_name in _CRITICAL_PERMISSIONS:
        return "Critical"
    if short_name in _WARNING_PERMISSIONS:
        return "Warning"
    return "Info"


def classify_permission(name):
    """Public helper: severity level for a full permission name (e.g.
    ``android.permission.READ_SMS`` -> ``Critical``)."""
    return _classify_permission(str(name).rsplit(".", 1)[-1])


def extract_static_features(contents, filename="specimen.apk"):
    """Extract verifiable static features from raw APK bytes.

    Returns a stable findings dict. The structure is always the same shape, with
    empty collections where a feature could not be recovered.
    """
    sha256 = hashlib.sha256(contents).hexdigest()
    size_mb = round(len(contents) / (1024 * 1024), 4)

    findings = {
        "filename": filename,
        "sha256": sha256,
        "size_mb": size_mb,
        "is_valid_zip": False,
        "permissions": [],          # list of {name, level}
        "suspicious_apis": [],      # list of signature strings actually present
        "urls": [],
        "ips": [],
        "domains": [],
        "extraction_notes": [],
    }

    perm_names = set()
    api_sigs = set()
    urls = set()
    ips = set()
    domains = set()

    try:
        with zipfile.ZipFile(io.BytesIO(contents)) as zf:
            findings["is_valid_zip"] = True
            names = zf.namelist()

            # 1. Permissions: prefer the manifest, fall back to the whole archive.
            manifest_blob = b""
            if "AndroidManifest.xml" in names:
                try:
                    manifest_blob = zf.read("AndroidManifest.xml")[:_MAX_ENTRY_BYTES]
                except Exception as exc:  # pragma: no cover - defensive
                    findings["extraction_notes"].append(f"manifest read failed: {exc}")
            scan_targets = [manifest_blob] if manifest_blob else []

            # 2. Content scan for strings across code/resource entries.
            scanned = 0
            for name in names:
                lower = name.lower()
                if not (lower.endswith(".dex") or lower.endswith(".xml")
                        or lower.endswith(".arsc") or lower.startswith("assets/")
                        or lower.startswith("res/")):
                    continue
                try:
                    blob = zf.read(name)[:_MAX_ENTRY_BYTES]
                except Exception:
                    continue
                scan_targets.append(blob)
                scanned += 1
                if scanned >= 64:  # bound the number of entries scanned
                    findings["extraction_notes"].append("entry scan capped at 64 files")
                    break

            if not manifest_blob and not scan_targets:
                findings["extraction_notes"].append(
                    "AndroidManifest.xml not found; permissions scanned from archive content"
                )

            for blob in scan_targets:
                for m in _PERMISSION_RE.finditer(blob):
                    perm_names.add("android.permission." + m.group(1).decode("ascii"))
                for sig in _SUSPICIOUS_API_SIGNATURES:
                    if sig.encode("ascii") in blob:
                        api_sigs.add(sig)
                for m in _URL_RE.finditer(blob):
                    try:
                        urls.add(m.group(0).decode("ascii", "ignore").rstrip("\\/\"'"))
                    except Exception:
                        continue
                for m in _IPV4_RE.finditer(blob):
                    raw = m.group(1).decode("ascii", "ignore")
                    if _valid_ipv4(raw):
                        ips.add(raw)

            # Derive hostnames from URLs (never treat a URL path as a hostname).
            for url in urls:
                host = urlparse(url).hostname
                if host and _looks_like_domain(host):
                    domains.add(host.lower())

    except zipfile.BadZipFile:
        findings["extraction_notes"].append("not a valid zip/APK archive; static extraction skipped")
    except Exception as exc:  # pragma: no cover - defensive
        findings["extraction_notes"].append(f"extraction error: {exc}")

    findings["permissions"] = sorted(
        ({"name": p, "level": _classify_permission(p.rsplit(".", 1)[-1])} for p in perm_names),
        key=lambda x: x["name"],
    )
    findings["suspicious_apis"] = sorted(api_sigs)
    findings["urls"] = sorted(urls)
    findings["ips"] = sorted(ips)
    findings["domains"] = sorted(domains)
    return findings
