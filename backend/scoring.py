"""
ANVESH - Dynamic Risk Scoring Module
================================================
Module: backend/scoring.py
Lead: Developer 3 — AI/ML & Static Parsing Lead
Branch: feature/ml-parser-scoring

Explainable, deterministic heuristic risk-scoring engine.
Evaluates static APK parser output, feature-density metrics, and contextual
compounding of suspicious indicators.

NOTE ON METHODOLOGY:
This module is a configurable, explainable rule-based scoring engine.
It is NOT a trained predictive ML model (e.g., neural network or random forest)
as no empirical model weights or training pipelines are provided.
Missing observations are explicitly surfaced as warnings and NEVER treated
as proof of safety.

Severity Classification:
- LOW:      0–24
- MEDIUM:  25–49
- HIGH:    50–74
- CRITICAL: 75–100
"""

from dataclasses import dataclass, field
import logging
from typing import Any, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)

# Critical high-abuse permissions frequently exploited in banking trojans and spyware
CRITICAL_ABUSE_PERMISSIONS: Dict[str, float] = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 12.0,  # Keylogging, auto-granting, UI scraping
    "android.permission.SYSTEM_ALERT_WINDOW": 10.0,         # Fake overlay injection over banking apps
    "android.permission.BIND_DEVICE_ADMIN": 10.0,           # Device takeover, uninstall prevention
    "android.permission.REQUEST_INSTALL_PACKAGES": 8.0,     # Dropper / payload sideloading
    "android.permission.PACKAGE_USAGE_STATS": 7.0,          # Forensic app monitoring (target detection)
    "android.permission.QUERY_ALL_PACKAGES": 5.0,           # Installed app reconnaissance
    "android.permission.WRITE_SETTINGS": 5.0,               # System configuration tampering
}

# Standard Android dangerous (runtime) permissions + high-abuse permissions
DANGEROUS_PERMISSIONS: Set[str] = {
    # SMS
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_WAP_PUSH",
    # Phone / Telephony
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.ANSWER_PHONE_CALLS",
    # Location
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    # Media / Audio
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    # Contacts & Calendar
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    # Storage
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    # Body sensors
    "android.permission.BODY_SENSORS",
    # Union of Critical Abuse permissions
    *CRITICAL_ABUSE_PERMISSIONS.keys(),
}


@dataclass
class ScoringConfig:
    """Configurable weights and ceilings for risk score computation."""

    # Permission feature-density weights
    weight_permission_density: float = 20.0
    weight_dangerous_perm: float = 4.0
    max_permission_score: float = 50.0

    # Obfuscation feature-density weights
    weight_obfuscation_density: float = 25.0
    max_obfuscation_score: float = 25.0

    # Suspicious indicator weights
    weight_suspicious_indicator: float = 8.0
    max_indicator_score: float = 20.0

    # Contextual compounding interaction bonuses (toxic combinations)
    bonus_sms_stealer: float = 14.0         # SMS interception + Internet access
    bonus_banking_overlay: float = 16.0     # Overlay + Accessibility or Usage Stats
    bonus_dropper_payload: float = 12.0     # Package installer + Internet + Storage
    bonus_surveillance: float = 14.0        # Audio/Camera + Location + Internet
    bonus_stealth_exfil: float = 12.0       # High obfuscation + High dangerous permission density
    bonus_dynamic_code_c2: float = 12.0     # Dynamic code loading + Internet
    max_compound_score: float = 30.0

    # Total score clamping
    min_score: int = 0
    max_score: int = 100


def classify_severity(score: int) -> str:
    """
    Classify normalized risk score into severity tiers.
    - LOW:      0–24
    - MEDIUM:  25–49
    - HIGH:    50–74
    - CRITICAL: 75–100
    """
    if score <= 24:
        return "LOW"
    elif score <= 49:
        return "MEDIUM"
    elif score <= 74:
        return "HIGH"
    else:
        return "CRITICAL"


def _safe_int(val: Any) -> Optional[int]:
    """Safely convert value to non-negative int or None."""
    if val is None:
        return None
    try:
        iv = int(val)
        return iv if iv >= 0 else None
    except (ValueError, TypeError):
        return None


def calculate_risk_score(
    parser_output: Optional[Dict[str, Any]] = None,
    *,
    config: Optional[ScoringConfig] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Calculate an explainable, deterministic risk score from static parser output.

    Parameters:
    -----------
    parser_output: Optional[Dict[str, Any]]
        Structured dictionary matching backend.parser.parse_apk output schema,
        optionally extended with analysis pipeline metrics.
    config: Optional[ScoringConfig]
        Optional custom scoring weights and thresholds.
    kwargs: Any
        Direct parameter overrides (e.g. requested_permissions, obfuscated_methods_count, etc.)

    Returns:
    --------
    dict:
        {
            "risk_score": int (0–100),
            "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
            "feature_metrics": dict,
            "risk_contributors": list of dicts,
            "warnings": list of strings,
            "model_metadata": dict
        }
    """
    cfg = config or ScoringConfig()
    warnings: List[str] = []
    contributors: List[Dict[str, Any]] = []

    # Merge parser_output and kwargs
    data: Dict[str, Any] = {}
    if isinstance(parser_output, dict):
        data.update(parser_output)
    elif parser_output is not None:
        warnings.append(f"Input parser_output of type '{type(parser_output).__name__}' is invalid; expected dict.")
    data.update(kwargs)

    # Inspect parser status
    if not data:
        warnings.append("Input data is empty or None; returning baseline assessment without assuming safety.")

    parser_status = data.get("status")
    if parser_status == "error":
        err_msg = data.get("error_message") or "Unspecified parser error"
        warnings.append(
            f"Underlying parser reported failure: '{err_msg}'. "
            "Scoring reflects only available extracted data and cannot guarantee safety."
        )

    # ---------------------------------------------------------
    # 1. Permission Feature-Density & Critical Abuse Scoring
    # ---------------------------------------------------------
    raw_perms = data.get("requested_permissions", [])
    if not isinstance(raw_perms, (list, set, tuple)):
        warnings.append(f"Invalid requested_permissions type '{type(raw_perms).__name__}'; expected list.")
        raw_perms = []

    permissions_set: Set[str] = set(str(p).strip() for p in raw_perms if p)
    total_requested = len(permissions_set)

    matched_dangerous: List[str] = sorted(
        list(permissions_set.intersection(DANGEROUS_PERMISSIONS))
    )
    matched_critical: List[str] = sorted(
        list(permissions_set.intersection(set(CRITICAL_ABUSE_PERMISSIONS.keys())))
    )

    dangerous_count = len(matched_dangerous)
    critical_count = len(matched_critical)

    # Permission danger density = dangerous_permissions / total_requested
    permission_danger_density = 0.0
    if total_requested > 0:
        permission_danger_density = round(dangerous_count / total_requested, 4)
    else:
        if parser_status != "error":
            warnings.append("No permissions requested or manifest unpopulated.")

    permission_score = 0.0

    # Contribution 1A: Permission Danger Density
    if permission_danger_density > 0:
        density_pts = round(permission_danger_density * cfg.weight_permission_density, 2)
        permission_score += density_pts
        contributors.append({
            "category": "permission_density",
            "name": "Dangerous Permission Density",
            "points": density_pts,
            "description": f"{dangerous_count} of {total_requested} requested permissions are dangerous ({permission_danger_density * 100:.1f}%).",
            "evidence": [f"{dangerous_count}/{total_requested} dangerous"],
        })

    # Contribution 1B: Standard Dangerous Permissions Count (excluding double-count with critical abuse)
    non_critical_dangerous = [p for p in matched_dangerous if p not in CRITICAL_ABUSE_PERMISSIONS]
    if non_critical_dangerous:
        danger_pts = round(min(len(non_critical_dangerous) * cfg.weight_dangerous_perm, 20.0), 2)
        permission_score += danger_pts
        contributors.append({
            "category": "dangerous_permissions",
            "name": "Dangerous Permissions Observed",
            "points": danger_pts,
            "description": f"Requests {len(non_critical_dangerous)} Android dangerous runtime permissions.",
            "evidence": non_critical_dangerous,
        })

    # Contribution 1C: Critical Abuse Permissions
    if critical_count > 0:
        crit_pts = sum(CRITICAL_ABUSE_PERMISSIONS[p] for p in matched_critical)
        crit_pts_capped = round(min(crit_pts, 25.0), 2)
        permission_score += crit_pts_capped
        contributors.append({
            "category": "critical_permissions",
            "name": "Critical High-Abuse Permissions",
            "points": crit_pts_capped,
            "description": f"Requests {critical_count} critical permissions frequently abused by malware.",
            "evidence": matched_critical,
        })

    permission_score_capped = min(permission_score, cfg.max_permission_score)

    # ---------------------------------------------------------
    # 2. Obfuscation Feature-Density Scoring
    # ---------------------------------------------------------
    # Only computed when explicitly provided by the pipeline
    raw_obf = _safe_int(data.get("obfuscated_methods_count"))
    raw_total_m = _safe_int(data.get("total_methods_count"))
    clean_m = _safe_int(data.get("clean_methods_count"))

    if raw_total_m is None and raw_obf is not None and clean_m is not None:
        raw_total_m = raw_obf + clean_m

    obfuscation_density: Optional[float] = None
    obfuscation_score = 0.0

    if raw_obf is not None and raw_total_m is not None and raw_total_m > 0:
        obfuscation_density = round(min(1.0, raw_obf / raw_total_m), 4)
        obfuscation_pts = round(obfuscation_density * cfg.weight_obfuscation_density, 2)
        obfuscation_score = min(obfuscation_pts, cfg.max_obfuscation_score)
        if obfuscation_score > 0:
            contributors.append({
                "category": "obfuscation",
                "name": "Bytecode Obfuscation Density",
                "points": obfuscation_score,
                "description": f"{raw_obf} of {raw_total_m} bytecode methods exhibit identifier or control-flow obfuscation ({obfuscation_density * 100:.1f}%).",
                "evidence": [f"{raw_obf}/{raw_total_m} obfuscated methods"],
            })
    else:
        warnings.append(
            "Bytecode method obfuscation metrics were not provided in input; "
            "obfuscation density omitted from calculation without assuming safety."
        )

    # ---------------------------------------------------------
    # 3. Explicit Suspicious Indicators Scoring
    # ---------------------------------------------------------
    raw_indicators = data.get("suspicious_indicators", [])
    if not isinstance(raw_indicators, (list, set, tuple)):
        warnings.append(f"Invalid suspicious_indicators type '{type(raw_indicators).__name__}'; expected list.")
        raw_indicators = []

    suspicious_indicators: List[str] = [
        str(ind).strip() for ind in raw_indicators if str(ind).strip()
    ]

    indicator_score = 0.0
    if suspicious_indicators:
        ind_pts = min(len(suspicious_indicators) * cfg.weight_suspicious_indicator, cfg.max_indicator_score)
        indicator_score = ind_pts
        contributors.append({
            "category": "indicators",
            "name": "Pipeline Suspicious Indicators",
            "points": indicator_score,
            "description": f"Analysis pipeline detected {len(suspicious_indicators)} explicit suspicious indicators.",
            "evidence": suspicious_indicators,
        })
    else:
        warnings.append(
            "No dynamic runtime observations or pipeline suspicious indicators provided; "
            "scoring reflects static observations only."
        )

    # ---------------------------------------------------------
    # 4. Contextual Compounding (Toxic Combinations)
    # ---------------------------------------------------------
    compound_score = 0.0
    compound_triggers: List[str] = []

    has_internet = "android.permission.INTERNET" in permissions_set

    # Combo 1: SMS Interception + Internet (SMS Stealer / OTP Theft)
    has_sms = any(
        p in permissions_set
        for p in ["android.permission.RECEIVE_SMS", "android.permission.READ_SMS", "android.permission.SEND_SMS"]
    )
    if has_sms and has_internet:
        compound_score += cfg.bonus_sms_stealer
        compound_triggers.append("SMS_STEALER_COMBO")
        contributors.append({
            "category": "contextual_compounding",
            "name": "Contextual Compounding: SMS Interception & Exfiltration",
            "points": cfg.bonus_sms_stealer,
            "description": "Co-occurrence of SMS reception/reading and Internet access enables automated OTP theft.",
            "evidence": ["SMS interception capability", "android.permission.INTERNET"],
        })

    # Combo 2: Fake Overlay + Accessibility / Usage Stats (Banking Trojan)
    has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in permissions_set
    has_acc_or_usage = (
        "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions_set
        or "android.permission.PACKAGE_USAGE_STATS" in permissions_set
    )
    if has_overlay and has_acc_or_usage:
        compound_score += cfg.bonus_banking_overlay
        compound_triggers.append("BANKING_OVERLAY_COMBO")
        contributors.append({
            "category": "contextual_compounding",
            "name": "Contextual Compounding: Banking Overlay & UI Monitoring",
            "points": cfg.bonus_banking_overlay,
            "description": "Combination of SYSTEM_ALERT_WINDOW with Accessibility or Usage Stats represents a banking overlay attack pattern.",
            "evidence": [
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.BIND_ACCESSIBILITY_SERVICE / PACKAGE_USAGE_STATS",
            ],
        })

    # Combo 3: Dropper Payload (Install packages + Internet + Storage / Dynamic Code)
    has_installer = "android.permission.REQUEST_INSTALL_PACKAGES" in permissions_set
    has_storage = any(
        p in permissions_set
        for p in [
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
        ]
    )
    has_dynamic_code = "dynamic_code_loading" in [ind.lower() for ind in suspicious_indicators]
    if has_installer and has_internet and (has_storage or has_dynamic_code):
        compound_score += cfg.bonus_dropper_payload
        compound_triggers.append("DROPPER_PAYLOAD_COMBO")
        contributors.append({
            "category": "contextual_compounding",
            "name": "Contextual Compounding: Malware Dropper Architecture",
            "points": cfg.bonus_dropper_payload,
            "description": "Package installer permission paired with Internet and file storage / dynamic execution enables secondary payload dropping.",
            "evidence": ["REQUEST_INSTALL_PACKAGES", "INTERNET", "Storage/Dynamic Code"],
        })

    # Combo 4: Covert Surveillance (Audio/Camera + Location + Internet)
    has_media_capture = (
        "android.permission.RECORD_AUDIO" in permissions_set
        or "android.permission.CAMERA" in permissions_set
    )
    has_location = (
        "android.permission.ACCESS_FINE_LOCATION" in permissions_set
        or "android.permission.ACCESS_COARSE_LOCATION" in permissions_set
    )
    if has_media_capture and has_location and has_internet:
        compound_score += cfg.bonus_surveillance
        compound_triggers.append("SURVEILLANCE_SPYWARE_COMBO")
        contributors.append({
            "category": "contextual_compounding",
            "name": "Contextual Compounding: Covert Audio/Visual & Location Surveillance",
            "points": cfg.bonus_surveillance,
            "description": "Simultaneous capture of audio/video, real-time location, and Internet exfiltration indicates surveillance spyware.",
            "evidence": ["Audio/Camera capture", "Location tracking", "INTERNET"],
        })

    # Combo 5: Stealth Disguise (High Obfuscation + High Permission Danger Density)
    if obfuscation_density is not None and obfuscation_density >= 0.5 and permission_danger_density >= 0.5:
        compound_score += cfg.bonus_stealth_exfil
        compound_triggers.append("STEALTH_EXFIL_COMBO")
        contributors.append({
            "category": "contextual_compounding",
            "name": "Contextual Compounding: Heavily Obfuscated High-Privilege Code",
            "points": cfg.bonus_stealth_exfil,
            "description": "Heavily obfuscated codebase (>=50%) coupled with high dangerous permission ratio (>=50%) indicates intentional anti-reversing.",
            "evidence": [
                f"Obfuscation density: {obfuscation_density * 100:.1f}%",
                f"Permission danger density: {permission_danger_density * 100:.1f}%",
            ],
        })

    # Combo 6: Dynamic Code Loading + Internet
    if has_dynamic_code and has_internet and "DROPPER_PAYLOAD_COMBO" not in compound_triggers:
        compound_score += cfg.bonus_dynamic_code_c2
        compound_triggers.append("DYNAMIC_CODE_C2_COMBO")
        contributors.append({
            "category": "contextual_compounding",
            "name": "Contextual Compounding: Dynamic Code Loading via Internet",
            "points": cfg.bonus_dynamic_code_c2,
            "description": "Dynamic DEX/payload loading with network access enables staging uninspected remote payloads.",
            "evidence": ["dynamic_code_loading", "android.permission.INTERNET"],
        })

    compound_score_capped = min(compound_score, cfg.max_compound_score)

    # ---------------------------------------------------------
    # 5. Composite Score Calculation & Normalization
    # ---------------------------------------------------------
    raw_total_score = (
        permission_score_capped
        + obfuscation_score
        + indicator_score
        + compound_score_capped
    )

    final_score = int(round(max(cfg.min_score, min(cfg.max_score, raw_total_score))))
    severity = classify_severity(final_score)

    feature_metrics: Dict[str, Any] = {
        "total_requested_permissions": total_requested,
        "dangerous_permissions_count": dangerous_count,
        "permission_danger_density": permission_danger_density,
        "critical_abuse_permissions_count": critical_count,
        "obfuscated_methods_count": raw_obf,
        "total_methods_count": raw_total_m,
        "obfuscation_density": obfuscation_density,
        "suspicious_indicators_count": len(suspicious_indicators),
        "contextual_compound_triggers": len(compound_triggers),
        "contextual_triggers_list": compound_triggers,
    }

    return {
        "risk_score": final_score,
        "severity": severity,
        "feature_metrics": feature_metrics,
        "risk_contributors": contributors,
        "warnings": warnings,
        "model_metadata": {
            "engine_type": "deterministic_feature_density_compounding",
            "is_trained_ml_model": False,
            "version": "2.0.0",
            "scoring_method": "deterministic_explainable_rules",
            "max_score_possible": cfg.max_score,
            "min_score_possible": cfg.min_score,
        },
    }
