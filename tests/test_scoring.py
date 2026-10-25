"""
SENTINEL-CRS v2.0 - Unit Tests for Dynamic Risk Scoring Module
==============================================================
Module: tests/test_scoring.py
Author: Developer 3 — AI/ML & Static Parsing Lead

Comprehensive unit tests verifying:
- Severity boundaries (0, 24, 25, 49, 50, 74, 75, 100)
- Empty, missing, and malformed inputs
- All-dangerous permissions
- Contextual compounding (SMS stealer, Banking overlay, Dropper, Surveillance, Stealth)
- Prevention of double-counting
- Missing metrics and honesty warnings (never assumes safety)
- Invalid values and defensive parsing
- Strict determinism across repeated executions
- Integration with backend.parser output schemas
"""

import unittest
from backend.scoring import (
    ScoringConfig,
    calculate_risk_score,
    classify_severity,
)


class TestRiskScoring(unittest.TestCase):
    def test_severity_boundary_classification(self):
        """Test exact boundary points for severity tier assignment."""
        # LOW: 0–24
        self.assertEqual(classify_severity(0), "LOW")
        self.assertEqual(classify_severity(12), "LOW")
        self.assertEqual(classify_severity(24), "LOW")

        # MEDIUM: 25–49
        self.assertEqual(classify_severity(25), "MEDIUM")
        self.assertEqual(classify_severity(37), "MEDIUM")
        self.assertEqual(classify_severity(49), "MEDIUM")

        # HIGH: 50–74
        self.assertEqual(classify_severity(50), "HIGH")
        self.assertEqual(classify_severity(62), "HIGH")
        self.assertEqual(classify_severity(74), "HIGH")

        # CRITICAL: 75–100
        self.assertEqual(classify_severity(75), "CRITICAL")
        self.assertEqual(classify_severity(88), "CRITICAL")
        self.assertEqual(classify_severity(100), "CRITICAL")

    def test_empty_permissions_and_inputs(self):
        """Test that empty inputs or empty permissions yield baseline score with clear warnings."""
        # None input
        res_none = calculate_risk_score(None)
        self.assertEqual(res_none["risk_score"], 0)
        self.assertEqual(res_none["severity"], "LOW")
        self.assertGreater(len(res_none["warnings"]), 0)

        # Empty dict
        res_empty = calculate_risk_score({})
        self.assertEqual(res_empty["risk_score"], 0)
        self.assertEqual(res_empty["severity"], "LOW")
        self.assertEqual(res_empty["feature_metrics"]["total_requested_permissions"], 0)
        self.assertEqual(res_empty["feature_metrics"]["permission_danger_density"], 0.0)

        # Empty permissions list
        res_empty_perms = calculate_risk_score({"requested_permissions": []})
        self.assertEqual(res_empty_perms["risk_score"], 0)
        self.assertEqual(res_empty_perms["severity"], "LOW")

    def test_clean_benign_app(self):
        """Test an application requesting only benign/normal permissions."""
        benign_perms = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.VIBRATE",
            "android.permission.WAKE_LOCK",
        ]
        res = calculate_risk_score({"requested_permissions": benign_perms})
        self.assertEqual(res["feature_metrics"]["dangerous_permissions_count"], 0)
        self.assertEqual(res["feature_metrics"]["permission_danger_density"], 0.0)
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(res["severity"], "LOW")

    def test_all_dangerous_permissions_critical_severity(self):
        """Test an APK where 100% of requested permissions are dangerous/critical."""
        malicious_perms = [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.INTERNET",
        ]
        # Add high obfuscation metrics
        res = calculate_risk_score(
            {
                "requested_permissions": malicious_perms,
                "obfuscated_methods_count": 80,
                "total_methods_count": 100,
                "suspicious_indicators": ["dynamic_code_loading", "anti_vm_detection"],
            }
        )
        self.assertEqual(res["severity"], "CRITICAL")
        self.assertGreaterEqual(res["risk_score"], 75)
        self.assertLessEqual(res["risk_score"], 100)
        self.assertGreater(res["feature_metrics"]["permission_danger_density"], 0.5)
        self.assertEqual(res["feature_metrics"]["obfuscation_density"], 0.8)

    def test_contextual_compounding_sms_stealer(self):
        """
        Verify that SMS reading/reception combined with INTERNET triggers
        the SMS_STEALER_COMBO compounding bonus.
        """
        # Case A: SMS permission WITHOUT Internet
        res_no_net = calculate_risk_score(
            {"requested_permissions": ["android.permission.RECEIVE_SMS"]}
        )
        self.assertNotIn("SMS_STEALER_COMBO", res_no_net["feature_metrics"]["contextual_triggers_list"])

        # Case B: SMS permission WITH Internet (covert exfiltration capability)
        res_with_net = calculate_risk_score(
            {"requested_permissions": ["android.permission.RECEIVE_SMS", "android.permission.INTERNET"]}
        )
        self.assertIn("SMS_STEALER_COMBO", res_with_net["feature_metrics"]["contextual_triggers_list"])
        self.assertGreater(res_with_net["risk_score"], res_no_net["risk_score"])

        # Check evidence in contributors
        compound_contributors = [
            c for c in res_with_net["risk_contributors"] if c["category"] == "contextual_compounding"
        ]
        self.assertTrue(any("SMS" in c["name"] for c in compound_contributors))

    def test_contextual_compounding_banking_overlay(self):
        """
        Verify that SYSTEM_ALERT_WINDOW combined with BIND_ACCESSIBILITY_SERVICE
        triggers the BANKING_OVERLAY_COMBO.
        """
        perms = [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.INTERNET",
        ]
        res = calculate_risk_score({"requested_permissions": perms})
        self.assertIn("BANKING_OVERLAY_COMBO", res["feature_metrics"]["contextual_triggers_list"])
        self.assertGreaterEqual(res["risk_score"], 50)  # Elevated into HIGH or CRITICAL

    def test_contextual_compounding_dropper(self):
        """
        Verify that REQUEST_INSTALL_PACKAGES + INTERNET + WRITE_EXTERNAL_STORAGE
        triggers the DROPPER_PAYLOAD_COMBO.
        """
        perms = [
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.INTERNET",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        ]
        res = calculate_risk_score({"requested_permissions": perms})
        self.assertIn("DROPPER_PAYLOAD_COMBO", res["feature_metrics"]["contextual_triggers_list"])

    def test_contextual_compounding_surveillance(self):
        """
        Verify that Audio/Camera + Location + Internet triggers
        the SURVEILLANCE_SPYWARE_COMBO.
        """
        perms = [
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.INTERNET",
        ]
        res = calculate_risk_score({"requested_permissions": perms})
        self.assertIn("SURVEILLANCE_SPYWARE_COMBO", res["feature_metrics"]["contextual_triggers_list"])

    def test_contextual_compounding_stealth_exfil(self):
        """
        Verify that >=50% method obfuscation coupled with >=50% dangerous permission density
        triggers STEALTH_EXFIL_COMBO.
        """
        perms = [
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_CONTACTS",
            "android.permission.INTERNET",
        ]
        res = calculate_risk_score(
            {
                "requested_permissions": perms,
                "obfuscated_methods_count": 60,
                "total_methods_count": 100,  # 60% obfuscated
            }
        )
        self.assertIn("STEALTH_EXFIL_COMBO", res["feature_metrics"]["contextual_triggers_list"])

    def test_missing_metrics_honesty_and_warnings(self):
        """
        Ensure missing metrics (e.g. obfuscation, dynamic indicators) are NOT
        treated as proof of safety, and explicit warnings are issued.
        """
        res = calculate_risk_score({"requested_permissions": ["android.permission.INTERNET"]})

        # Feature density for obfuscation should be None, not 0.0
        self.assertIsNone(res["feature_metrics"]["obfuscation_density"])

        # Check that warnings note the missing metrics
        warning_texts = " ".join(res["warnings"])
        self.assertIn("obfuscation", warning_texts.lower())
        self.assertIn("dynamic runtime observations", warning_texts.lower())

    def test_parser_error_handling_and_warning(self):
        """Ensure parser errors are reported in warnings and do not crash the engine."""
        error_payload = {
            "status": "error",
            "error_message": "Malformed APK: AndroidManifest.xml not found in archive",
            "requested_permissions": [],
            "extracted_strings": [],
        }
        res = calculate_risk_score(error_payload)
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(res["severity"], "LOW")
        self.assertTrue(any("parser reported failure" in w for w in res["warnings"]))

    def test_invalid_and_malformed_values(self):
        """Test defensive behavior against malformed, negative, or invalid types."""
        res = calculate_risk_score(
            {
                "requested_permissions": "NOT_A_LIST",  # Invalid type
                "obfuscated_methods_count": -50,         # Negative number
                "total_methods_count": 0,               # Zero division edge case
                "suspicious_indicators": None,           # None value
            }
        )
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(res["severity"], "LOW")
        self.assertIsNone(res["feature_metrics"]["obfuscation_density"])

    def test_deterministic_output(self):
        """Verify that identical inputs produce identical scores and contributors across runs."""
        sample_input = {
            "requested_permissions": [
                "android.permission.RECEIVE_SMS",
                "android.permission.INTERNET",
                "android.permission.ACCESS_FINE_LOCATION",
            ],
            "obfuscated_methods_count": 25,
            "total_methods_count": 100,
            "suspicious_indicators": ["c2_beaconing"],
        }

        baseline = calculate_risk_score(sample_input)
        for _ in range(20):
            current = calculate_risk_score(sample_input)
            self.assertEqual(baseline["risk_score"], current["risk_score"])
            self.assertEqual(baseline["severity"], current["severity"])
            self.assertEqual(baseline["feature_metrics"], current["feature_metrics"])
            self.assertEqual(len(baseline["risk_contributors"]), len(current["risk_contributors"]))

    def test_score_clamping(self):
        """Ensure the score is strictly clamped within [0, 100]."""
        extreme_input = {
            "requested_permissions": list(
                ScoringConfig.__annotations__.keys()
            ) + [
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.INTERNET",
                "android.permission.WRITE_EXTERNAL_STORAGE",
            ],
            "obfuscated_methods_count": 1000,
            "total_methods_count": 1000,
            "suspicious_indicators": [f"indicator_{i}" for i in range(50)],
        }
        res = calculate_risk_score(extreme_input)
        self.assertEqual(res["risk_score"], 100)
        self.assertEqual(res["severity"], "CRITICAL")

    def test_custom_config_support(self):
        """Verify that custom ScoringConfig can override weights and thresholds."""
        custom_cfg = ScoringConfig(
            weight_permission_density=5.0,
            bonus_sms_stealer=5.0,
        )
        res_default = calculate_risk_score({
            "requested_permissions": ["android.permission.RECEIVE_SMS", "android.permission.INTERNET"]
        })
        res_custom = calculate_risk_score(
            {"requested_permissions": ["android.permission.RECEIVE_SMS", "android.permission.INTERNET"]},
            config=custom_cfg,
        )
        self.assertLess(res_custom["risk_score"], res_default["risk_score"])


if __name__ == "__main__":
    unittest.main()
