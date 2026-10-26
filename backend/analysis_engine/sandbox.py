"""Simulated dynamic sandbox and telemetry layer (Phase 4).

IMPORTANT -- WHAT THIS IS AND IS NOT
------------------------------------
This module does **not** execute the APK. A hardware device farm is out of scope
for the build, and running live malware on the host is exactly what the rest of
the pipeline is designed to avoid. Instead this is an *explainable simulation*:

* It emits **synthetic sensor telemetry** (accelerometer, battery, touch/scroll)
  of the kind a real sandbox would feed a sample to defeat emulator-detection
  checks -- malware that bails out on a "stuck 100% battery" or a motionless
  device. Every telemetry value is clearly labelled simulated and is derived
  deterministically from the sample's SHA-256 so a demo is reproducible.

* It derives **plausible runtime API-call sequences** from the static features
  and anti-evasion findings already extracted. These are hypotheses about what
  the sample *would* do, grounded in symbols actually present in the bytecode --
  never a claim that the code path ran.

The ``dynamic_indicators`` it returns are lowercase tokens that feed straight into
``backend.scoring.calculate_risk_score`` alongside the static indicators, so the
behavioural layer contributes to the final composite score.
"""
from __future__ import annotations

import hashlib
import random

DISCLAIMER = (
    "SIMULATED dynamic analysis. The APK was NOT executed. Telemetry is synthetic "
    "and behavioural sequences are hypotheses derived from static symbols present "
    "in the sample, not observed runtime execution."
)


def _seed_rng(seed_hex: str) -> random.Random:
    """A deterministic RNG seeded from the sample hash (reproducible demos)."""
    return random.Random(int(seed_hex[:16], 16))


def generate_mock_telemetry(seed_hex: str, duration_s: int = 10) -> dict:
    """Produce synthetic sensor telemetry that defeats common sandbox detection.

    Deterministic for a given ``seed_hex`` so the same specimen always yields the
    same telemetry stream.
    """
    rng = _seed_rng(seed_hex)

    # Accelerometer: small jitter around gravity on each axis -> "device is being
    # held by a moving human", not a frozen emulator reading (0,0,9.81) forever.
    accelerometer = []
    for i in range(duration_s):
        accelerometer.append({
            "t": i,
            "x": round(rng.uniform(-1.5, 1.5), 3),
            "y": round(rng.uniform(-1.5, 1.5), 3),
            "z": round(9.81 + rng.uniform(-0.8, 0.8), 3),
        })

    # Battery: a believable, variable drain from a non-100% start. Emulators that
    # report a pinned 100% / charging state are a classic sandbox tell.
    start = rng.randint(61, 93)
    battery = []
    level = float(start)
    for i in range(duration_s):
        level = max(1.0, level - rng.uniform(0.1, 0.6))
        battery.append({"t": i, "level": round(level, 2), "charging": False})

    # Touch / scroll: synthetic gesture stream so UI-gated payloads unlock.
    gestures = ["tap", "scroll_down", "scroll_up", "swipe_left", "swipe_right", "long_press"]
    touch_events = []
    for i in range(duration_s):
        touch_events.append({
            "t": i,
            "gesture": rng.choice(gestures),
            "x": rng.randint(0, 1080),
            "y": rng.randint(0, 2340),
        })

    log = [
        f"[⚡] Injecting mock accelerometer data ({len(accelerometer)} samples, simulated hand motion)",
        f"[⚡] Simulating variable battery drain ({start}% → {battery[-1]['level']}%, discharging)",
        f"[⚡] Feeding synthetic touch and scroll events ({len(touch_events)} gestures)",
    ]
    return {
        "simulated": True,
        "duration_s": duration_s,
        "accelerometer": accelerometer,
        "battery": battery,
        "touch_events": touch_events,
        "log": log,
    }


# Each rule maps a set of required static signals to a behaviour hypothesis with a
# plausible API-call sequence and a scoring indicator. ``perms`` matches against
# requested permission names (suffix match); ``apis`` against suspicious API strings.
def _has_perm(perm_names: set[str], needle: str) -> bool:
    return any(needle in p for p in perm_names)


def derive_behavioral_sequences(static_features: dict, anti_evasion: dict | None = None) -> list[dict]:
    """Build runtime API-call-sequence hypotheses from static evidence."""
    anti_evasion = anti_evasion or {}
    perms = {p["name"] for p in static_features.get("permissions", []) if isinstance(p, dict)}
    apis = set(static_features.get("suspicious_apis", []))
    dcl = anti_evasion.get("dynamic_code_loading", {}).get("detected", False)

    behaviours: list[dict] = []

    # 1. Overlay + accessibility abuse (banking-trojan signature).
    if (_has_perm(perms, "SYSTEM_ALERT_WINDOW") or "addView" in apis) and \
       (_has_perm(perms, "BIND_ACCESSIBILITY_SERVICE") or "AccessibilityService" in apis):
        behaviours.append({
            "name": "Overlay injection under accessibility control",
            "severity": "CRITICAL",
            "indicator": "overlay_accessibility_abuse",
            "api_sequence": [
                "AccessibilityService.onServiceConnected()",
                "WindowManager.addView(type=TYPE_APPLICATION_OVERLAY)",
                "AccessibilityEvent.getSource() [reading foreground app node tree]",
                "AccessibilityNodeInfo.performAction(ACTION_CLICK)",
            ],
            "rationale": "Reads the active app's accessibility node hierarchy while an overlay window is shown -- the classic credential-capture pattern.",
        })

    # 2. SMS interception / exfiltration.
    if (_has_perm(perms, "READ_SMS") or _has_perm(perms, "RECEIVE_SMS") or "sendTextMessage" in apis):
        behaviours.append({
            "name": "SMS interception and exfiltration",
            "severity": "HIGH",
            "indicator": "sms_exfiltration",
            "api_sequence": [
                "BroadcastReceiver.onReceive(SMS_RECEIVED)",
                "SmsMessage.createFromPdu()",
                "SmsMessage.getMessageBody()",
                "HttpURLConnection.getOutputStream() [to C2]",
            ],
            "rationale": "Intercepts inbound SMS (incl. OTPs) and has the network primitives to relay them.",
        })

    # 3. Dynamic code loading as a C2-staged payload.
    if dcl or {"DexClassLoader", "PathClassLoader", "loadDex"} & apis:
        behaviours.append({
            "name": "Dynamic code loading of a remote payload",
            "severity": "HIGH",
            "indicator": "dynamic_code_loading",
            "api_sequence": [
                "HttpURLConnection.getInputStream() [fetch encrypted stage-2]",
                "Cipher.doFinal() [decrypt payload]",
                "DexClassLoader.loadClass()",
                "java.lang.reflect.Method.invoke()",
            ],
            "rationale": "Fetches, decrypts and reflectively loads code not present at install time -- defeats static-only review.",
        })

    # 4. Device fingerprinting / reconnaissance.
    if {"getDeviceId", "getSubscriberId", "getLine1Number", "TelephonyManager"} & apis:
        behaviours.append({
            "name": "Device and subscriber fingerprinting",
            "severity": "MEDIUM",
            "indicator": "device_fingerprinting",
            "api_sequence": [
                "TelephonyManager.getDeviceId()",
                "TelephonyManager.getSubscriberId()",
                "TelephonyManager.getLine1Number()",
            ],
            "rationale": "Harvests IMEI/IMSI/MSISDN identifiers for victim tracking.",
        })

    # 5. Arbitrary command execution.
    if "Runtime;->exec" in apis:
        behaviours.append({
            "name": "Native command execution",
            "severity": "HIGH",
            "indicator": "runtime_command_execution",
            "api_sequence": [
                "Runtime.getRuntime().exec()",
                "Process.getInputStream()",
            ],
            "rationale": "Spawns shell commands from within the app process.",
        })

    return behaviours


def detect_anti_sandbox_techniques(telemetry: dict) -> list[dict]:
    """Report which emulator-detection checks the mock telemetry neutralises."""
    battery = telemetry.get("battery", [])
    varies = len({round(b["level"]) for b in battery}) > 1 if battery else False
    accel = telemetry.get("accelerometer", [])
    moves = any(abs(a["x"]) > 0.05 or abs(a["y"]) > 0.05 for a in accel) if accel else False
    touches = bool(telemetry.get("touch_events"))
    return [
        {"check": "SensorManager.getDefaultSensor(ACCELEROMETER) motion", "defeated": moves,
         "how": "Non-zero, time-varying accelerometer samples simulate a held device."},
        {"check": "BatteryManager stuck-level / always-charging", "defeated": varies,
         "how": "Discharging, non-100% battery curve defeats the 'perfect battery' heuristic."},
        {"check": "Absence of user interaction", "defeated": touches,
         "how": "Synthetic touch/scroll stream unlocks UI-gated payloads."},
    ]


def simulate(contents: bytes, static_features: dict, anti_evasion: dict | None = None,
             *, case_id: str | None = None, duration_s: int = 10) -> dict:
    """Run the full simulated dynamic analysis for one specimen.

    Returns a court-/demo-ready report. ``dynamic_indicators`` is the list of
    behavioural tokens to pass to the risk scorer.
    """
    sha256 = static_features.get("sha256") or hashlib.sha256(contents).hexdigest()
    telemetry = generate_mock_telemetry(sha256, duration_s=duration_s)
    behaviours = derive_behavioral_sequences(static_features, anti_evasion)
    evasions = detect_anti_sandbox_techniques(telemetry)

    dynamic_indicators = sorted({b["indicator"] for b in behaviours})

    summary = (
        f"Simulated {duration_s}s dynamic session: "
        f"{len(behaviours)} behavioural flag(s), "
        f"{sum(1 for e in evasions if e['defeated'])}/{len(evasions)} anti-sandbox check(s) neutralised."
    )

    return {
        "simulated": True,
        "disclaimer": DISCLAIMER,
        "case_id": case_id,
        "sha256": sha256,
        "seed": sha256[:16],
        "telemetry": telemetry,
        "telemetry_log": telemetry["log"],
        "api_call_sequences": [
            {"behaviour": b["name"], "severity": b["severity"], "sequence": b["api_sequence"]}
            for b in behaviours
        ],
        "behavioral_flags": behaviours,
        "anti_sandbox_evasions_defeated": evasions,
        "dynamic_indicators": dynamic_indicators,
        "summary": summary,
    }
