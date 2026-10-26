"""Seed demonstration indicators so the sample malicious APK lights up IOC matches.

Run once after installing dependencies (from anywhere):

    python backend/seed_demo.py

It loads the local IOC database with the C2 IP, domain and the SHA-256 of
``samples/ANVESH_demo_malicious.apk`` (all clearly tagged SYNTHETIC-DEMO-FIXTURE),
so uploading that specimen in the console shows a known-malicious-hash match.
These are synthetic fixtures for the demo only — not real threat intelligence.
"""
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

# Point the engine at the backend's database regardless of the current directory.
os.environ.setdefault("SENTINEL_DB_PATH", os.path.join(HERE, "database", "sentinel_audit.db"))
sys.path.insert(0, HERE)

from analysis_engine import ioc_service  # noqa: E402

SRC = "SYNTHETIC-DEMO-FIXTURE"


def main():
    ioc_service.initialize_ioc_database()
    ioc_service.add_ioc("ip", "185.220.101.5", SRC,
                        {"threat_category": "android_banking_trojan_c2", "confidence": "high"})
    ioc_service.add_ioc("domain", "evil-c2.example.com", SRC,
                        {"threat_category": "android_banking_trojan_c2", "confidence": "high"})

    sample = os.path.join(REPO, "samples", "ANVESH_demo_malicious.apk")
    if os.path.exists(sample):
        with open(sample, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        ioc_service.add_ioc("sha256", digest, SRC,
                            {"threat_category": "android_banking_trojan", "confidence": "high"})
        print(f"Seeded malicious sample hash: {digest}")
    else:
        print("Note: samples/ANVESH_demo_malicious.apk not found; seeded IP + domain only.")

    print(f"IOC database now holds {ioc_service.count_iocs()} indicator(s).")


if __name__ == "__main__":
    main()
