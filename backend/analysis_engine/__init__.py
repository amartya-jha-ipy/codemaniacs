"""SENTINEL-CRS analysis engine (AI/ML Engineer 2).

Isolated, reusable modules for static feature similarity, IOC matching, and the
evidence report pipeline. Importable as ``analysis_engine`` when the backend is run
from the ``backend/`` directory (matching the existing ``main.py`` import style).
"""
from . import (audit_trail, config, evidence_report, feature_extractor,
               ioc_service, similarity, store)

__all__ = [
    "config", "store", "feature_extractor", "similarity", "ioc_service",
    "evidence_report", "audit_trail",
]
