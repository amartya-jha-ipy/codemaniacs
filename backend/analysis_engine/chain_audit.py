"""Bridge to the tamper-evident HMAC audit chain (``database/audit_log.py``).

The live backend runs with its working directory at ``backend/``, where the name
``database`` already resolves to ``backend/database.py``. The hash-chained,
append-only audit log lives in the *repo-root* ``database/`` package, so we load it
by file path to avoid the name clash.

Every function here is defensive: if the chain module cannot be loaded, or
``AUDIT_LOG_KEY`` is not set, the helpers return ``None`` and record a note rather
than raising -- a missing forensic key must never take down the analysis request,
and a key is never fabricated for an evidential log.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from functools import lru_cache
from typing import Any, Optional

# backend/analysis_engine/chain_audit.py -> repo root is three levels up.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_AUDIT_LOG_PATH = os.path.join(_REPO_ROOT, "database", "audit_log.py")


@lru_cache(maxsize=1)
def _load_chain_module():
    """Import repo-root database/audit_log.py by path. Returns the module or None."""
    try:
        spec = importlib.util.spec_from_file_location("sentinel_chain_audit", _AUDIT_LOG_PATH)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        # Register before exec: the frozen @dataclass in audit_log.py resolves its
        # own module via sys.modules during class creation.
        sys.modules.setdefault("sentinel_chain_audit", module)
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


def is_available(key: Optional[str] = None) -> bool:
    """True when the chain module loads and an HMAC key of sufficient length exists."""
    mod = _load_chain_module()
    if mod is None:
        return False
    try:
        mod.load_key(key)
        return True
    except Exception:
        return False


def append_stage(case_id: str, stage: str, payload: dict[str, Any], *,
                 key: Optional[str] = None, db_path: Optional[str] = None) -> Optional[dict]:
    """Append one stage entry to the immutable chain.

    Returns a small dict describing the new entry (id, stage, entry_hash), or
    ``None`` if the chain is unavailable / unkeyed. Never raises on the live path.
    """
    mod = _load_chain_module()
    if mod is None:
        return None
    try:
        mod.load_key(key)  # fail fast (and quietly) if no usable key
    except Exception:
        return None

    path = db_path or os.environ.get(
        "SENTINEL_DB_PATH", os.path.join("database", "sentinel_audit.db")
    )
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    import sqlite3

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        mod.init_audit_log(conn)
        entry = mod.append_entry(conn, key, case_id, stage, payload)
        return {
            "id": entry.id,
            "stage": entry.stage,
            "ts": entry.ts,
            "entry_hash": entry.entry_hash,
            "prev_hash": entry.prev_hash,
        }
    except Exception:
        return None
    finally:
        conn.close()
