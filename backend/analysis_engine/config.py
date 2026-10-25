"""Central configuration for the SENTINEL-CRS analysis engine (AI/ML Engineer 2 modules).

Everything here is overridable via environment variables so tests and deployments
can redirect storage without touching code. Paths default to the same relative
locations the existing backend already uses (CWD == backend/).
"""
import os

# --- Storage -----------------------------------------------------------------
# Reuse the existing SQLite database file so there is a single chain-of-custody store.
DB_PATH = os.environ.get("SENTINEL_DB_PATH", os.path.join("database", "sentinel_audit.db"))

# Directory where generated evidence reports are written.
REPORTS_DIR = os.environ.get("SENTINEL_REPORTS_DIR", "reports")

# --- Similarity --------------------------------------------------------------
# Default cosine-similarity threshold above which two APKs are reported as "similar".
# Configurable; documented in the module docstring and the handoff notes.
SIMILARITY_THRESHOLD = float(os.environ.get("SENTINEL_SIMILARITY_THRESHOLD", "0.80"))

# Minimum number of persisted feature vectors required before DBSCAN clustering is
# attempted. Below this, similarity is reported pairwise only (clustering is skipped).
MIN_VECTORS_FOR_CLUSTERING = int(os.environ.get("SENTINEL_MIN_CLUSTER_VECTORS", "4"))

# --- Tooling / provenance ----------------------------------------------------
TOOL_NAME = "SENTINEL-CRS-analysis-engine"
TOOL_VERSION = "2.0.0"

# Neutral product branding for generated reports. Do NOT substitute official
# government/police emblems or endorsement text unless explicitly authorized.
REPORT_BRAND = os.environ.get("SENTINEL_REPORT_BRAND", "SENTINEL-CRS")
