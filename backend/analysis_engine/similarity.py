"""Static-feature similarity and (optional) clustering for analysed APKs.

Approach
--------
Each APK is reduced to a *set of feature tokens* derived from its static findings:
permissions, suspicious-API signatures, and coarse network-indicator flags. Two
APKs are compared with **cosine similarity** over binary multi-hot vectors (which,
for binary vectors, equals ``|A ∩ B| / sqrt(|A|·|B|)``). This needs no fixed global
vocabulary and degrades gracefully when features are missing.

Clustering is attempted **only** when enough feature vectors exist
(``config.MIN_VECTORS_FOR_CLUSTERING``). It builds a TF-IDF representation of the
per-APK token documents and runs DBSCAN on the cosine distance matrix. The chosen
``eps``/``min_samples`` are documented on ``cluster_corpus``.

Important limitation (surfaced to callers and reports): static similarity reflects
shared characteristics only. It does **not** establish common authorship, a shared
build toolchain, or membership of the same cybercrime group.

The similarity threshold defaults to ``config.SIMILARITY_THRESHOLD`` (0.80) and is
configurable via the ``SENTINEL_SIMILARITY_THRESHOLD`` environment variable or the
``threshold`` argument.
"""
import json
import math

from . import config, store

_DISCLAIMER = (
    "Similarity reflects shared static characteristics only. It does not establish "
    "common authorship, a shared build toolchain, or membership of the same group."
)


def extract_feature_vector(findings):
    """Convert a findings dict into a stable, order-independent token set.

    Tokens are namespaced so different feature kinds never collide:
      perm:<permission name> · api:<signature> · net:has_urls / has_ips / has_domains
    Returns a sorted list (JSON-serialisable and deterministic).
    """
    tokens = set()
    for perm in findings.get("permissions", []) or []:
        name = perm.get("name") if isinstance(perm, dict) else perm
        if name:
            tokens.add("perm:" + name)
    for sig in findings.get("suspicious_apis", []) or []:
        tokens.add("api:" + sig)
    if findings.get("urls"):
        tokens.add("net:has_urls")
    if findings.get("ips"):
        tokens.add("net:has_ips")
    if findings.get("domains"):
        tokens.add("net:has_domains")
    return sorted(tokens)


def calculate_similarity(features_a, features_b):
    """Cosine similarity between two token collections. Returns a float in [0, 1].

    Empty input yields 0.0 (an empty vector cannot be meaningfully similar).
    """
    set_a, set_b = set(features_a or []), set(features_b or [])
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    denom = math.sqrt(len(set_a)) * math.sqrt(len(set_b))
    return round(intersection / denom, 4) if denom else 0.0


def persist_feature_vector(analysis_id, findings, db_path=None):
    """Store the token vector for an analysis so future APKs can be compared to it."""
    store.init_schema(db_path)
    tokens = extract_feature_vector(findings)
    conn = store.get_conn(db_path)
    try:
        conn.execute(
            """
            INSERT INTO feature_vectors (analysis_id, sha256, filename, tokens, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(analysis_id) DO UPDATE SET tokens=excluded.tokens
            """,
            (analysis_id, findings.get("sha256"), findings.get("filename"),
             json.dumps(tokens), store.utc_now()),
        )
        conn.commit()
    finally:
        conn.close()
    return tokens


def _load_vectors(db_path=None):
    conn = store.get_conn(db_path)
    try:
        rows = conn.execute(
            "SELECT analysis_id, sha256, filename, tokens FROM feature_vectors"
        ).fetchall()
    finally:
        conn.close()
    return [
        {
            "analysis_id": r["analysis_id"],
            "sha256": r["sha256"],
            "filename": r["filename"],
            "tokens": json.loads(r["tokens"]),
        }
        for r in rows
    ]


def find_similar_apks(analysis_id, threshold=None, db_path=None):
    """Find previously analysed APKs similar to ``analysis_id``.

    Returns a dict with the matches (score, shared features, differing features),
    the comparison count, and the non-attribution disclaimer. Handles the
    insufficient-data case (no other vectors) gracefully.
    """
    store.init_schema(db_path)
    if threshold is None:
        threshold = config.SIMILARITY_THRESHOLD

    vectors = _load_vectors(db_path)
    target = next((v for v in vectors if v["analysis_id"] == analysis_id), None)
    result = {
        "analysis_id": analysis_id,
        "threshold": threshold,
        "total_compared": 0,
        "similar": [],
        "clustering": None,
        "disclaimer": _DISCLAIMER,
    }
    if target is None:
        result["note"] = "No feature vector stored for this analysis."
        return result
    if target["tokens"] == []:
        result["note"] = "Feature vector is empty; no comparable static features were extracted."

    others = [v for v in vectors if v["analysis_id"] != analysis_id]
    result["total_compared"] = len(others)
    target_set = set(target["tokens"])

    matches = []
    for other in others:
        score = calculate_similarity(target["tokens"], other["tokens"])
        if score >= threshold:
            other_set = set(other["tokens"])
            matches.append({
                "analysis_id": other["analysis_id"],
                "sha256": other["sha256"],
                "filename": other["filename"],
                "score": score,
                "shared_features": sorted(target_set & other_set),
                "differing_features": sorted(target_set ^ other_set),
            })
    matches.sort(key=lambda m: m["score"], reverse=True)
    result["similar"] = matches

    # Only attach a clustering label if clustering was actually performed.
    clustering = cluster_corpus(db_path=db_path)
    if clustering is not None:
        result["clustering"] = {
            "label": clustering["labels"].get(analysis_id),
            "params": clustering["params"],
            "note": "Label -1 denotes an outlier not assigned to any cluster.",
        }
    return result


def cluster_corpus(eps=0.30, min_samples=2, db_path=None):
    """Cluster all stored feature vectors with DBSCAN over cosine distance.

    Returns ``None`` when there are too few vectors to justify clustering
    (``config.MIN_VECTORS_FOR_CLUSTERING``) or when the vectors share no tokens.
    ``eps=0.30`` on cosine distance corresponds to ~0.70 cosine similarity; chosen
    so that members of a cluster are clearly related rather than incidentally
    overlapping. ``min_samples=2`` because forensic corpora are typically small.
    """
    vectors = [v for v in _load_vectors(db_path) if v["tokens"]]
    if len(vectors) < config.MIN_VECTORS_FOR_CLUSTERING:
        return None

    try:
        import numpy as np
        from sklearn.cluster import DBSCAN
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_distances
    except Exception:
        return None

    docs = [" ".join(v["tokens"]) for v in vectors]
    try:
        tfidf = TfidfVectorizer(token_pattern=r"[^ ]+").fit_transform(docs)
    except ValueError:
        # Empty vocabulary (no shared/any tokens) -> clustering not meaningful.
        return None

    distance = cosine_distances(tfidf)
    np.clip(distance, 0, None, out=distance)
    labels = DBSCAN(eps=eps, min_samples=min_samples, metric="precomputed").fit_predict(distance)

    return {
        "labels": {v["analysis_id"]: int(lbl) for v, lbl in zip(vectors, labels)},
        "params": {"algorithm": "DBSCAN", "metric": "cosine", "eps": eps, "min_samples": min_samples},
        "n_vectors": len(vectors),
    }
