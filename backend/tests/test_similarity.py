from analysis_engine import similarity, store


def _findings(perms, apis, net=True):
    return {
        "sha256": "0" * 64,
        "filename": "x.apk",
        "permissions": [{"name": p, "level": "Info"} for p in perms],
        "suspicious_apis": list(apis),
        "urls": ["http://a.example.com"] if net else [],
        "ips": [], "domains": ["a.example.com"] if net else [],
    }


def test_extract_feature_vector_is_namespaced_and_sorted():
    tokens = similarity.extract_feature_vector(_findings(["android.permission.READ_SMS"], ["getDeviceId"]))
    assert "perm:android.permission.READ_SMS" in tokens
    assert "api:getDeviceId" in tokens
    assert "net:has_urls" in tokens
    assert tokens == sorted(tokens)


def test_identical_vectors_score_one():
    a = similarity.extract_feature_vector(_findings(["p1", "p2"], ["s1"]))
    assert similarity.calculate_similarity(a, a) == 1.0


def test_partial_overlap_between_zero_and_one():
    a = similarity.extract_feature_vector(_findings(["p1", "p2"], ["s1"]))
    b = similarity.extract_feature_vector(_findings(["p1", "p3"], ["s1"]))
    score = similarity.calculate_similarity(a, b)
    assert 0.0 < score < 1.0


def test_disjoint_vectors_score_zero():
    a = similarity.extract_feature_vector(_findings(["p1"], ["s1"], net=False))
    b = similarity.extract_feature_vector(_findings(["p2"], ["s2"], net=False))
    assert similarity.calculate_similarity(a, b) == 0.0


def test_empty_vectors_score_zero():
    assert similarity.calculate_similarity([], ["perm:x"]) == 0.0
    assert similarity.calculate_similarity([], []) == 0.0


def test_find_similar_apks_insufficient_data():
    aid = store.save_analysis("a" * 64, "only.apk", _findings(["p1"], ["s1"]))
    similarity.persist_feature_vector(aid, _findings(["p1"], ["s1"]))
    result = similarity.find_similar_apks(aid)
    assert result["total_compared"] == 0
    assert result["similar"] == []
    assert "disclaimer" in result


def test_find_similar_apks_matches_above_threshold():
    f = _findings(["p1", "p2", "p3"], ["s1", "s2"])
    aid1 = store.save_analysis("a" * 64, "one.apk", f)
    similarity.persist_feature_vector(aid1, f)
    aid2 = store.save_analysis("b" * 64, "two.apk", f)
    similarity.persist_feature_vector(aid2, f)

    result = similarity.find_similar_apks(aid1, threshold=0.5)
    assert result["total_compared"] == 1
    assert len(result["similar"]) == 1
    match = result["similar"][0]
    assert match["analysis_id"] == aid2
    assert match["score"] == 1.0
    assert match["shared_features"]


def test_clustering_skipped_when_too_few_vectors():
    f = _findings(["p1"], ["s1"])
    aid = store.save_analysis("a" * 64, "one.apk", f)
    similarity.persist_feature_vector(aid, f)
    assert similarity.cluster_corpus() is None
