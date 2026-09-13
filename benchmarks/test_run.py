"""U12/F10: the benchmark must SUBSTANTIATE what it reports — page past 10k, fail loudly
on a query/engine error (never score a silent empty arm), wait for ingestion to settle,
and hash the real engine outputs. No OpenSearch/Docker: fetch/count/sleep are injected.

  python3 test_run.py
"""
import os
import tempfile

import run


def test_os_search_paginates_past_a_single_page():
    # 25 docs across pages of 10 via search_after — the old size=10000 truncated silently.
    docs = [{"_source": {"i": i}, "sort": [i]} for i in range(25)]

    def fetch(endpoint, index, body):
        after = body.get("search_after")
        start = (after[0] + 1) if after else 0
        return docs[start:start + body["size"]]

    got = run.os_search("http://x", "idx", page=10, fetch=fetch)
    assert [d["i"] for d in got] == list(range(25)), "pagination lost or duplicated docs"


def test_os_search_strict_raises_on_query_error():
    def boom(*_a):
        raise RuntimeError("engine 503")
    try:
        run.os_search("http://x", "idx", fetch=boom, strict=True)
        assert False, "strict os_search must raise, not return an empty arm"
    except RuntimeError as e:
        assert "idx" in str(e)
    # non-strict degrades to partial (used only by the wait poller)
    assert run.os_search("http://x", "idx", fetch=boom, strict=False) == []


def test_wait_for_completion_returns_counts_with_valid_empty_optional():
    # baseline 'a' arrives and stabilises; optional 'b' stays empty -> a VALID completion
    # (benign scenario / real miss), returning the counts rather than raising.
    seq = {"a": [0, 3, 3], "b": [0, 0, 0]}
    calls = {"a": 0, "b": 0}

    def count(idx):
        v = seq[idx][min(calls[idx], len(seq[idx]) - 1)]
        calls[idx] += 1
        return v
    got = run.wait_for_completion("http://x", required=["a"], optional=["b"],
                                  tries=5, count=count, sleep=lambda _s: None)
    assert got == {"a": 3, "b": 0}


def test_wait_for_completion_raises_when_baseline_never_arrives():
    # an empty baseline means telemetry never shipped: a broken run, not zero detections.
    try:
        run.wait_for_completion("http://x", required=["a"], optional=["b"], tries=3,
                                count=lambda _i: 0, sleep=lambda _s: None)
        assert False, "empty baseline must raise"
    except RuntimeError:
        pass


def test_manifest_drift_flags_changed_and_missing_only():
    cur = {"redpanda": {"image_id": "sha256:aaa"}, "finding-service": {"image_id": "sha256:bbb"}}
    pin = {"images": {"redpanda": {"image_id": "sha256:aaa"},          # matches -> not flagged
                      "finding-service": {"image_id": "sha256:OLD"},   # changed
                      "forwarder": {"image_id": "sha256:ccc"}}}        # absent in current
    assert {d["service"] for d in run.manifest_drift(cur, pin)} == {"finding-service", "forwarder"}


def test_manifest_drift_empty_when_identical():
    imgs = {"a": {"image_id": "1"}, "b": {"image_id": "2"}}
    assert run.manifest_drift(imgs, {"images": imgs}) == []


def test_sha256_matches_hashlib():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"cernity-benchmark")
        path = f.name
    try:
        import hashlib
        assert run._sha256(path) == hashlib.sha256(b"cernity-benchmark").hexdigest()
    finally:
        os.unlink(path)


def test_classify_completion_reconciled():
    c = run.classify_completion({"suricata-offline": 0, "arm-b-feeder": 0}, {"g1": 0, "g2": 0},
                                {"arm-a-suricata": 100})
    assert c["state"] == "reconciled" and c["unresolved"] == []


def test_classify_completion_invalid_when_a_producer_fails():
    c = run.classify_completion({"suricata-offline": 1}, {"g1": 0}, {"arm-a-suricata": 100})
    assert c["state"] == "invalid"


def test_classify_completion_inconclusive_cases():
    assert run.classify_completion({"s": 0}, {"g": 5}, {"arm-a-suricata": 100})["state"] == "inconclusive"   # lag
    assert run.classify_completion({"s": 0}, {"g": 0}, {"arm-a-suricata": 0})["state"] == "inconclusive"     # baseline empty
    assert run.classify_completion({"s": 0}, {}, {"arm-a-suricata": 100})["state"] == "inconclusive"         # drain unverified


def test_wait_for_drain_returns_when_lag_stable_zero():
    seq = [{"g": 3}, {"g": 0}, {"g": 0}]
    i = {"n": 0}

    def lag_fn():
        v = seq[min(i["n"], len(seq) - 1)]
        i["n"] += 1
        return v
    assert run.wait_for_drain("p", tries=5, sleep=lambda _s: None, lag_fn=lag_fn) == {"g": 0}


def test_preflight_aborts_on_foreign_container():
    # a fixed container name already present (a real deployment) must abort, never attach (§3)
    try:
        run.preflight_no_foreign_containers(names=["cernity-redpanda"], exists=lambda _n: True)
        assert False, "must abort on collision"
    except SystemExit as e:
        assert "cernity-redpanda" in str(e)


def test_preflight_passes_when_no_collision():
    run.preflight_no_foreign_containers(names=["cernity-redpanda", "cernity-finding-service"],
                                        exists=lambda _n: False)   # no raise


def test_wait_for_completion_raises_when_never_stable():
    # counts still changing (still ingesting) must RAISE, never be scored as a settled zero.
    n = {"a": 0}

    def count(_i):
        n["a"] += 1
        return n["a"]
    try:
        run.wait_for_completion("http://x", required=["a"], tries=3,
                                count=count, sleep=lambda _s: None)
        assert False, "a never-settling run must raise"
    except RuntimeError:
        pass


def test_eve_paths_hashes_real_outputs():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "eve.json"), "w") as f:
            f.write('{"event_type":"alert"}\n')
        os.environ["BENCH_EVE_DIR"] = d
        try:
            assert run._eve_paths(), "real engine outputs not discovered for the determinism hash"
            h1 = run.determinism_hash(*run._eve_paths())
            assert h1 and h1 == run.determinism_hash(*run._eve_paths())   # stable
        finally:
            del os.environ["BENCH_EVE_DIR"]
    assert run._eve_paths() == []                    # unset -> nothing (honest, not a fake hash)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} benchmark run tests passed")
