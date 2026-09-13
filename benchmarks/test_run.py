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


def test_wait_for_completion_grace_and_min_stable_wait_out_a_batched_sink_write():
    # §25.2 under-count guard: 'b' reads 0 twice (forwarder's batched OpenSearch write in flight)
    # then delivers 5 and holds. grace + min_stable=3 must NOT settle at the transient 0.
    seq = {"a": [4, 4, 4, 4, 4], "b": [0, 0, 5, 5, 5]}
    calls = {"a": 0, "b": 0}

    def count(idx):
        v = seq[idx][min(calls[idx], len(seq[idx]) - 1)]
        calls[idx] += 1
        return v
    graced = {"n": 0}
    got = run.wait_for_completion("http://x", required=["a"], optional=["b"], tries=8,
                                  count=count, sleep=lambda _s: graced.__setitem__("n", graced["n"] + 1),
                                  grace=20, min_stable=3)
    assert got == {"a": 4, "b": 5}, "settled on the transient empty sink instead of the delivered count"
    assert graced["n"] >= 1, "grace wait was not applied before the first poll"


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


# §24.2: reconciliation requires the COMPLETE expected inventory to report a valid outcome; an
# absent/null/unparsable status is unknown, never success. Tests pin explicit small inventories.
_P = ("suricata-offline", "arm-b-feeder")
_G = ("g1", "g2")


def test_classify_completion_reconciled():
    c = run.classify_completion({"suricata-offline": 0, "arm-b-feeder": 0}, {"g1": 0, "g2": 0},
                                {"arm-a-suricata": 100}, expected_producers=_P, expected_groups=_G)
    assert c["state"] == "inputs_drained" and c["unresolved"] == []   # §25.2: not "reconciled" (no downstream acks yet)


def test_classify_completion_invalid_when_a_producer_fails():
    c = run.classify_completion({"suricata-offline": 1, "arm-b-feeder": 0}, {"g1": 0, "g2": 0},
                                {"arm-a-suricata": 100}, expected_producers=_P, expected_groups=_G)
    assert c["state"] == "invalid"


def test_classify_completion_inconclusive_cases():
    def cc(pe, gl, ac):
        return run.classify_completion(pe, gl, ac, expected_producers=_P, expected_groups=_G)["state"]
    assert cc({"suricata-offline": 0, "arm-b-feeder": 0}, {"g1": 5, "g2": 0}, {"arm-a-suricata": 100}) == "inconclusive"  # lag
    assert cc({"suricata-offline": 0, "arm-b-feeder": 0}, {"g1": 0, "g2": 0}, {"arm-a-suricata": 0}) == "inconclusive"    # baseline empty
    assert cc({"suricata-offline": 0, "arm-b-feeder": 0}, {}, {"arm-a-suricata": 100}) == "inconclusive"                 # drain unverified


def test_classify_completion_rejects_incomplete_or_unknown_inventory():
    # §24.2 adversarial battery: the reproduced false reconciliations must now be inconclusive.
    def cc(pe, gl):
        return run.classify_completion(pe, gl, {"arm-a-suricata": 100},
                                       expected_producers=_P, expected_groups=_G)["state"]
    assert cc({}, {"g1": 0, "g2": 0}) == "inconclusive"                              # empty producer dict
    assert cc({"suricata-offline": None, "arm-b-feeder": 0}, {"g1": 0, "g2": 0}) == "inconclusive"  # null status
    assert cc({"suricata-offline": 0}, {"g1": 0, "g2": 0}) == "inconclusive"         # missing producer
    assert cc({"suricata-offline": 0, "arm-b-feeder": 0}, {"g1": 0}) == "inconclusive"  # missing expected group
    assert cc({"suricata-offline": 0, "arm-b-feeder": 0}, {"g1": None, "g2": 0}) == "inconclusive"  # unparsable lag
    # a real non-zero exit still dominates as invalid even amid unknowns
    assert cc({"suricata-offline": 2}, {"g1": 0, "g2": 0}) == "invalid"


def test_wait_for_drain_returns_when_lag_stable_zero():
    seq = [{"g": 3}, {"g": 0}, {"g": 0}]
    i = {"n": 0}

    def lag_fn():
        v = seq[min(i["n"], len(seq) - 1)]
        i["n"] += 1
        return v
    assert run.wait_for_drain("p", tries=5, sleep=lambda _s: None, lag_fn=lag_fn) == {"g": 0}


def _spec(required=("redpanda", "ndr-finding-service"), rid="r1"):
    return run.build_run_spec("s", rid, {"images": {}, "inputs": {}},
                              required_services=required, required_groups=("g",))


def test_run_spec_preflight_passes_complete_topology():
    run.preflight_run_spec(_spec(), running_services=["redpanda", "ndr-finding-service", "opensearch"])


def test_run_spec_preflight_fails_missing_required_service():
    try:
        run.preflight_run_spec(_spec(), running_services=["redpanda"])   # finding-service absent
        assert False, "must abort before production on a missing required service"
    except SystemExit as e:
        assert "ndr-finding-service" in str(e)


def test_run_spec_preflight_fails_empty_required_set():
    # a spec that declares nothing required would silently accept any topology
    try:
        run.preflight_run_spec(_spec(required=()), running_services=["redpanda"])
        assert False, "empty required set must fail"
    except SystemExit:
        pass


def test_run_spec_preflight_refuses_to_clobber_existing_output():
    try:
        run.preflight_run_spec(_spec(), running_services=["redpanda", "ndr-finding-service"],
                               output_exists=True)                       # reused run dir / id
        assert False, "must refuse to overwrite an existing scored run"
    except SystemExit as e:
        assert "overwrite" in str(e).lower()
    # explicit overwrite is allowed
    run.preflight_run_spec(_spec(), running_services=["redpanda", "ndr-finding-service"],
                           output_exists=True, overwrite=True)


def test_run_ids_are_unique():
    assert run._run_id() != run._run_id()


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


def test_score_from_export_reconciles_with_live_scoring():
    # R4/§20.3+§21.4: the report is computed FROM the exported files. Scoring the same docs
    # in-memory (as run_full does with the export snapshot) and re-reading them off disk must
    # produce identical metrics — otherwise a published number can't be reproduced from out/.
    import json
    arm_a = [{"event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "203.0.113.66",
              "alert": {"signature": "ET beacon"}}]
    arm_b = [{"finding_id": "f1", "behavior": "c2",
              "entities": [{"value": "10.0.0.5", "type": "ip", "role": "initiator"},
                           {"value": "203.0.113.66", "type": "ip", "role": "target"}]}]
    labels = {"malicious": ["10.0.0.5"], "granularity": "host",
              "episodes": [{"id": "A", "label": "malicious", "behavior": "c2",
                            "entities": [{"value": "10.0.0.5", "role": "initiator"},
                                         {"value": "203.0.113.66", "role": "target"}]}]}
    live = run._score_arms(arm_a, arm_b, [], labels, {"scenario": "t", "granularity": "per-host"})

    with tempfile.TemporaryDirectory() as d:
        od = os.path.join(d, "out", "t", "output")
        os.makedirs(od)
        for fname, docs in (("suricata-alerts.jsonl", arm_a), ("cernity-findings.jsonl", arm_b),
                            ("zeek-notices.jsonl", [])):
            with open(os.path.join(od, fname), "w") as f:
                for x in docs:
                    f.write(json.dumps(x) + "\n")
        ds = os.path.join(d, "datasets", "t")
        os.makedirs(ds)
        with open(os.path.join(ds, "labels.json"), "w") as f:
            json.dump(labels, f)
        saved = run.DATASETS
        run.DATASETS = os.path.join(d, "datasets")
        try:
            recomputed = run.score_from_export(os.path.join(d, "out", "t"), "t")
        finally:
            run.DATASETS = saved

    assert recomputed["episode_scoring"] == live["episode_scoring"], "episode metrics not reproducible from files"
    assert recomputed["arms"] == live["arms"], "arm metrics not reproducible from files"


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
