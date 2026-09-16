"""U12/F10: the benchmark must SUBSTANTIATE what it reports — page past 10k, fail loudly
on a query/engine error (never score a silent empty arm), wait for ingestion to settle,
and hash the real engine outputs. No OpenSearch/Docker: fetch/count/sleep are injected.

  python3 test_run.py
"""
import json
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


def test_os_search_distinguishes_absent_index_from_query_error():
    # R07: an ABSENT index (404) is a proven-empty arm; a query/engine error is NOT — it must raise even
    # for an optional arm, never silently reading as '0 detections'.
    class _NotFound(Exception):
        code = 404
    def absent(*_a):
        raise _NotFound("index_not_found_exception")
    def engine_error(*_a):
        raise RuntimeError("engine 503")
    assert run.os_search("http://x", "arm-b", fetch=absent, allow_absent=True) == []   # absent -> empty
    try:
        run.os_search("http://x", "arm-b", fetch=engine_error, allow_absent=True)
        assert False, "a query error must raise even when absent is allowed"
    except RuntimeError as e:
        assert "arm-b" in str(e)


def test_score_arms_uses_per_arm_replay_clock():
    # §41 FAIRNESS: only Arm B is fed through the reanchoring feeder, so Arm A (raw pcap clock) is scored
    # with offset 0 and Arm B (replay clock) with the recorded offset. A Suricata alert on the ORIGINAL
    # clock and a Cernity finding on the REPLAY clock must BOTH surface the same timed episode.
    import datetime as _d
    OFF = 5000.0
    def _ts(e): return _d.datetime.fromtimestamp(e, _d.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    ep = {"id": "ep1", "label": "malicious", "behavior": "c2",
          "entities": [{"value": "10.0.0.5", "role": "initiator"}, {"value": "1.2.3.4", "role": "target"}],
          "interval": {"start": 1000.0, "end": 1100.0}}
    labels = {"granularity": "host", "malicious": ["10.0.0.5"], "episodes": [ep]}
    arm_a = [{"event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "1.2.3.4",
              "alert": {"category": "A Network Trojan was detected"},
              "flow": {"start": _ts(1000), "end": _ts(1010)}}]                 # ORIGINAL clock
    arm_b = [{"finding_id": "f1", "category": "c2", "tenant_id": "default", "observed": True,
              "first_seen": _ts(1000 + OFF), "last_seen": _ts(1100 + OFF),     # REPLAY clock (original + OFF)
              "entities": json.dumps([{"type": "ip", "role": "src", "value": "10.0.0.5"},
                                      {"type": "ip", "role": "dst", "value": "1.2.3.4"}])}]
    es = run._score_arms(arm_a, arm_b, [], labels, {"scenario": "t"}, replay_offset=OFF)["episode_scoring"]
    assert es["suricata_siem"]["episode_recall"] == 1.0    # Arm A surfaces on the ORIGINAL clock (offset 0)
    assert es["cernity_siem"]["episode_recall"] == 1.0     # Arm B surfaces on the REPLAY clock (offset OFF)


def test_per_arm_clock_invariance_armc_and_signed_offsets():
    # §43.5 per-arm clock invariance: Arm C (Zeek, original clock) is scored with offset 0; the mapping
    # holds under a NEGATIVE offset and mixed timestamp formats; an untimed baseline detection is
    # ambiguous (identity ok, time unverifiable), not credited and not a false miss.
    import datetime as _d
    def _ts(e, fmt): return _d.datetime.fromtimestamp(e, _d.timezone.utc).strftime(fmt)
    OFF = -3000.0                                                       # NEGATIVE reanchor offset
    ep = {"id": "e", "label": "malicious", "behavior": "recon",
          "entities": [{"value": "10.0.0.5", "role": "initiator"}, {"value": "10.0.0.9", "role": "target"}],
          "interval": {"start": 2000.0, "end": 2100.0}}
    labels = {"granularity": "host", "malicious": ["10.0.0.5"], "episodes": [ep]}
    # Arm C zeek notice on the ORIGINAL clock, compact +0000 offset
    arm_c = [{"src_ip": "10.0.0.5", "dest_ip": "10.0.0.9", "note": "recon",
              "ts": _ts(2050, "%Y-%m-%dT%H:%M:%S.%f+0000")}]
    # Arm B finding on the REPLAY clock (original + negative OFF), Z format
    arm_b = [{"finding_id": "f", "category": "recon", "tenant_id": "default", "observed": True,
              "first_seen": _ts(2000 + OFF, "%Y-%m-%dT%H:%M:%S.%fZ"), "last_seen": _ts(2100 + OFF, "%Y-%m-%dT%H:%M:%S.%fZ"),
              "entities": json.dumps([{"type": "ip", "role": "src", "value": "10.0.0.5"},
                                      {"type": "ip", "role": "dst", "value": "10.0.0.9"}])}]
    # Arm A alert with NO timestamp -> untimed -> ambiguous (identity matches, time unverifiable)
    arm_a = [{"event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "10.0.0.9", "alert": {"category": "scan"}}]
    es = run._score_arms(arm_a, arm_b, arm_c, labels, {"scenario": "t"}, replay_offset=OFF)["episode_scoring"]
    assert es["zeek_reference"]["episode_recall"] == 1.0               # Arm C surfaces on the original clock
    assert es["cernity_siem"]["episode_recall"] == 1.0                # Arm B surfaces under a negative offset
    assert es["suricata_siem"]["episode_recall"] == 0.0               # untimed -> not surfaced
    assert "e" in es["suricata_siem"]["ambiguous_ids"]                # ... but ambiguous, not a false miss


def test_labels_capture_overlap_guards_against_mismatched_pcap():
    # §35.10 guard: labels and pcap from DIFFERENT captures must fail loud, not silently zero recall.
    import datetime as _d
    def _eve(path, starts):
        with open(path, "w") as f:
            for s in starts:
                ts = _d.datetime.fromtimestamp(s, _d.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")
                f.write(json.dumps({"event_type": "flow", "flow": {"start": ts}}) + "\n")
    with tempfile.TemporaryDirectory() as tmp:
        eve = os.path.join(tmp, "source-eve.jsonl")
        _eve(eve, [1789395520.0, 1789395590.0])                       # flows span ~70s
        good = {"episodes": [{"id": "e", "interval": {"start": 1789395523.0, "end": 1789395598.0}}]}
        assert run.labels_capture_overlap(good, eve)[0]               # episodes within flow window -> ok
        bad = {"episodes": [{"id": "e", "interval": {"start": 1789394520.0, "end": 1789394590.0}}]}
        ok, detail = run.labels_capture_overlap(bad, eve)             # ~1000s earlier -> mismatch
        assert not ok and "DIFFERENT captures" in detail
        assert run.labels_capture_overlap({"episodes": [{"id": "e"}]}, eve)[0]   # no timed episodes -> skip
        assert run.labels_capture_overlap(good, os.path.join(tmp, "missing.jsonl"))[0]  # no capture -> skip


def test_require_capture_binding_by_hash():
    # §43.4-2: labels bound to a pcap by HASH must fail on a different pcap even if clocks would overlap;
    # absent a binding, the check passes (temporal-overlap fallback applies).
    with tempfile.TemporaryDirectory() as d:
        pcap = os.path.join(d, "cap.pcap"); open(pcap, "wb").write(b"PCAPDATA")
        other = os.path.join(d, "other.pcap"); open(other, "wb").write(b"DIFFERENT")
        assert run.require_capture_binding({"episodes": []}, pcap)[0]       # no binding -> fallback passes
        labels_path = os.path.join(d, "labels.json"); json.dump({"episodes": []}, open(labels_path, "w"))
        b = run.bind_labels_pcap(labels_path, pcap)
        assert b["pcap_sha256"] and b["capture_run_id"]
        labels = json.load(open(labels_path))
        assert run.require_capture_binding(labels, pcap)[0]                 # same pcap -> ok
        ok, det = run.require_capture_binding(labels, other)               # different pcap -> mismatch
        assert not ok and "MISMATCH" in det
        assert not run.require_capture_binding(labels, os.path.join(d, "gone.pcap"))[0]  # missing pcap fails
        # §49.3: refuse to silently rebind to a DIFFERENT pcap; force preserves the prior binding
        try:
            run.bind_labels_pcap(labels_path, other)
            assert False, "rebinding to a different pcap must fail without force"
        except SystemExit as e:
            assert "refusing to rebind" in str(e)
        forced = run.bind_labels_pcap(labels_path, other, force=True)
        assert forced["superseded"]["pcap_sha256"] == b["pcap_sha256"]     # prior binding preserved for audit


def test_require_scorer_inventory_enforces_mandatory_artifacts():
    # R07: scoring a bundle requires labels + baseline arm to be enumerated; an on-disk scorer-read file
    # absent from the manifest is unverified influence and also fails.
    with tempfile.TemporaryDirectory() as d:
        od = os.path.join(d, "output")
        os.makedirs(od)
        # manifest omits labels.json entirely
        m = {"files": {"suricata-alerts.jsonl": {"sha256": "x", "doc_count": 0}}}
        try:
            run.require_scorer_inventory(d, m)
            assert False, "missing labels.json entry must fail"
        except SystemExit as e:
            assert "labels.json" in str(e) and "required artifact" in str(e)
        # labels + baseline enumerated, but replay.json sits on disk unenumerated -> unverified influence
        open(os.path.join(od, "replay.json"), "w").close()
        m2 = {"files": {"labels.json": {"sha256": "x"}, "suricata-alerts.jsonl": {"sha256": "y", "doc_count": 0},
                        "cernity-findings.jsonl": {"sha256": "z", "doc_count": 0}}}
        try:
            run.require_scorer_inventory(d, m2)
            assert False, "unenumerated on-disk replay.json must fail"
        except SystemExit as e:
            assert "replay.json" in str(e) and "not enumerated" in str(e)
        # §43.4-2: B (cernity-findings) is required for an A/B comparison
        os.remove(os.path.join(od, "replay.json"))
        m3 = {"files": {"labels.json": {"sha256": "x"}, "suricata-alerts.jsonl": {"sha256": "y", "doc_count": 0}}}
        try:
            run.require_scorer_inventory(d, m3)
            assert False, "missing B arm (cernity-findings) must fail"
        except SystemExit as e:
            assert "cernity-findings.jsonl" in str(e) and "required artifact" in str(e)
        # §49.3: replay.json is required UNCONDITIONALLY (the requirement cannot derive from the offset
        # scalar it guards) — a bundle without the mapping fails regardless of the offset value.
        m4 = {"files": {"labels.json": {"sha256": "x"}, "suricata-alerts.jsonl": {"sha256": "y", "doc_count": 0},
                        "cernity-findings.jsonl": {"sha256": "z", "doc_count": 0}}}
        for off in (0.0, 211.9):
            try:
                run.require_scorer_inventory(d, m4, replay_offset=off)
                assert False, "missing replay.json must fail regardless of offset"
            except SystemExit as e:
                assert "replay.json" in str(e) and "required artifact" in str(e)


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
    # §25.2: clean inputs but no downstream accounting -> inputs_drained; R01: the reason is now named
    # (delivery not accounted), never a silent [] that could be mistaken for a reconciled run.
    assert c["state"] == "inputs_drained"
    assert any("delivery not accounted" in u for u in c["unresolved"])


def test_reconcile_source_coverage():
    # §49.3: feeder must consume ALL Suricata output with no mid-feed loss/dup (count fallback).
    assert run.reconcile_source_coverage(100, {"read_events": 100, "fed_events": 100})[0]
    ok, p = run.reconcile_source_coverage(100, {"read_events": 100, "fed_events": 97})  # dropped
    assert not ok and "dropped/duplicated" in p[0]
    ok2, p2 = run.reconcile_source_coverage(100, {"read_events": 95, "fed_events": 95})  # omission
    assert not ok2 and "omission" in p2[0]
    assert not run.reconcile_source_coverage(100, None)[0]                               # no manifest -> unverified


def test_source_identity_catches_equal_count_omission_plus_dup():
    # §59.1: the case a COUNT check misses — one record omitted and another duplicated so totals still
    # match. Identity digests differ, so the reconciler catches it.
    src = [{"flow_id": i, "event_type": "flow", "src_ip": "10.0.0.1"} for i in range(5)]
    src_digest = run._identity_digest([run._event_identity(e) for e in src])
    # feeder read a set with flow_id 4 dropped but flow_id 0 duplicated -> same COUNT (5), different set
    corrupt = [src[0], src[0], src[1], src[2], src[3]]
    read_digest = run._identity_digest([run._event_identity(e) for e in corrupt])
    manifest = {"read_events": 5, "fed_events": 5,
                "read_identity_digest": read_digest, "fed_identity_digest": read_digest}
    ok, probs = run.reconcile_source_coverage(5, manifest, source_id_digest=src_digest)
    assert not ok and any("omission/substitution" in p for p in probs)
    # a clean feed with matching identities reconciles
    good = {"read_events": 5, "fed_events": 5, "read_identity_digest": src_digest, "fed_identity_digest": src_digest}
    assert run.reconcile_source_coverage(5, good, source_id_digest=src_digest)[0]
    # mid-feed drop/dup: fed digest != read digest
    bad_feed = {"read_events": 5, "fed_events": 5, "read_identity_digest": src_digest,
                "fed_identity_digest": read_digest}
    ok2, probs2 = run.reconcile_source_coverage(5, bad_feed, source_id_digest=src_digest)
    assert not ok2 and any("dropped/duplicated" in p for p in probs2)


def test_reconcile_obligations_per_destination():
    # §49.3: every destination must account for >= the dispatched-findings inventory.
    lifecycle = {"delivered_now": 8, "finalized": 0}
    full = {"sinks": [{"name": "es", "delivered": 8, "dead_lettered": 0}]}
    assert run.reconcile_obligations(lifecycle, full)[0]
    under = {"sinks": [{"name": "es", "delivered": 3, "dead_lettered": 0}]}
    ok, probs = run.reconcile_obligations(lifecycle, under)
    assert not ok and "under-accounted" in probs[0]
    # §57.5: None lifecycle is UNKNOWN (blocks), NOT a silent N/A success (see the dedicated test below)
    assert not run.reconcile_obligations(None, full)[0]


def test_reconcile_obligations_counts_suppressed():
    # Delivery-suppressed findings (withheld from the analyst plane, kept for correlation) are a terminal
    # disposition carrying NO per-sink ledger record — their count comes from the forwarder receipt and
    # must be credited, else a healthy run that suppresses low-severity findings false-flags as a gap.
    lifecycle = {"delivered_now": 39, "finalized": 0}
    ledger = {"sinks": [{"name": "opensearch", "delivered": 3, "dead_lettered": 0}]}
    assert not run.reconcile_obligations(lifecycle, ledger)[0]                     # 3 < 39 without suppressed
    assert run.reconcile_obligations(lifecycle, ledger, suppressed=36)[0]          # 3 + 36 = 39 -> balanced
    # a genuine gap still trips even with suppression credited
    assert not run.reconcile_obligations(lifecycle, ledger, suppressed=30)[0]      # 3 + 30 = 33 < 39


def test_reconcile_obligations_fails_closed_on_missing_evidence():
    # §57.5: the defects Codex's probe found must now FAIL, not silently pass.
    lifecycle = {"delivered_now": 39, "finalized": 0}
    # empty sink list while work was dispatched -> UNKNOWN destination, not success
    ok, probs = run.reconcile_obligations(lifecycle, {"sinks": []}, suppressed=0)
    assert not ok and "NO sink outcomes" in probs[0]
    # None lifecycle -> UNKNOWN, not N/A success
    assert not run.reconcile_obligations(None, {"sinks": [{"name": "es", "delivered": 1}]})[0]
    # an expected sink absent from the ledger -> fail (a missing sink cannot be assumed delivered)
    ok2, probs2 = run.reconcile_obligations(
        lifecycle, {"sinks": [{"name": "opensearch", "delivered": 3, "dead_lettered": 0}]},
        suppressed=36, expected_sinks=["opensearch", "devo"])
    assert not ok2 and any("devo" in p for p in probs2)


def test_ledger_disposition_counts_suppressed_identities():
    # §59.1: suppressed records ('(withheld)', outcome 'suppressed') are counted by (finding_id, revision)
    # identity, not treated as a real sink; a duplicate identity does not double-count.
    recs = [{"finding_id": "a", "revision": 1, "dest": "opensearch", "outcome": "delivered"},
            {"finding_id": "b", "revision": 1, "dest": "(withheld)", "outcome": "suppressed"},
            {"finding_id": "b", "revision": 1, "dest": "(withheld)", "outcome": "suppressed"},  # dup replay
            {"finding_id": "c", "revision": 2, "dest": "(withheld)", "outcome": "suppressed"}]
    d = run.ledger_disposition(recs)
    assert d["suppressed_identities"] == 2                       # b:1 and c:2, dup collapsed
    assert [s["name"] for s in d["sinks"]] == ["opensearch"]     # no '(withheld)' sink
    # reconcile prefers the ledger identity count over the aggregate receipt arg
    lifecycle = {"delivered_now": 3, "finalized": 0}
    assert run.reconcile_obligations(lifecycle, d, suppressed=999)[0]   # 1 delivered + 2 suppressed-identity = 3


def test_reconcile_obligations_zero_and_all_suppressed():
    # explicit zero expected work reconciles; an all-suppressed run (net 0) reconciles with no sink record
    assert run.reconcile_obligations({"delivered_now": 0, "finalized": 0}, {"sinks": []})[0]
    assert run.reconcile_obligations({"delivered_now": 12, "finalized": 0}, {"sinks": []}, suppressed=12)[0]


def test_ledger_partial_accounting_does_not_reconcile():
    # §36.3: a NONEMPTY ledger accounting for FEWER than the receipt's live deliveries is partial and
    # must NOT reconcile (one terminal record among 100 live items must fail closed).
    receipt = {"consumed": 100, "suppressed": 0, "delivered_live": 100,
               "sinks": [{"name": "es", "delivered": 100, "dead_lettered": 0}]}
    partial = {"sinks": [{"name": "es", "delivered": 1, "dead_lettered": 0}], "delivered": 1, "dead_lettered": 0}
    ok, detail = run._ledger_accounted(partial, receipt)
    assert not ok and "partial" in detail                         # per-destination under-accounting (§39.2)
    full = {"sinks": [{"name": "es", "delivered": 100, "dead_lettered": 0}], "delivered": 100, "dead_lettered": 0}
    assert run._ledger_accounted(full, receipt)[0]                # complete ledger reconciles
    # run8 non-racing case: receipt live=0 (stale/suppressed) but ledger has real deliveries -> reconcile
    stale = {"consumed": 1, "suppressed": 1, "delivered_live": 0, "sinks": [{"name": "es", "delivered": 0, "dead_lettered": 0}]}
    assert run._ledger_accounted({"delivered": 3, "dead_lettered": 0, "sinks": [{"name": "es", "delivered": 3, "dead_lettered": 0}]}, stale)[0]


def test_classify_completion_blocks_on_ledger_receipt_conflict():
    # §39.2 BLOCKER: an available ledger that FAILS reconciliation must NOT be overridden by an
    # internally-balanced receipt. 1-delivery ledger vs 100-live receipt -> inputs_drained (conflict).
    receipt = {"consumed": 100, "suppressed": 0, "delivered_live": 100,
               "sinks": [{"name": "es", "delivered": 100, "dead_lettered": 0}]}
    partial = run.ledger_disposition([{"finding_id": "f1", "revision": 1, "dest": "es", "outcome": "delivered"}])
    c = run.classify_completion({"suricata-offline": 0, "arm-b-feeder": 0}, {"g1": 0, "g2": 0},
                                {"arm-a-suricata": 100}, expected_producers=_P, expected_groups=_G,
                                sink_receipt=receipt, ledger=partial)
    assert c["state"] == "inputs_drained"                         # NOT reconciled despite the balanced receipt
    assert any("delivery CONFLICT" in u for u in c["unresolved"])
    # a COMPLETE ledger with the same receipt reconciles
    full = run.ledger_disposition([{"finding_id": f"f{i}", "revision": 1, "dest": "es", "outcome": "delivered"} for i in range(100)])
    assert run.classify_completion({"suricata-offline": 0, "arm-b-feeder": 0}, {"g1": 0, "g2": 0},
                                   {"arm-a-suricata": 100}, expected_producers=_P, expected_groups=_G,
                                   sink_receipt=receipt, ledger=full)["state"] == "reconciled"


def test_ledger_missing_destination_does_not_reconcile():
    # §39.2/§39.5 per-destination loss: two required sinks, ledger records only one -> not accounted
    # (a global total would hide the missing sink).
    receipt = {"consumed": 8, "suppressed": 0, "delivered_live": 8,
               "sinks": [{"name": "es", "delivered": 8, "dead_lettered": 0}, {"name": "splunk", "delivered": 8, "dead_lettered": 0}]}
    ledger = {"delivered": 8, "dead_lettered": 0, "sinks": [{"name": "es", "delivered": 8, "dead_lettered": 0}]}
    ok, detail = run._ledger_accounted(ledger, receipt)
    assert not ok and "splunk" in detail                          # missing destination caught


def test_empty_ledger_does_not_reconcile_without_zero_proof():
    # R01 (reproduced blocker): a readable-but-EMPTY ledger must NOT reconcile a run.
    empty = run.ledger_disposition([])
    c = run.classify_completion({"suricata-offline": 0, "arm-b-feeder": 0}, {"g1": 0, "g2": 0},
                                {"arm-a-suricata": 100}, expected_producers=_P, expected_groups=_G,
                                ledger=empty)
    assert c["state"] == "inputs_drained"                     # not "reconciled"
    assert any("empty durable ledger" in u for u in c["unresolved"])
    # ... unless a zero-delivery run is independently proven by the receipt (delivered_live == 0):
    zero_receipt = {"consumed": 0, "suppressed": 0, "delivered_live": 0, "sinks": [{"name": "es", "delivered": 0, "dead_lettered": 0}]}
    c2 = run.classify_completion({"suricata-offline": 0, "arm-b-feeder": 0}, {"g1": 0, "g2": 0},
                                 {"arm-a-suricata": 100}, expected_producers=_P, expected_groups=_G,
                                 ledger=empty, sink_receipt=zero_receipt)
    assert c2["state"] == "reconciled"


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


def _clean(sink_receipt=None):
    return run.classify_completion({"suricata-offline": 0, "arm-b-feeder": 0}, {"g1": 0, "g2": 0},
                                   {"arm-a-suricata": 100}, expected_producers=_P, expected_groups=_G,
                                   sink_receipt=sink_receipt)


def test_reconciled_only_with_an_accountable_sink_receipt():
    # Rec-D: a clean run with NO receipt is inputs_drained; an accountable receipt upgrades it.
    assert _clean()["state"] == "inputs_drained"
    receipt = {"consumed": 10, "suppressed": 2, "delivered_live": 8,
               "sinks": [{"name": "opensearch", "delivered": 8, "dead_lettered": 0}]}
    c = _clean(receipt)
    assert c["state"] == "reconciled" and c["delivery"]["dead_lettered"] == 0


def test_ledger_disposition_dedups_and_tallies_by_dest():
    recs = [{"finding_id": "a", "revision": None, "dest": "opensearch", "outcome": "delivered"},
            {"finding_id": "a", "revision": None, "dest": "opensearch", "outcome": "delivered"},  # dup append
            {"finding_id": "b", "revision": None, "dest": "opensearch", "outcome": "dead_lettered"}]
    d = run.ledger_disposition(recs)
    assert d["delivered"] == 1 and d["dead_lettered"] == 1                 # a counted once
    assert d["sinks"][0] == {"name": "opensearch", "delivered": 1, "dead_lettered": 1}


def test_ledger_is_authoritative_over_an_incomplete_receipt():
    # the run8 case: the bus receipt raced (consumed=1/delivered=0) but the durable ledger recorded
    # real deliveries -> reconcile from the LEDGER, not the stale receipt (§stage3 fix).
    stale_receipt = {"consumed": 1, "suppressed": 1, "delivered_live": 0,
                     "sinks": [{"name": "opensearch", "delivered": 0, "dead_lettered": 0}]}
    ledger = run.ledger_disposition([{"finding_id": f"b{i}", "revision": None, "dest": "opensearch",
                                      "outcome": "delivered"} for i in range(3)])
    c = run.classify_completion({"suricata-offline": 0, "arm-b-feeder": 0}, {"g1": 0, "g2": 0},
                                {"arm-a-suricata": 100}, expected_producers=_P, expected_groups=_G,
                                sink_receipt=stale_receipt, ledger=ledger)
    assert c["state"] == "reconciled"
    assert c["delivery"]["source"] == "obligation-ledger" and c["delivery"]["delivered"] == 3


def test_lifecycle_disposition_aggregates_latest_per_worker():
    acks = [{"worker": "w", "seq": 1, "delivered_now": 1, "capture_requested": 2, "pending": 2, "finalized": 0},
            {"worker": "w", "seq": 2, "delivered_now": 3, "capture_requested": 2, "pending": 0, "finalized": 2}]
    d = run.lifecycle_disposition(acks)
    assert d["pending"] == 0 and d["delivered_now"] == 3 and d["finalized"] == 2   # latest (seq2) wins
    assert run.lifecycle_disposition([]) is None                                    # not armed


def test_lifecycle_gate_blocks_reconcile_while_capture_pending():
    base = dict(producer_exits={"suricata-offline": 0, "arm-b-feeder": 0}, group_lag={"g1": 0, "g2": 0},
                arm_counts={"arm-a-suricata": 100}, expected_producers=_P, expected_groups=_G,
                ledger=run.ledger_disposition([{"finding_id": "a", "revision": None, "dest": "opensearch",
                                                "outcome": "delivered"}]))
    assert run.classify_completion(**base, lifecycle_ok=True)["state"] == "reconciled"
    c = run.classify_completion(**base, lifecycle_ok=False)
    assert c["state"] == "inputs_drained" and any("pending disposition" in u for u in c["unresolved"])
    assert run.classify_completion(**base, lifecycle_ok=None)["state"] == "reconciled"   # not armed


def test_eval_horizon_requires_every_partition_past_the_deadline():
    # R04: one partition acked past the deadline must NOT satisfy the whole service gate — every
    # OBSERVED partition of an expected detector must have evaluated past deadline+horizon.
    exp = ("behavioral-detectors",)
    good = [{"svc": "behavioral-detectors", "partition": 0, "evaluated_wall": 150.0, "horizon_secs": 0},
            {"svc": "behavioral-detectors", "partition": 1, "evaluated_wall": 150.0, "horizon_secs": 0}]
    ok, un = run.eval_horizon_ok(good, exp, deadline_wall=100.0)
    assert ok and un == []
    lagging = [{"svc": "behavioral-detectors", "partition": 0, "evaluated_wall": 150.0, "horizon_secs": 0},
               {"svc": "behavioral-detectors", "partition": 1, "evaluated_wall": 80.0, "horizon_secs": 0}]
    ok2, un2 = run.eval_horizon_ok(lagging, exp, deadline_wall=100.0)
    assert not ok2 and any("partition" in u for u in un2)          # partition 1 lags -> not ok


def test_lifecycle_ok_gate_treats_missing_acks_as_unknown():
    # R05: no acks + findings produced -> False (block); no acks + no findings -> None (evidence-only);
    # acks present -> pending gate.
    assert run.lifecycle_ok_gate(None, produced_count=5) is False    # findings but disposition unconfirmed
    assert run.lifecycle_ok_gate(None, produced_count=0) is None     # nothing to finalize
    assert run.lifecycle_ok_gate({"pending": 0}, produced_count=5) is True
    assert run.lifecycle_ok_gate({"pending": 2}, produced_count=5) is False


def test_eval_gate_blocks_reconcile_until_detectors_ack():
    # §stage3 armed gate: delivery accounted but detectors not yet evaluated-through-horizon ->
    # inputs_drained (still scoreable, reason recorded), NOT reconciled.
    ledger = run.ledger_disposition([{"finding_id": "a", "revision": None, "dest": "opensearch",
                                      "outcome": "delivered"}])
    base = dict(producer_exits={"suricata-offline": 0, "arm-b-feeder": 0}, group_lag={"g1": 0, "g2": 0},
                arm_counts={"arm-a-suricata": 100}, expected_producers=_P, expected_groups=_G, ledger=ledger)
    assert run.classify_completion(**base, eval_ok=True)["state"] == "reconciled"
    c = run.classify_completion(**base, eval_ok=False)
    assert c["state"] == "inputs_drained" and any("evaluation through the input horizon" in u for u in c["unresolved"])
    assert run.classify_completion(**base, eval_ok=None)["state"] == "reconciled"   # gate not armed -> unchanged


def test_empty_ledger_reconciles_only_with_independent_zero_proof():
    # R01: a readable-but-empty ledger is NOT self-justifying (readability != completeness). It
    # reconciles a benign no-delivery run ONLY when the forwarder receipt independently proves zero live
    # deliveries; on its own it stays inputs_drained.
    ledger = run.ledger_disposition([])              # no deliveries, but the ledger was readable
    base = dict(producer_exits={"suricata-offline": 0, "arm-b-feeder": 0}, group_lag={"g1": 0, "g2": 0},
                arm_counts={"arm-a-suricata": 100}, expected_producers=_P, expected_groups=_G, ledger=ledger)
    assert run.classify_completion(**base)["state"] == "inputs_drained"
    zero_receipt = {"consumed": 0, "suppressed": 0, "delivered_live": 0,
                    "sinks": [{"name": "es", "delivered": 0, "dead_lettered": 0}]}
    c = run.classify_completion(**base, sink_receipt=zero_receipt)
    assert c["state"] == "reconciled" and c["delivery"]["delivered"] == 0


def test_dead_letters_still_reconcile_as_a_recorded_negative_outcome():
    receipt = {"consumed": 8, "suppressed": 0, "delivered_live": 8,
               "sinks": [{"name": "splunk", "delivered": 5, "dead_lettered": 3}]}
    c = _clean(receipt)
    assert c["state"] == "reconciled" and c["delivery"]["dead_lettered"] == 3   # accounted, surfaced


def test_inconsistent_receipt_does_not_reconcile():
    # sink accounts for fewer than the live consumed count -> not accountable -> stays inputs_drained
    receipt = {"consumed": 10, "suppressed": 0, "delivered_live": 10,
               "sinks": [{"name": "es", "delivered": 4, "dead_lettered": 0}]}
    assert _clean(receipt)["state"] == "inputs_drained"


# §stage3: aggregate the latest receipt PER WORKER, not the last message; validate types/invariants.
def _r(worker, seq, consumed, suppressed, delivered, dead=0, name="es"):
    return {"schema_version": "1.0", "worker": worker, "seq": seq, "consumed": consumed,
            "suppressed": suppressed, "delivered_live": consumed - suppressed,
            "sinks": [{"name": name, "delivered": delivered, "dead_lettered": dead}]}


def test_aggregate_keeps_latest_per_worker_and_sums():
    receipts = [_r("w1", 1, 3, 0, 3), _r("w1", 2, 5, 0, 5),          # w1 latest = seq2 (5)
                _r("w2", 1, 4, 1, 3)]                                 # w2 = 4 consumed, 1 suppressed, 3 live
    agg, problems = run.aggregate_receipts(receipts)
    assert problems == [] and agg["workers"] == 2
    assert agg["consumed"] == 9 and agg["suppressed"] == 1 and agg["delivered_live"] == 8
    assert agg["sinks"][0]["delivered"] == 8 and run._receipt_accounted(agg)


def test_eval_horizon_ok_requires_a_post_deadline_evaluation_per_detector():
    # §stage3: a detector must have an evaluate() pass at/after (deadline + its horizon).
    acks = [{"svc": "behavioral-detectors", "partition": 0, "evaluated_wall": 1000.0, "horizon_secs": 60},
            {"svc": "behavioral-detectors", "partition": 0, "evaluated_wall": 1200.0, "horizon_secs": 60}]
    ok, unresolved = run.eval_horizon_ok(acks, ["behavioral-detectors"], deadline_wall=1100.0)
    assert ok and unresolved == []                    # latest 1200 >= 1100 + 60
    ok2, u2 = run.eval_horizon_ok(acks, ["behavioral-detectors"], deadline_wall=1200.0)
    assert not ok2 and u2                             # latest 1200 < 1200 + 60 -> not covered
    ok3, u3 = run.eval_horizon_ok(acks, ["dns-detector"], deadline_wall=1000.0)
    assert not ok3 and "no evaluation ack" in u3[0]   # a detector that never acked
    # gate not armed when no detectors are declared expected (evidence-only phase)
    assert run.eval_horizon_ok(acks, [], deadline_wall=9e9)[0] is True


def test_aggregate_rejects_bad_types_and_broken_invariants():
    assert run.aggregate_receipts([])[0] is None                     # no receipts
    bad_bool = [{"worker": "w", "seq": 1, "consumed": True, "suppressed": 0, "delivered_live": 1,
                 "sinks": [{"name": "es", "delivered": 1, "dead_lettered": 0}]}]
    assert run.aggregate_receipts(bad_bool)[0] is None               # bool is not a count
    negative = [_r("w", 1, 3, 0, 3)]; negative[0]["sinks"][0]["delivered"] = -1
    assert run.aggregate_receipts(negative)[0] is None
    broken = [_r("w", 1, 10, 0, 4)]                                   # sink 4 != live 10
    agg, problems = run.aggregate_receipts(broken)
    assert agg is None and problems


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


def test_verify_export_manifest_detects_mutation_truncation_and_missing():
    # §25.4/Rec-E: file-only recompute must refuse mutated/truncated/missing exported evidence.
    import json
    with tempfile.TemporaryDirectory() as d:
        od = os.path.join(d, "output")
        os.makedirs(od)
        fpath = os.path.join(od, "cernity-findings.jsonl")
        with open(fpath, "w") as f:
            f.write('{"a":1}\n{"a":2}\n')
        manifest = {"consistency_basis": "test", "files": {"cernity-findings.jsonl":
                    {"sha256": run._sha256(fpath), "doc_count": 2}}}
        with open(os.path.join(od, "export-manifest.json"), "w") as f:
            json.dump(manifest, f)
        assert run.verify_export_manifest(d)["files"]           # unchanged -> passes
        with open(fpath, "a") as f:                             # mutate/append -> hash + count drift
            f.write('{"a":3}\n')
        try:
            run.verify_export_manifest(d)
            assert False, "mutated export must fail verification"
        except SystemExit as e:
            assert "cernity-findings.jsonl" in str(e)
        os.remove(fpath)                                        # missing file
        try:
            run.verify_export_manifest(d)
            assert False, "missing export must fail verification"
        except SystemExit as e:
            assert "missing" in str(e)


def test_verify_export_manifest_detects_altered_file_list_via_bundle_digest():
    # §stage4: editing the manifest's file list (to hide a change) must fail the published digest.
    import json
    with tempfile.TemporaryDirectory() as d:
        od = os.path.join(d, "output")
        os.makedirs(od)
        fp = os.path.join(od, "cernity-findings.jsonl")
        with open(fp, "w") as f:
            f.write('{"a":1}\n')
        files = {"cernity-findings.jsonl": {"sha256": run._sha256(fp), "doc_count": 1}}
        digest = run._bundle_digest(files)
        # tamper: drop the file from the manifest list but keep the (stale) published digest
        with open(os.path.join(od, "export-manifest.json"), "w") as f:
            json.dump({"consistency_basis": "t", "files": {}, "bundle_digest": digest}, f)
        try:
            run.verify_export_manifest(d)
            assert False, "altered file list must fail the bundle digest"
        except SystemExit as e:
            assert "bundle_digest" in str(e)


def test_verify_export_manifest_rejects_path_traversal_in_file_names():
    # §stage4: a manifest entry must be a plain basename inside the bundle, never an escaping path.
    import json
    with tempfile.TemporaryDirectory() as d:
        od = os.path.join(d, "output")
        os.makedirs(od)
        files = {"../../etc/passwd": {"sha256": "x", "doc_count": 0}}
        with open(os.path.join(od, "export-manifest.json"), "w") as f:
            json.dump({"consistency_basis": "t", "files": files, "bundle_digest": run._bundle_digest(files)}, f)
        try:
            run.verify_export_manifest(d)
            assert False, "traversal path in manifest must be rejected"
        except SystemExit as e:
            assert "traversal" in str(e)


def test_release_record_pins_run_bundle_and_report():
    import json
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "report.json"), "w") as f:
            json.dump({"metric": 1}, f)
        rec = run._release_record(d, "run-xyz", "deadbeef")
        assert rec["run_id"] == "run-xyz" and rec["bundle_digest"] == "deadbeef"
        assert rec["report_sha256"] and json.load(open(os.path.join(d, "release.json")))["run_id"] == "run-xyz"


def test_verify_export_manifest_requires_a_manifest():
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "output"))
        try:
            run.verify_export_manifest(d)
            assert False, "absent manifest must fail (cannot verify evidence)"
        except SystemExit:
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
        _files = {}
        for fname, docs in (("suricata-alerts.jsonl", arm_a), ("cernity-findings.jsonl", arm_b),
                            ("zeek-notices.jsonl", [])):
            fp = os.path.join(od, fname)
            with open(fp, "w") as f:
                for x in docs:
                    f.write(json.dumps(x, sort_keys=True) + "\n")
            _files[fname] = {"sha256": run._sha256(fp), "doc_count": len(docs)}
        lp = os.path.join(od, "labels.json")                     # §stage4: truth frozen IN the bundle
        with open(lp, "w") as f:
            json.dump(labels, f)
        _files["labels.json"] = {"sha256": run._sha256(lp)}
        rp = os.path.join(od, "replay.json")                     # §49.3: transform mapping always present
        with open(rp, "w") as f:
            json.dump({"replay_offset_seconds": 0.0, "anchor": "none"}, f)
        _files["replay.json"] = {"sha256": run._sha256(rp)}
        with open(os.path.join(od, "export-manifest.json"), "w") as f:  # verified before scoring
            json.dump({"consistency_basis": "test", "files": _files,
                       "bundle_digest": run._bundle_digest(_files)}, f)
        recomputed = run.score_from_export(os.path.join(d, "out", "t"), "t")  # no repo/DATASETS fallback

    assert recomputed["episode_scoring"] == live["episode_scoring"], "episode metrics not reproducible from files"
    assert recomputed["arms"] == live["arms"], "arm metrics not reproducible from files"


def test_score_from_export_refuses_a_bundle_without_frozen_truth():
    # §stage4: no repo/DATASETS fallback — a bundle with no labels.json cannot be scored.
    import json
    with tempfile.TemporaryDirectory() as d:
        od = os.path.join(d, "out", "t", "output")
        os.makedirs(od)
        fp = os.path.join(od, "suricata-alerts.jsonl")
        open(fp, "w").close()
        with open(os.path.join(od, "export-manifest.json"), "w") as f:
            json.dump({"consistency_basis": "test",
                       "files": {"suricata-alerts.jsonl": {"sha256": run._sha256(fp), "doc_count": 0}}}, f)
        try:
            run.score_from_export(os.path.join(d, "out", "t"), "t")
            assert False, "must refuse a bundle with no frozen labels.json"
        except SystemExit as e:
            # R07: the mandatory-artifact inventory now catches the missing labels at manifest
            # verification (before scoring), still refusing a truth-less bundle.
            assert "labels.json" in str(e) and "required artifact" in str(e)


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
