"""protocol-detectors externalized state + entity JA4 novelty + shared dedup (plan 006)."""
import json

import app
import store


class _P:
    def __init__(self):
        self.sent = []

    def send(self, topic, msg):
        self.sent.append(msg)

    def flush(self):
        pass


def _fresh():
    app._store = store.make_store("memory")


def test_ssh_bruteforce_from_shared_counter():
    _fresh()
    p = _P()
    for _ in range(15):                                  # ssh_brute_hit min_sessions=15
        app._handle({"event_type": "ssh", "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2"}, p)
    assert any(m["detector_id"] == "ssh_bruteforce" for m in p.sent)


def _fp(i=0):
    return f"t13d1516h2_{i:012x}_{i:012x}"


def _event(fp, src="10.0.0.1", **extra):
    return {"event_type": "tls", "src_ip": src, "tls": {"ja4": fp, **extra}}


def _ready(src="10.0.0.1"):
    key = f"ja4:{app.TENANT}:{src}"
    app._store.set_add(key + ":seen", _fp(99), app.JA4_BASELINE_TTL)
    app._store.kv_set(key + ":baseline",
                      {"observations": app.JA4_MIN_OBSERVATIONS,
                       "first": app.time.time() - app.JA4_MIN_SPAN_SECS},
                      app.JA4_BASELINE_TTL)
    return key


def _hits(p):
    return [m for m in p.sent if m["detector_id"] in ("ja4_novelty", "ja4_transition_burst")]


def test_ja4_learn_only():
    _fresh()
    p = _P()
    for i in range(app.JA4_MIN_OBSERVATIONS + 2):
        app._handle(_event(_fp(i)), p)
    assert not _hits(p)  # even a transition burst is learn-only before span is met
    key = f"ja4:{app.TENANT}:10.0.0.1"
    assert app._store.kv_get(key + ":baseline")["observations"] == app.JA4_MIN_OBSERVATIONS + 2
    assert app._store.set_contains(key + ":seen", _fp(0))
    assert app._store.set_contains(key + ":ac", app.proto.ja4_ac(_fp(0)))


def test_ja4_second_entity_and_known_fingerprint():
    _fresh()
    p = _P()
    for src in ("10.0.0.1", "10.0.0.2"):
        _ready(src)
        app._handle(_event(_fp(), src), p)
    hits = _hits(p)
    assert len(hits) == 2 and all(m["detector_id"] == "ja4_novelty" for m in hits)
    values = {v["type"]: v["value"] for v in json.loads(hits[-1]["entities"])}
    assert values["fleet_entity_count"] == 1 and values["maturity"] == "ready"
    assert values["ja4_ac"] == app.proto.ja4_ac(_fp())
    assert "JA4_NEW_TO_ENTITY" in values["reason_codes"]
    for _ in range(10):
        app._handle(_event(_fp()), p)
    assert len(_hits(p)) == 2
    assert app._store.set_len(f"ja4fleet:{app.TENANT}:{_fp()}") == 2


def test_ja4_standalone_and_burst():
    _fresh()
    p = _P()
    _ready()
    for i in range(app.JA4_RARE_MAX_ENTITIES + 1):
        app._store.set_add(f"ja4fleet:{app.TENANT}:{_fp()}", f"host{i}", app.JA4_BASELINE_TTL)
    app._handle(_event(_fp()), p)
    finding = _hits(p)[0]
    assert 1 <= finding["severity"] <= 2 and finding["confidence"] <= 0.3
    for i in range(1, app.JA4_TRANSITION_MIN_DISTINCT):
        app._handle(_event(_fp(i)), p)
    burst = [m for m in _hits(p) if m["detector_id"] == "ja4_transition_burst"]
    assert len(burst) == 1
    assert next(v["value"] for v in json.loads(burst[0]["entities"])
                if v["type"] == "distinct_count") == app.JA4_TRANSITION_MIN_DISTINCT


def test_ja4_ac_attenuation_and_quic():
    outcomes = []
    for similar in (False, True):
        _fresh()
        p = _P()
        key = _ready()
        if similar:
            app._store.set_add(key + ":ac", app.proto.ja4_ac(_fp()), app.JA4_BASELINE_TTL)
        app._handle({"event_type": "quic", "src_ip": "10.0.0.1",
                     "quic": {"ja4": {"string": _fp()}}}, p)
        outcomes.append(_hits(p)[0])
    assert outcomes[1]["severity"] < outcomes[0]["severity"] <= 6
    assert outcomes[1]["confidence"] < outcomes[0]["confidence"]
    entities = json.loads(outcomes[1]["entities"])
    assert next(v for v in entities if v["type"] == "ja4")["transport"] == "quic"
    assert "JA4_AC_SIMILARITY" in next(v["value"] for v in entities if v["type"] == "reason_codes")


def test_invalid_ja4_alone_and_missing_source():
    _fresh()
    p = _P()
    _ready()
    for fp in (None, "", "barehash", {"hash": "flattened"}, "t13d1516h2_bad_bad"):
        app._handle(_event(fp), p)
    app._handle(_event(_fp(), src=None), p)
    assert not p.sent
    assert not app._store.set_members(f"ja4:{app.TENANT}:10.0.0.1:ac")
    assert not app._store.set_members(f"ja4fleet:{app.TENANT}:{_fp()}")


def test_invalid_ja4_no_pollution_and_ja3_fallback():
    _fresh()
    p = _P()
    for i in range(7):
        app._handle(_event({"hash": "bad"}, ja3=f"hash{i}"), p)
    assert not _hits(p)
    assert not app._store.set_members(f"ja4:{app.TENANT}:10.0.0.1:ac")
    assert app._store.kv_get(f"ja4:{app.TENANT}:10.0.0.1:baseline") is None
    assert any(m["detector_id"] == "ja4_rarity" for m in p.sent)  # legacy JA3 path


def test_ja4_tenant_isolation_and_expiry():
    _fresh()
    p = _P()
    original_tenant, original_time = app.TENANT, app.time.time
    now = [1000000.0]
    app.time.time = lambda: now[0]
    app._store._now = lambda: now[0]
    try:
        _ready()
        app._handle(_event(_fp()), p)
        app.TENANT = "other"
        app._handle(_event(_fp()), p)
        assert len(_hits(p)) == 1
        app.TENANT = original_tenant
        now[0] += app.JA4_BASELINE_TTL + 1
        app._handle(_event(_fp(1)), p)
        assert len(_hits(p)) == 1  # an actual week without traffic requires learning again
        assert app._store.kv_get(f"ja4:{app.TENANT}:10.0.0.1:baseline") == {"first": now[0], "observations": 1}
    finally:
        app.TENANT, app.time.time = original_tenant, original_time


def test_ja4_continuous_activity_preserves_maturity():
    # The default 100 observations must be reachable even below 100/week. Check
    # every event across many former reset boundaries, not just the final state.
    original_time = app.time.time
    now = [1000000.0]
    app.time.time = lambda: now[0]
    try:
        for events_per_day in (10, 14, 480):
            _fresh()
            app._store._now = lambda: now[0]
            p = _P()
            start = now[0]
            key = f"ja4:{app.TENANT}:10.0.0.1"
            reached_ready = False
            for i in range(events_per_day * 60):
                now[0] = start + i * 86400 / events_per_day
                baseline = app._store.kv_get(key + ":baseline") or {}
                maturity = app.proto.baseline_maturity(
                    baseline.get("observations", 0), app._store.set_len(key + ":seen"),
                    baseline.get("first"), now[0])
                expected_ready = i >= 100 and now[0] - start >= 86400
                assert (maturity == "ready") == expected_ready
                if reached_ready:
                    assert maturity == "ready"
                reached_ready |= maturity == "ready"
                app._handle(_event(_fp()), p)
            assert reached_ready and not _hits(p)
            app._handle(_event(_fp(123)), p)
            hits = _hits(p)
            assert len(hits) == 1 and hits[0]["detector_id"] == "ja4_novelty"
            assert next(v["value"] for v in json.loads(hits[0]["entities"])
                        if v["type"] == "maturity") == "ready"
    finally:
        app.time.time = original_time


def test_dedup_no_double_emit():
    _fresh()
    p = _P()
    ev = {"event_type": "tls", "src_ip": "10.0.0.1", "tls": {"sni": "pastebin.com", "ja4": "j"}}
    app._handle(dict(ev), p)
    app._handle(dict(ev), p)                             # same bucket -> shared dedup
    assert sum(1 for m in p.sent if m["detector_id"] == "cloud_staging") == 1


def test_stable_hash_deterministic():
    assert app._stable("x") == app._stable("x")


def test_ja3_object_fingerprint_does_not_crash_and_uses_the_hash():
    # F06: newer Suricata emits tls.ja3 / ja3s as {"hash","string"} OBJECTS, not strings.
    # The old code used the object directly as a rarity-set member -> unhashable-dict
    # TypeError (the audit's crash). Normalize to the hash string.
    _fresh()
    p = _P()
    for i in range(6):                                    # warm up with distinct object fps
        app._handle({"event_type": "tls", "src_ip": f"10.0.0.{i}",
                     "tls": {"ja3": {"hash": f"h{i}", "string": "771,4-5"}, "sni": "x"}}, p)
    app._handle({"event_type": "tls", "src_ip": "10.0.0.99",
                 "tls": {"ja3": {"hash": "hnew", "string": "771,4-5"}, "sni": "evil"}}, p)
    hits = [m for m in p.sent if m["detector_id"] == "ja4_rarity"]
    assert hits, "ja3-object client after warmup was not flagged rare"
    ents = json.loads(hits[-1]["entities"])
    fp = next(e["value"] for e in ents if e.get("type") in ("ja3", "ja4"))
    assert fp == "hnew", f"fingerprint should be the hash string, got {fp!r}"


def test_ja3s_object_server_fingerprint_does_not_crash():
    _fresh()
    p = _P()
    for i in range(6):
        app._handle({"event_type": "tls", "dest_ip": f"1.1.1.{i}",
                     "tls": {"ja3s": {"hash": f"s{i}", "string": "a,b"}, "sni": "x"}}, p)
    app._handle({"event_type": "tls", "dest_ip": "2.2.2.2",
                 "tls": {"ja3s": {"hash": "snew", "string": "a,b"}, "sni": "evil"}}, p)
    assert any(m["detector_id"] == "server_fp_rarity" for m in p.sent)


def test_source_events_provenance_attached():
    # U3: the candidate carries the originating EVE; verdict fields unchanged (R6).
    _fresh()
    p = _P()
    app._handle({"event_type": "http", "src_ip": "10.0.0.5", "dest_ip": "203.0.113.9",
                 "http": {"http_user_agent": "curl/8.4.0"}}, p)
    f = next(m for m in p.sent if m["detector_id"] == "suspicious_ua")
    assert f["source_events"][0]["record"]["http"]["http_user_agent"] == "curl/8.4.0"
    assert f["detector_id"] == "suspicious_ua"                  # R6: verdict unchanged


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f()
            print("ok", _n)
    print("all proto-state tests passed")
