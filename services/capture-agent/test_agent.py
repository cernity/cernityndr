"""Pure-logic tests for the sensor capture agent. No Kafka/socket/MinIO."""
import agent


def test_for_this_sensor():
    assert agent.for_this_sensor({"sensor_id": "sensor-1"}, "sensor-1")
    assert not agent.for_this_sensor({"sensor_id": "other"}, "sensor-1")


def test_validate_ok_and_reject():
    assert agent.validate({"capture_profile": "ip", "value": "47.254.114.96"})[0]
    assert not agent.validate({"capture_profile": "ip", "value": ""})[0]
    assert not agent.validate({"capture_profile": "bogus", "value": "x"})[0]
    # socket-injection guard: no whitespace allowed in a dataset value
    assert not agent.validate({"capture_profile": "ip", "value": "1.2.3.4 evil"})[0]


def test_dataset_for():
    assert agent.dataset_for("ip") == ("ndr-capture-ip", "ip")
    assert agent.dataset_for("ja4") == ("ndr-capture-ja4", "string")


def test_pcap_key_rejects_unsafe_advertised_ref():
    # a forged/unsafe pcap_ref off the bus must NOT become the object key
    for bad in ("../../etc/passwd", "/etc/passwd", "ndr-pcap/../x", "a b; rm -rf",
                "x\n../y", 123, None):
        k = agent.pcap_key({"pcap_ref": bad, "finding_id": "f1", "capture_profile": "ip"})
        assert k == "ndr-pcap/f1-ip.pcap", (bad, k)   # falls back to the safe computed key


def test_pcap_key_sanitizes_fallback_components():
    # unsafe finding_id/profile can't introduce traversal in the computed key
    k = agent.pcap_key({"finding_id": "../../evil", "capture_profile": "ip/../x"})
    assert ".." not in k and k.startswith("ndr-pcap/") and k.endswith(".pcap")


def test_pcap_key_prefers_advertised_ref():
    assert agent.pcap_key({"pcap_ref": "ndr-pcap/x.pcap"}) == "ndr-pcap/x.pcap"
    k = agent.pcap_key({"finding_id": "f1", "capture_profile": "ip"})
    assert k == "ndr-pcap/f1-ip.pcap"


def test_window_pcaps_filters_by_mtime():
    entries = [("old.pcap", 100.0), ("in.pcap", 200.0), ("new.pcap", 250.0)]
    got = agent.window_pcaps(entries, start_ts=150.0)
    assert got == ["in.pcap", "new.pcap"]        # old excluded, newest last


def test_budget():
    assert agent.budget_ok(0)[0]
    ok, reason = agent.budget_ok(agent.LOCAL_MAX_CONCURRENT)
    assert ok is False and reason == "agent_max_concurrent"


def test_ttl_and_bytes_defaults():
    assert agent.ttl_secs({}) == agent.DEFAULT_TTL_SECS
    assert agent.ttl_secs({"ttl_secs": 30}) == 30
    assert agent.ttl_secs({"ttl_secs": "bad"}) == agent.DEFAULT_TTL_SECS
    assert agent.max_bytes({"max_bytes": 5}) == 5


def test_sha_from_name():
    h = "a" * 64
    assert agent.sha_from_name(h) == h
    assert agent.sha_from_name(h + ".json") is None    # sidecar, not the carved file
    assert agent.sha_from_name(h + ".meta") is None
    assert agent.sha_from_name("notahash.pcap") is None


def test_should_ship_file():
    seen = {"a" * 64}
    assert agent.should_ship_file(100, "b" * 64, seen)
    assert not agent.should_ship_file(100, "a" * 64, seen)              # already shipped
    assert not agent.should_ship_file(0, "c" * 64, seen)               # empty
    assert not agent.should_ship_file(agent.MAX_FILE_BYTES + 1, "d" * 64, seen)  # oversize
    assert not agent.should_ship_file(100, None, seen)                 # no sha


def test_file_extracted_event():
    e = agent.file_extracted_event("sensor-1", "d" * 64, 500)
    assert e["object_ref"] == f"{agent.FILES_BUCKET}/{'d' * 64}"
    assert e["sensor_id"] == "sensor-1" and e["size"] == 500


# --- U2: look-back retrieval (edge rolling-packet buffer) ----------------------
def test_lookback_pcaps_selects_pre_trigger_window():
    # ring files by mtime; a finding triggers at t=1000 with a 120s look-back
    entries = [("r1.pcap", 800.0), ("r2.pcap", 900.0), ("r3.pcap", 950.0),
               ("r4.pcap", 1005.0), ("r5.pcap", 1200.0)]
    got = agent.lookback_pcaps(entries, trigger_ts=1000.0, lookback_secs=120.0)
    # in-window: r2 (900), r3 (950), and r4 (1005, within the small forward buffer);
    # r1 (800, older than 1000-120=880) and r5 (1200, well after) are excluded
    assert "r2.pcap" in got and "r3.pcap" in got
    assert "r1.pcap" not in got and "r5.pcap" not in got
    # returned oldest -> newest
    assert got == sorted(got, key=lambda p: dict(entries)[p])


def test_lookback_pcaps_short_ring_returns_what_exists():
    entries = [("r1.pcap", 995.0)]                      # ring holds < lookback
    got = agent.lookback_pcaps(entries, trigger_ts=1000.0, lookback_secs=600.0)
    assert got == ["r1.pcap"]                           # no error, just what's there
    assert agent.lookback_pcaps([], 1000.0, 120.0) == []


def test_lookback_bpf_from_ip_profile():
    assert agent.lookback_bpf({"capture_profile": "ip", "value": "203.0.113.9"}) == "host 203.0.113.9"
    # app-layer profiles have no packet-level BPF from an IP ring -> None (no carve)
    assert agent.lookback_bpf({"capture_profile": "sni", "value": "evil.com"}) is None


def test_lookback_key_suffixes_pcap_key():
    k = agent.lookback_key({"finding_id": "f1", "capture_profile": "ip"})
    assert k == "ndr-pcap/f1-ip-lookback.pcap"


def test_wants_lookback():
    assert agent.wants_lookback({"lookback_secs": 120})
    assert agent.wants_lookback({"mode": "lookback"})
    assert not agent.wants_lookback({"capture_profile": "ip", "value": "1.2.3.4"})


def test_lookback_arm_still_requires_validation():
    # a look-back arm is admitted by the SAME validate gate as a forward arm:
    # an invalid value is rejected whether or not look-back is requested.
    bad = {"capture_profile": "ip", "value": "1.2.3.4 evil", "mode": "lookback"}
    assert agent.wants_lookback(bad)                 # it IS a look-back arm
    assert not agent.validate(bad)[0]                # but validation still rejects it


# --- U4/F11: per-finding isolation + measured uploader health -------------------
def test_capture_bpf_isolates_the_finding():
    # F11: the forward conditional pcap-log is shared across concurrent arms; carve
    # the finding's own connection so one finding's slice can't leak another's packets.
    assert agent.capture_bpf({"capture_profile": "ip", "value": "203.0.113.9"}) == "host 203.0.113.9"
    # app-layer profiles have no packet-level BPF from an IP dataset -> no carve (best effort)
    assert agent.capture_bpf({"capture_profile": "sni", "value": "evil.com"}) is None
    # injection guard: a whitespaced value never becomes a BPF
    assert agent.capture_bpf({"capture_profile": "ip", "value": "1.2.3.4 or 1"}) is None


def test_uploader_health_reflects_a_stall():
    # F11: replace the constant-healthy stub with measured health.
    assert agent.uploader_healthy(active_jobs=0, secs_since_progress=9999)        # idle = healthy
    assert agent.uploader_healthy(active_jobs=2, secs_since_progress=5, stale_secs=300)   # recent progress
    assert not agent.uploader_healthy(active_jobs=1, secs_since_progress=10_000, stale_secs=300)  # stalled


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} agent tests passed")
