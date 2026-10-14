"""Coverage-detector pure-logic tests."""
import coverage as c


def test_capture_loss_fires_on_high_drops():
    stats = {"capture": {"kernel_packets": 900000, "kernel_drops": 100000}}  # 10% drops
    fired, ratio = c.capture_loss(stats, drop_threshold=0.02)
    assert fired and abs(ratio - 0.1) < 1e-6


def test_capture_loss_ignores_clean_capture():
    stats = {"capture": {"kernel_packets": 1000000, "kernel_drops": 50}}  # 0.005%
    assert c.capture_loss(stats, drop_threshold=0.02)[0] is False


def test_capture_loss_none_when_no_capture_block():
    # offline pcap runs have no AF_PACKET capture stats -> no false alarm
    assert c.drop_ratio({"decoder": {"pkts": 100}}) is None
    assert c.capture_loss({"decoder": {"pkts": 100}})[0] is False


def test_applayer_blind_fires_when_packets_flow_but_no_applayer():
    # 200k packets decoded, but app-layer reassembled ~nothing = half-duplex/lossy mirror
    stats = {"decoder": {"pkts": 200000}, "app_layer": {"flow": {"http": 0, "tls": 0, "dns": 1}}}
    fired, ratio = c.applayer_blind(stats, min_pkts=5000, ratio_threshold=0.001)
    assert fired and ratio < 0.001


def test_applayer_blind_ignores_healthy_mirror():
    # plenty of app-layer flows relative to packets = healthy
    stats = {"decoder": {"pkts": 200000}, "app_layer": {"flow": {"http": 1200, "tls": 3400, "dns": 5000}}}
    assert c.applayer_blind(stats, min_pkts=5000)[0] is False


def test_applayer_blind_ignores_quiet_sensor():
    # below the packet baseline, do not flag (a quiet sensor is not a blind one)
    stats = {"decoder": {"pkts": 100}, "app_layer": {"flow": {}}}
    assert c.applayer_blind(stats, min_pkts=5000)[0] is False


def test_applayer_flows_sums_across_protocols():
    stats = {"app_layer": {"flow": {"http": 10, "tls": 20, "dns": 30, "failed_tcp": 5}}}
    assert c.applayer_flows(stats) == 65


def test_to_candidate_shape_and_severity():
    cand = c.to_candidate("capture_loss", "sensor-a", 0.1234, tenant="acme", window=42)
    assert cand["detector_id"] == "coverage_degraded"
    assert cand["category"] == "coverage"
    assert cand["severity"] == 6            # above the default suppression floor (5)
    assert cand["tenant_id"] == "acme"
    assert cand["finding_id"] == "cov-sensor-a-capture_loss-42"   # B-U7/R11: windowed id (distinct episodes)
    assert cand["first_seen"] and cand["last_seen"]              # R11: strict finding schema requires both
    assert "sensor-a" in cand["entities"] and "0.1234" in cand["entities"]


def test_to_candidate_distinct_window_distinct_id():
    # B-U7/R04+R11: a later degraded episode on the same sensor is a DISTINCT finding, not one
    # permanent id collapsing every episode.
    a = c.to_candidate("capture_loss", "s", 0.1, window=1)
    b = c.to_candidate("capture_loss", "s", 0.1, window=2)
    assert a["finding_id"] != b["finding_id"]


def test_to_candidate_rejects_unknown_kind():
    assert c.to_candidate("bogus", "s", 0.5) is None



def _stats(drops=0, flows=100):
    return {"capture": {"kernel_packets": 10000, "kernel_drops": drops},
            "decoder": {"pkts": 10000}, "app_layer": {"flow": {"http": flows}}}


def test_quality_verdicts_and_null_measurements():
    for stats, verdict, reasons in (
        (_stats(), "good", []), (_stats(3000), "degraded", ["CAPTURE_LOSS"]),
        (_stats(0, 0), "blind", ["APPLAYER_BLIND"]),
        (_stats(3000, 0), "blind", ["CAPTURE_LOSS", "APPLAYER_BLIND"]),
        ({}, "unknown", [])):
        q = c.to_quality(stats, "s", "acme", observed_at="2026-10-14T00:00:00Z")
        assert q["quality"] == verdict and q["reasons"] == reasons
        assert q["tenant_id"] == "acme" and q["sensor_id"] == "s"
    stats = _stats()
    del stats["capture"]
    q = c.to_quality(stats, "s", observed_at="2026-10-14T00:00:00Z")
    assert q["quality"] == "unknown"
    assert q["signals"]["capture_drop_ratio"] is None
    del stats["app_layer"]
    q = c.to_quality(stats, "s", observed_at="2026-10-14T00:00:00Z")
    assert q["quality"] == "unknown"
    assert q["signals"]["applayer_flows_per_pkt"] is None
    for flow in ({}, {"http": None}):
        stats = _stats()
        stats["app_layer"]["flow"] = flow
        assert c.to_quality(stats, "s", observed_at="2026-10-14T00:00:00Z")["quality"] == "unknown"


def test_every_stats_record_emits_quality_without_changing_finding_dedup():
    import app
    class Producer:
        def __init__(self):
            self.sent = []
        def send(self, topic, value, key=None):
            self.sent.append((topic, value, key))
    producer = Producer()
    old_emitted, old_window = app._emitted, app.WINDOW
    try:
        app._emitted, app.WINDOW = set(), 1e12   # deterministic single episode
        for stats in (_stats(), _stats(3000), _stats(3000), _stats(), {}):
            app.evaluate(producer, {"event_type": "stats", "sensor_id": "sensor-a",
                                    "timestamp": "2026-10-14T00:00:00Z", "stats": stats})
        quality = [v for topic, v, key in producer.sent if topic == app.QUALITY_TOPIC]
        assert [q["quality"] for q in quality] == ["good", "degraded", "degraded", "good", "unknown"]
        assert all(q["sensor_id"] == "sensor-a" for q in quality)
        findings = [v for topic, v, key in producer.sent if topic == app.CANDIDATE_TOPIC]
        assert len(findings) == 1 and findings[0]["severity"] == 6
        count = len(producer.sent)
        app.evaluate(producer, {"event_type": "flow"})
        assert len(producer.sent) == count
    finally:
        app._emitted, app.WINDOW = old_emitted, old_window

if __name__ == "__main__":
    import inspect
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        if inspect.getfullargspec(fn).args:
            continue
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} coverage-detector tests passed")
