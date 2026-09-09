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
    cand = c.to_candidate("capture_loss", "sensor-a", 0.1234, tenant="acme")
    assert cand["detector_id"] == "coverage_degraded"
    assert cand["category"] == "coverage"
    assert cand["severity"] == 6            # above the default suppression floor (5)
    assert cand["tenant_id"] == "acme"
    assert cand["finding_id"] == "cov-sensor-a-capture_loss"   # stable id = natural dedup
    assert "sensor-a" in cand["entities"] and "0.1234" in cand["entities"]


def test_to_candidate_rejects_unknown_kind():
    assert c.to_candidate("bogus", "s", 0.5) is None


if __name__ == "__main__":
    import inspect
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        if inspect.getfullargspec(fn).args:
            continue
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} coverage-detector tests passed")
