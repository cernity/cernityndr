"""U10 capture-orchestration gate tests — refusal paths first (v6 §14)."""
import gates as g

MANIFEST_OK = {"capture_profiles": {"ip": {"available": True}, "ja4": {"available": True}}}
MANIFEST_NO = {"capture_profiles": {"ip": {"available": False}}}
THR = {"max_loss_pct": 1.0, "max_cpu_pct": 85.0}
LIMITS = {"max_jobs": 3, "max_bytes": 500_000_000}
HEALTHY = {"packet_loss_pct": 0.0, "cpu_pct": 40.0}
REQ = {"sensor_id": "sensor-1", "capture_profile": "ip", "value": "10.0.0.5"}


def test_capability_unavailable_refuses():
    ok, why = g.decide_arm(REQ, MANIFEST_NO, HEALTHY, {}, THR, LIMITS)
    assert not ok and why == "capability_unavailable"


def test_unhealthy_sensor_refuses():
    ok, why = g.decide_arm(REQ, MANIFEST_OK, {"packet_loss_pct": 3.0}, {}, THR, LIMITS)
    assert not ok and why == "packet_loss_over_threshold"


def test_high_cpu_refuses():
    ok, why = g.decide_arm(REQ, MANIFEST_OK, {"cpu_pct": 95.0}, {}, THR, LIMITS)
    assert not ok and why == "cpu_over_threshold"


def test_budget_exhausted_refuses():
    budget = {"sensor-1": {"active_jobs": 3}}
    ok, why = g.decide_arm(REQ, MANIFEST_OK, HEALTHY, budget, THR, LIMITS)
    assert not ok and why == "max_concurrent_jobs"


def test_byte_budget_refuses():
    budget = {"sensor-1": {"bytes_captured": 600_000_000}}
    ok, why = g.decide_arm(REQ, MANIFEST_OK, HEALTHY, budget, THR, LIMITS)
    assert not ok and why == "byte_budget_exhausted"


def test_all_gates_pass_arms():
    ok, why = g.decide_arm(REQ, MANIFEST_OK, HEALTHY, {}, THR, LIMITS)
    assert ok and why == "armed"


def test_capability_checked_before_health():
    # an unhealthy sensor lacking capability reports capability, not health.
    ok, why = g.decide_arm(REQ, MANIFEST_NO, {"packet_loss_pct": 9.0}, {}, THR, LIMITS)
    assert why == "capability_unavailable"


def test_arm_disarm_commands():
    assert g.arm_command("ip", "10.0.0.5") == "dataset-add ndr-capture-ip ip 10.0.0.5"
    assert g.disarm_command("ja4", "abc") == "dataset-remove ndr-capture-ja4 string abc"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} gate tests passed")
