"""U19 reconstruct-by-source + graph tests (pure)."""
import reconstruct as rc

FLOWS = [
    {"event_time": "2026-08-18 20:00:01", "src_ip": "10.0.0.5", "dst_ip": "1.1.1.1",
     "dst_port": 443, "app_proto": "tls"},
    {"event_time": "2026-08-18 20:00:03", "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8",
     "dst_port": 53, "app_proto": "dns"},
]
SESSIONS = [{"started": "2026-08-18 20:00:02", "session_type": "host_pair",
             "src_ip": "10.0.0.5", "dst_ip": "1.1.1.1", "app_proto": "tls", "flows": 4}]
FINDINGS = [{"first_seen": "2026-08-18 20:00:05", "finding_id": "hscan-1",
             "category": "recon", "detector_id": "horizontal_scan", "severity": 5,
             "state": "FINAL"}]


def test_timeline_is_time_ordered_and_typed():
    tl = rc.build_timeline(FLOWS, SESSIONS, FINDINGS)
    assert [e["kind"] for e in tl] == ["flow", "session", "flow", "finding"]
    assert tl[0]["t"] < tl[-1]["t"]


def test_graph_roots_at_source_with_dest_and_finding_edges():
    g = rc.build_graph("10.0.0.5", FLOWS, FINDINGS)
    ids = {n["id"] for n in g["nodes"]}
    assert {"10.0.0.5", "1.1.1.1", "8.8.8.8", "hscan-1"} <= ids
    rels = {(e["from"], e["to"], e["rel"]) for e in g["edges"]}
    assert ("10.0.0.5", "1.1.1.1", "flow") in rels
    assert ("10.0.0.5", "hscan-1", "finding") in rels


def test_graph_dedups_repeated_flow_edges():
    many = FLOWS + FLOWS + FLOWS      # same source->dests repeated
    g = rc.build_graph("10.0.0.5", many, [])
    flow_edges = [e for e in g["edges"] if e["rel"] == "flow"]
    assert len(flow_edges) == 2       # one per distinct dest, not 6


def test_safe_param_rejects_injection():
    rc.safe_param("10.0.0.5")
    rc.safe_param("mac:aa:bb:cc:00:11:22")
    for bad in ("'; DROP TABLE ndr.finding;--", "a b", "x'y"):
        try:
            rc.safe_param(bad); assert False, f"should reject {bad!r}"
        except ValueError:
            pass


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} reconstruct tests passed")
