"""Tests for protocol-anomaly promotion (G4)."""
import anomaly as a

APPLAYER = {"event_type": "anomaly", "src_ip": "10.0.0.5", "dest_ip": "1.2.3.4",
            "app_proto": "http", "anomaly": {"type": "applayer", "event": "http.unexpected_data"}}
STREAM_EVASION = {"event_type": "anomaly", "src_ip": "a", "dest_ip": "b",
                  "anomaly": {"type": "stream", "event": "stream.reassembly_overlap_different_data"}}
DECODE_NOISE = {"event_type": "anomaly", "src_ip": "a", "dest_ip": "b",
                "anomaly": {"type": "decode", "event": "decoder.udp.invalid_checksum"}}
FLOW = {"event_type": "flow"}


def test_promotes_applayer_anomaly():
    c = a.to_candidate(APPLAYER)
    assert c and c["detector_id"] == "protocol_anomaly" and c["category"] == "anomaly"
    assert "http.unexpected_data" in c["entities"]


def test_promotes_stream_evasion():
    assert a.to_candidate(STREAM_EVASION) is not None


def test_suppresses_decode_noise():
    assert a.to_candidate(DECODE_NOISE) is None
    assert a.is_threat_anomaly(DECODE_NOISE["anomaly"]) is False


def test_ignores_non_anomaly():
    assert a.to_candidate(FLOW) is None


if __name__ == "__main__":
    for n, f in sorted(globals().items()):
        if n.startswith("test_") and callable(f):
            f(); print("ok", n)
    print("all passed")
