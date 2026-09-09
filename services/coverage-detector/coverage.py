"""Mirror/SPAN coverage-completeness signal.

Closes the "silent under-detection" gap: the whole protocol/file detection tier
assumes the SPAN or mirror delivers complete, bidirectional traffic. When it does
not, the sensor under-detects and an analyst reads "no findings" as "no threat".
This detector consumes `suricata.stats.v1` (Suricata's own counters) and raises a
coverage finding when the sensor's visibility is degraded, so absence of findings
is never mistaken for absence of threat.

Two failure modes, both from Suricata's stats:
  - capture loss: `capture.kernel_drops` is a meaningful fraction of packets seen
    (oversubscribed or starved capture, so packets and detections are dropped).
  - application-layer blindness: packets are flowing (`decoder.pkts` high) but
    Suricata reassembles almost no application-layer flows (`app_layer.flow.*`
    near zero), the signature of a lossy or half-duplex/one-way mirror. This is
    the exact symptom that makes the protocol/file tier blind.

Pure functions; app.py holds the Kafka wiring, per-sensor windowing, and dedup.
"""
import json


def _num(d, *path):
    cur = d or {}
    for p in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur if isinstance(cur, (int, float)) else None


def drop_ratio(stats):
    """kernel_drops / (kernel_packets + kernel_drops). Returns None when capture
    stats are absent (offline pcap runs have no AF_PACKET capture block)."""
    drops = _num(stats, "capture", "kernel_drops")
    pkts = _num(stats, "capture", "kernel_packets")
    if drops is None or pkts is None:
        return None
    total = drops + pkts
    return (drops / total) if total > 0 else 0.0


def applayer_flows(stats):
    """Total application-layer flows Suricata parsed, summed across protocols."""
    flows = ((stats or {}).get("app_layer", {}) or {}).get("flow", {}) or {}
    return sum(v for v in flows.values() if isinstance(v, (int, float)))


def capture_loss(stats, drop_threshold=0.02):
    """(is_degraded, ratio). Fires when the drop ratio meets the threshold."""
    r = drop_ratio(stats)
    if r is None:
        return False, None
    return (r >= drop_threshold), r


def applayer_blind(stats, min_pkts=5000, ratio_threshold=0.001):
    """(is_blind, ratio). Packets flowing but almost no app-layer reassembled =
    lossy or half-duplex mirror. Ratio is app-layer flows per packet; below the
    floor with enough packets seen = blind. Needs a packet baseline so a quiet
    sensor is not flagged."""
    pkts = _num(stats, "decoder", "pkts")
    if pkts is None or pkts < min_pkts:
        return False, None
    ratio = applayer_flows(stats) / pkts if pkts else 0.0
    return (ratio <= ratio_threshold), ratio


_SEV = {"capture_loss": 6, "applayer_blind": 6}
_WHY = {
    "capture_loss": "Suricata is dropping packets at capture (kernel_drops); detections are being missed on this sensor",
    "applayer_blind": "packets are flowing but Suricata reassembles almost no application-layer traffic; the mirror is likely lossy or half-duplex, so the protocol and file detection tier is blind",
}


def to_candidate(kind, sensor, value, tenant="homelab"):
    """Build a coverage-degraded finding candidate. Severity is above the default
    suppression floor (5) on purpose: a coverage warning must reach the analyst,
    because its whole job is to stop 'no findings' being read as 'no threat'."""
    if kind not in _SEV:
        return None
    entities = json.dumps([
        {"type": "sensor", "value": sensor},
        {"type": "coverage", "value": kind},
        {"type": "metric", "value": round(value, 4) if isinstance(value, float) else value},
        {"type": "why", "value": _WHY[kind]},
    ])
    return {"finding_id": f"cov-{sensor}-{kind}",
            "tenant_id": tenant, "detector_id": "coverage_degraded", "detector_version": "1.0",
            "category": "coverage", "severity": _SEV[kind], "confidence": 0.8,
            "entities": entities, "state": "CANDIDATE"}
