"""Promote Suricata protocol-anomaly events to findings (re-eval gap G4).

`suricata.anomaly.v1` was produced but consumed by nobody. Application-layer
anomalies (protocol violations, unexpected events) are evasion/exploit tells;
decode-layer anomalies (bad checksums, malformed L2/L3) are engine noise. This
filters to the threat-relevant ones and emits finding candidates. Pure + testable.
"""
import json

_THREAT_TYPES = ("applayer",)          # app-layer protocol anomalies = threat-relevant
_KEEP_STREAM = ("overlap_different_data", "data_after_reset", "reassembly",
                "3whs", "wrong_thread")   # evasion/injection stream tells worth keeping


def is_threat_anomaly(anom: dict) -> bool:
    if not anom:
        return False
    t = str(anom.get("type", "")).lower()
    ev = str(anom.get("event", "")).lower()
    if t in _THREAT_TYPES:
        return True
    if t == "stream" and any(k in ev for k in _KEEP_STREAM):
        return True
    return False


def to_candidate(eve: dict, tenant: str = "homelab") -> dict | None:
    if eve.get("event_type") != "anomaly":
        return None
    anom = eve.get("anomaly") or {}
    if not is_threat_anomaly(anom):
        return None
    src, dst = eve.get("src_ip"), eve.get("dest_ip")
    ev = anom.get("event")
    entities = json.dumps([{"type": "ip", "role": "src", "value": src},
                           {"type": "ip", "role": "dst", "value": dst},
                           {"type": "anomaly", "value": ev},
                           {"type": "app_proto", "value": eve.get("app_proto")}])
    return {"finding_id": f"anom-{abs(hash((ev, src, dst))) % 10**10}",
            "tenant_id": tenant, "detector_id": "protocol_anomaly", "detector_version": "1.0",
            "category": "anomaly", "severity": 5, "confidence": 0.5,
            "entities": entities, "state": "CANDIDATE"}
