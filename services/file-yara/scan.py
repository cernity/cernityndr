"""file-yara scan logic (plan U6, Track A1). The pure decision and finding-
shaping functions are testable without yara-python; the yara compile/scan
wrappers import yara lazily so this module (and its pure tests) load without
the native library present.

Catches novel malware by content: a YARA rule match on a carved file produces a
malware finding even when the file's hash is in no blocklist, which is the gap
Suricata's force-hash matching cannot close on its own.
"""
from __future__ import annotations

import json
import time

DETECTOR = "file_yara"


def should_scan(event, max_bytes):
    """Skip empty or oversize objects. Unknown mime is still scanned, since a
    carved executable can arrive without a reliable mime."""
    size = int(event.get("size", 0) or 0)
    return 0 < size <= max_bytes


def finding_from_matches(event, matched_rules, tenant="default"):
    """Pure shaping: matched YARA rule names -> candidate finding, or None when
    nothing matched."""
    if not matched_rules:
        return None
    sha256 = event.get("sha256", "")
    ref = event.get("object_ref", "")
    entities = json.dumps([
        {"type": "ip", "role": "sensor", "value": event.get("sensor_id", "")},
        {"type": "file_sha256", "value": sha256},
        {"type": "yara_rules", "value": sorted(matched_rules)},
        {"type": "mime", "value": event.get("mime", "")},
    ])
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {
        "finding_id": f"{DETECTOR}-{sha256[:16] or 'nohash'}",
        "tenant_id": tenant,
        "detector_id": DETECTOR,
        "detector_version": "1.0",
        "category": "malware",
        "severity": 9,
        "confidence": 0.9,
        "first_seen": now,
        "last_seen": now,
        "entities": entities,
        "evidence_refs": [f"minio://{ref}"] if ref else [],
        "mitre": ["T1204"],   # User Execution: Malicious File
        "state": "CANDIDATE",
    }


def compile_rules(sources):
    """Compile YARA rule files (list of paths). Imports yara lazily. Returns
    None when there are no sources."""
    import yara
    if not sources:
        return None
    return yara.compile(filepaths={f"r{i}": p for i, p in enumerate(sources)})


def scan_bytes(compiled, data):
    """Matched rule names for a blob; empty when no rules are loaded."""
    if compiled is None:
        return []
    return [m.rule for m in compiled.match(data=data)]
