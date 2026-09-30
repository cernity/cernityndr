"""file-yara scan logic (plan U6, Track A1). The pure decision and finding-
shaping functions are testable without yara-python; the isolated scan
wrapper import yara lazily so this module (and its pure tests) load without
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


def scan_bytes(registry, data, *, pcap_evidence_id=None, limits=None):
    """Scan each registry-selected active/shadow version in a bounded child.

    Snapshot metadata in the parent; SQLite locks/connections are never used by
    the child. A failed scan is an explicit error, never an empty successful scan.
    """
    import yara
    import workers
    from registry import IntegrityError
    results = []
    if registry is None:
        return results
    for row in registry.active_for_scan():
        result = {
            "ruleset_id": row["id"], "ruleset_version": row["version"],
            "ruleset_sha256": row["sha256"], "engine_version": yara.__version__,
            "status": row["status"], "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if pcap_evidence_id:
            result["pcap_evidence_id"] = pcap_evidence_id
        try:
            source = registry.load_bytes(row["id"])
        except (KeyError, IntegrityError):
            result.update(scan_error="ruleset_integrity", matches=[])
        else:
            result.update(workers.run_scan(source, data, row, limits or workers.Limits()))
        result["acted"] = (row["status"] == "active" and not result.get("scan_error")
                           and bool(result["matches"]))
        results.append(result)
    return results


def finding_from_results(event, results, tenant="default"):
    rules = sorted({m["rule"] for r in results if r["acted"] for m in r["matches"]})
    finding = finding_from_matches(event, rules, tenant)
    if finding:
        finding["yara_results"] = results
        finding["file_forensics"] = next((r["file_forensics"] for r in results
                                           if r["acted"] and "file_forensics" in r), {})
    return finding
