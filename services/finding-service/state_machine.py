"""Finding lifecycle state machine (plan U9; v2 §17).

Pure logic: candidate -> enrichment decision -> terminal state. The I/O shell
(app.py) consumes ndr.finding.candidate.v1, persists to ClickHouse, and emits
ndr.finding.final.v1 / ndr.capture.request.v1. A failed enrichment must never
erase a valid first-stage finding.
"""
from __future__ import annotations

import os

# Delivery-suppression ceiling (ce-doc-review B2). A finding at or below this
# severity, from a detector that is not a confirmed-threat source, is kept in the
# store and still emitted to ndr.finding.final.v1 (so the correlation service can
# still build a kill-chain from it) but is NOT delivered to the analyst/SIEM
# plane. This is what makes the threat gate reduce analyst-facing volume instead
# of only re-ranking it: a benign beacon (severity ~5) is suppressed, while a
# beacon the gate raised to 7 because the destination looked hostile is delivered.
SUPPRESS_MAX_SEVERITY = int(os.environ.get("NDR_SUPPRESS_MAX_SEVERITY", "5"))

# MITRE ATT&CK mapping, applied when defensible (v2 §17).
CATEGORY_MITRE = {
    "recon": ["T1046"],            # Network Service Discovery
    "c2": ["T1071"],              # Application Layer Protocol
    "dns_tunnel": ["T1071.004"],  # DNS
    "lateral": ["T1021"],         # Remote Services
    "exfil": ["TA0010"],          # Exfiltration
    "bruteforce": ["T1110"],      # Brute Force
}

LIFECYCLE = {"CANDIDATE", "SCORED", "CAPTURE_REQUESTED", "ENRICHED",
             "ENRICHMENT_FAILED", "SUPPRESSED", "FINAL", "DEVO_QUEUED", "DEVO_SENT"}


CONFIRMED_THREAT_SOURCES = ("ids_signature", "threat_intel", "file_malware_hash")


def decide_enrichment(cand: dict) -> str:
    """metadata_sufficient | packets_needed (v2 §18.1).

    Two reasons to capture packets:
      - adjudication: low-confidence content findings, to decide.
      - evidence (G3): findings from an external threat authority — an IDS
        signature, a threat-intel IOC hit, or a known-bad file hash — are
        confirmed-serious, so we capture the session/files/JA3/cert for the
        analyst REGARDLESS of confidence, not only the ambiguous ones.
    nDPI risk is a low-confidence feature, not a confirmed threat: on its own it
    does not spend capture budget; corroboration by another detector on the same
    entity is what escalates it. Recon/scan is answerable from metadata."""
    cat = cand.get("category")
    det = cand.get("detector_id")
    conf = float(cand.get("confidence", 0) or 0)
    if cat == "recon":
        return "metadata_sufficient"
    if det == "ndpi_risk":
        return "metadata_sufficient"     # low-confidence feature; corroboration escalates, not capture
    if det in CONFIRMED_THREAT_SOURCES:
        return "packets_needed"          # evidence capture, any confidence
    if conf >= 0.9:
        return "metadata_sufficient"
    return "packets_needed"


def suppress_delivery(cand: dict) -> bool:
    """Delivery suppression (ce-doc-review B2). A low-severity finding with no
    threat anchoring is delivery-suppressed: kept in the store and still emitted
    to final.v1 for the correlation service, but not delivered to the analyst
    plane. Confirmed-threat sources are never suppressed, and any finding the
    threat gate raised above the ceiling (because the destination looked hostile)
    is delivered."""
    if cand.get("detector_id") in CONFIRMED_THREAT_SOURCES:
        return False
    return int(cand.get("severity", 10) or 10) <= SUPPRESS_MAX_SEVERITY


def build_finding(cand: dict) -> tuple[dict, str]:
    """CANDIDATE -> enrichment policy -> terminal state. Returns (finding, route)
    where route is 'final' or 'capture'."""
    policy = decide_enrichment(cand)
    f = dict(cand)
    f.setdefault("sensor_ids", [])
    f.setdefault("evidence_refs", [])
    f["mitre"] = CATEGORY_MITRE.get(cand.get("category"), [])
    f["capture_job_ids"] = []
    f["suppression_reason"] = ""
    if policy == "metadata_sufficient":
        f["enrichment_state"] = "NOT_REQUIRED"
        if suppress_delivery(cand):
            # Still emitted to final.v1 (correlation sees it) and persisted for
            # audit/hunting, but not delivered to the analyst/SIEM plane.
            f["state"] = "SUPPRESSED"
            f["devo_delivery_state"] = "SUPPRESSED"
            f["suppression_reason"] = (
                f"low-severity ({f.get('severity')}) non-threat finding; kept for "
                "correlation and audit, not delivered")
        else:
            f["state"] = "FINAL"
            f["devo_delivery_state"] = "QUEUED"
        return f, "final"
    f["enrichment_state"] = "REQUIRED"
    f["state"] = "CAPTURE_REQUESTED"
    f["devo_delivery_state"] = "NONE"
    return f, "capture"


def apply_enrichment_result(finding: dict, result: dict) -> dict:
    """Merge an enrichment result (U11) back onto a CAPTURE_REQUESTED finding.
    A failed enrichment still FINALizes — it never drops the finding (v2 §17)."""
    f = dict(finding)
    if result.get("status") == "ok":
        f["enrichment_state"] = "ENRICHED"
        f["evidence_refs"] = list(f.get("evidence_refs", [])) + result.get("evidence_refs", [])
    else:
        f["enrichment_state"] = "ENRICHMENT_FAILED"
    f["state"] = "FINAL"
    f["devo_delivery_state"] = "QUEUED"
    return f
