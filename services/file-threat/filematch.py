"""File-based malware detection (re-eval gap G2). Consumes suricata.file.v1
(fileinfo with sha256 — force-hash enabled on the sensor), matches file hashes
against a malware-hash feed (abuse.ch MalwareBazaar), and flags risky executable
delivery over cleartext. Pure matching is testable; app.py is the I/O + feed shell.
"""
import json

# EICAR standard antivirus test file — always matchable, for validation.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

_EXEC_MIMES = (
    "application/x-dosexec", "application/x-msdownload",
    "application/vnd.microsoft.portable-executable", "application/x-elf",
    "application/x-executable", "application/x-mach-binary", "application/x-sharedlib",
)


def hash_hit(fi: dict, malware_hashes: set):
    """Return the matched hash if any of the file's md5/sha1/sha256 is known-bad."""
    for alg in ("sha256", "sha1", "md5"):
        h = (fi.get(alg) or "").lower()
        if h and h in malware_hashes:
            return h
    return None


def risky_delivery(fi: dict) -> bool:
    """Executable/binary content transferred — suspicious even without a hash hit."""
    return (fi.get("mime_type") or "").lower() in _EXEC_MIMES


def hash_is_complete(fi: dict) -> bool:
    """Whether the file was fully captured, so its SHA256 can be trusted for
    whole-file malware-hash matching. Fail closed: require positive evidence of a
    clean capture. A hash is authoritative only when the file closed cleanly
    (explicit state CLOSED), had no gaps (explicit gaps false), started at byte 0
    if a start offset is given, and a sha256 is present. Missing state or missing
    gaps is treated as NOT complete, not assumed complete. Anything else is a
    partial-content hash that will not match a full-file hash, so it must not
    drive a whole-file threat-feed match (file-yara still scans the reassembled
    bytes for content, and the finding carries hash_complete either way)."""
    if not fi.get("sha256"):
        return False
    if str(fi.get("state", "")).upper() != "CLOSED":     # fail closed: require explicit CLOSED
        return False
    if fi.get("gaps") is not False:                      # fail closed: require explicit gaps=false
        return False
    start = fi.get("start")
    if start is not None:
        try:
            if int(start) != 0:
                return False
        except (TypeError, ValueError):
            return False
    return True


def join_key_entities(eve: dict) -> list[dict]:
    """community_id/flow_id join a finding back to the exact connection's
    flow/tls/dns telemetry in ClickHouse (metadata enrichment, no capture).
    Only added when the source event carries them. Keep in sync with the same
    helper in ids-alerts/promote.py and threat-intel/app.py."""
    out = []
    if eve.get("community_id"):
        out.append({"type": "community_id", "value": eve["community_id"]})
    if eve.get("flow_id"):
        out.append({"type": "flow_id", "value": eve["flow_id"]})
    return out


def to_candidate(eve: dict, malware_hashes: set, tenant: str = "default") -> dict | None:
    if eve.get("event_type") != "fileinfo":
        return None
    fi = eve.get("fileinfo") or {}
    src, dst = eve.get("src_ip"), eve.get("dest_ip")
    complete = hash_is_complete(fi)
    # Only a fully-captured file can assert a whole-file malware-hash match; a
    # partial hash from a truncated/gapped/mid-stream file must never produce
    # file_malware_hash (it would be a false verdict and would spend capture
    # budget). Such a file can still surface as risky_file_delivery, and file-yara
    # covers its content.
    hit = hash_hit(fi, malware_hashes) if complete else None
    if hit:
        det, sev, conf, label = "file_malware_hash", 9, 0.95, hit
    elif risky_delivery(fi):
        det, sev, conf, label = "risky_file_delivery", 6, 0.5, fi.get("mime_type")
    else:
        return None
    ents = [{"type": "ip", "role": "src", "value": src},
            {"type": "ip", "role": "dst", "value": dst},
            {"type": "filename", "value": fi.get("filename")},
            {"type": "mime", "value": fi.get("mime_type")},
            {"type": "sha256", "value": fi.get("sha256")},
            {"type": "hash_complete", "value": complete},
            {"type": "match", "value": label}]
    ents += join_key_entities(eve)
    entities = json.dumps(ents)
    return {"finding_id": f"{det}-{abs(hash((label, src, dst))) % 10**10}",
            "tenant_id": tenant, "detector_id": det, "detector_version": "1.0",
            "category": "malware", "severity": sev, "confidence": conf,
            "entities": entities, "state": "CANDIDATE"}
