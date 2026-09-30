"""Executable delivery detection and shared file completeness/feed primitives.
Hash verdicts are emitted only by threat-intel under the managed lifecycle.
"""
import hashlib
import json
import time


def _stable(*parts) -> int:
    """Stable cross-process id (F07): built-in hash() is PYTHONHASHSEED-randomized, so
    the same file match produced a different finding_id per process and dedup never fired."""
    s = "|".join("" if p is None else str(p) for p in parts)
    return int(hashlib.sha1(s.encode()).hexdigest()[:15], 16) % 10**10

# EICAR standard antivirus test file — always matchable, for validation.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

_EXEC_MIMES = (
    "application/x-dosexec", "application/x-msdownload",
    "application/vnd.microsoft.portable-executable", "application/x-elf",
    "application/x-executable", "application/x-mach-binary", "application/x-sharedlib",
)


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


def to_candidate(eve: dict, malware_hashes: set | None = None, tenant: str = "default") -> dict | None:
    """Risky delivery only; malware_hashes is a compatibility argument, unused."""
    if eve.get("event_type") != "fileinfo":
        return None
    fi = eve.get("fileinfo") or {}
    src, dst = eve.get("src_ip"), eve.get("dest_ip")
    complete = hash_is_complete(fi)
    # Hash intel is owned exclusively by the managed threat-intel matcher.
    if risky_delivery(fi):
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
    ts = eve.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {"finding_id": f"{det}-{_stable(label, src, dst)}",
            "tenant_id": tenant, "detector_id": det, "detector_version": "1.0",
            "category": "malware", "severity": sev, "confidence": conf,
            "first_seen": ts, "last_seen": ts,
            "entities": entities, "state": "CANDIDATE"}


MALWAREBAZAAR_URL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"


def malware_feed_spec(url=MALWAREBAZAAR_URL):
    """Register the former file-threat feed with the managed intel lifecycle."""
    return {"connector": "abusech", "variant": "malwarebazaar", "url": url,
            "source_trust": 0.9, "tlp": "green", "ttl_days": 1.0}


def parse_malware_hashes(text):
    import re
    return {line.strip().lower() for line in text.splitlines()
            if re.fullmatch(r"[a-fA-F0-9]{64}", line.strip())}
