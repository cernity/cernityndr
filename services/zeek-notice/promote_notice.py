"""Promote Zeek notice.log detections to NDR finding candidates.

Zeek's notice.log IS Zeek's detection output: the Intel framework raising a
notice on an IOC hit, certificate-validation failures, scan detections, and
package notices (JA3/JA4, etc). It is Zeek's equivalent of a Suricata signature
alert, and from a Detection-Engineering standpoint it is a first-class detection
source that belongs in the SIEM.

Not every notice is a detection, though. Zeek's notice framework also emits
operational/health notices about the sensor itself -- capture loss
(CaptureLoss::Too_Much_Loss), packet-filter problems, software inventory. Per the
SIEM/DE team, those are NOT detections and must be dropped: the SIEM only wants
the detection notices (Intel hits, cert problems, scans, package detections). So
promotion is permissive for detection notices (an unknown detection notice still
promotes) but drops the operational-notice denylist first. The denylist is
tunable via NDR_ZEEK_NOTICE_DROP so the DE team can adjust without a code change.

Pure and testable; app.py is the Kafka I/O shell. A "notice" here is one parsed
notice.log record (dict), whether Zeek emitted it as JSON or Vector parsed the
TSV. Field names follow Zeek's notice.log: note, msg, sub, src, dst, id.orig_h,
id.resp_h, uid.
"""
import json
import os

# Operational / health notices are NOT detections (SIEM/DE team feedback): the
# sensor talking about itself, not detecting a threat. Dropped before promotion.
# Tunable via NDR_ZEEK_NOTICE_DROP (comma-separated note-type prefixes). Capture
# loss is not discarded knowledge -- it is a coverage/health signal (see the
# SPAN/mirror-completeness data-quality path) -- it just is not a detection.
_DROP_PREFIXES = tuple(x.strip() for x in os.environ.get(
    "NDR_ZEEK_NOTICE_DROP", "CaptureLoss,PacketFilter,Software").split(",") if x.strip())


def is_operational(note: str) -> bool:
    """True for health/operational notices that are not detections (dropped)."""
    return any(note == d or note.startswith(d + "::") for d in _DROP_PREFIXES)

# Exact Zeek notice type -> (our category, severity 1..10).
_NOTE_MAP = {
    "Intel::Notice": ("c2", 8),                       # fed-IOC match (addr/domain/hash/cert)
    "SSL::Invalid_Server_Cert": ("c2", 6),
    "SSL::Certificate_Expired": ("c2", 5),
    "SSL::Weak_Key": ("c2", 5),
    "SSL::Old_Version": ("c2", 4),
    "Scan::Address_Scan": ("recon", 5),
    "Scan::Port_Scan": ("recon", 5),
    "Traceroute::Detected": ("recon", 4),
    "TeamCymruMalwareHashRegistry::Match": ("malware", 9),
    "Signatures::Sensitive_Signature": ("c2", 6),
}
# Fallback on the framework prefix before "::" when the exact note is unknown.
_PREFIX_MAP = {
    "Intel": ("c2", 8),
    "SSL": ("c2", 5),
    "X509": ("c2", 5),
    "Scan": ("recon", 5),
    "Signatures": ("c2", 6),
    "SMB": ("lateral", 6),
    "Kerberos": ("credential_access", 6),
    "DNS": ("c2", 5),
    "HTTP": ("c2", 5),
    "Weird": ("anomaly", 4),
}
_DEFAULT = ("malware", 6)


def classify(note: str) -> tuple[str, int]:
    """Map a Zeek notice type to (category, severity)."""
    if note in _NOTE_MAP:
        return _NOTE_MAP[note]
    prefix = note.split("::", 1)[0]
    return _PREFIX_MAP.get(prefix, _DEFAULT)


def _endpoints(notice: dict) -> tuple[str | None, str | None]:
    """Prefer the notice's explicit src/dst, else the connection endpoints."""
    src = notice.get("src") or notice.get("id.orig_h")
    dst = notice.get("dst") or notice.get("id.resp_h")
    src = None if src in (None, "", "-") else src
    dst = None if dst in (None, "", "-") else dst
    return src, dst


def join_key_entities(notice: dict) -> list[dict]:
    """community_id/uid join the finding back to the exact connection (metadata
    enrichment, no capture). Zeek emits `uid`; `community_id` when configured."""
    out = []
    if notice.get("community_id"):
        out.append({"type": "community_id", "value": notice["community_id"]})
    if notice.get("uid"):
        out.append({"type": "zeek_uid", "value": notice["uid"]})
    return out


def to_candidate(notice: dict, tenant: str = "default") -> dict | None:
    """Map one Zeek notice.log record to an ndr.finding.candidate.v1, or None."""
    note = str(notice.get("note") or "").strip()
    if not note or note == "-":
        return None
    if is_operational(note):
        return None                              # health/ops notice, not a detection
    src, dst = _endpoints(notice)
    category, severity = classify(note)
    msg = notice.get("msg") or ""
    sub = notice.get("sub") or ""               # often the matched IOC value
    ents = [{"type": "ip", "role": "src", "value": src},
            {"type": "ip", "role": "dst", "value": dst},
            {"type": "zeek_notice", "value": note},
            {"type": "msg", "value": msg}]
    if sub and sub != "-":
        ents.append({"type": "indicator", "value": sub})
    ents += join_key_entities(notice)
    return {"finding_id": f"zeeknotice-{abs(hash((note, src, dst, msg))) % 10**10}",
            "tenant_id": tenant, "detector_id": "zeek_notice", "detector_version": "1.0",
            "category": category, "severity": severity, "confidence": 0.8,
            "entities": json.dumps(ents), "state": "CANDIDATE"}


def parse_notice_tsv(text: str) -> list[dict]:
    """Parse a Zeek TSV notice.log (#fields header) into row dicts. For the path
    where the promoter reads notice.log directly rather than JSON off the bus."""
    fields: list[str] = []
    rows: list[dict] = []
    for line in text.splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#") or not line.strip() or not fields:
            continue
        cols = line.split("\t")
        rows.append({fields[i]: cols[i] for i in range(min(len(fields), len(cols)))})
    return rows
