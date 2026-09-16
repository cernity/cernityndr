"""Map a Cernity finding to ArcSight CEF (the lingua franca for syslog-based
SIEMs: QRadar, ArcSight, Devo-syslog, etc.).

CEF is a COMPACT transport, not a full-fidelity JSON container (handoff §6.9): it carries the
pivot fields an analyst needs in the SIEM (endpoints, finding id, mitre, tenant, revision, reverse
DNS, an evidence pointer) and deliberately OMITS the rich enrichment blob (Zeek summary/iocs, full
reputation, per-provider intel). Those travel intact on the JSON/ES sink — the full-fidelity
companion — and via the `flexString1` MinIO evidence link. This is an explicit, documented mapping,
not a claim of lossless CEF delivery."""
import json

# Entity roles that name the two endpoints, normalized to CEF src/dst. SLIPS emits
# attacker/victim (handoff §4); OT emits src/dst; some detectors use responder/scanner.
_SRC_ROLES = ("src", "attacker", "scanner", "responder")
_DST_ROLES = ("dst", "victim", "target")


def _entities(finding):
    """Pull the (src, dst) endpoint IPs out of the finding's entities list, honoring the
    attacker/victim aliases so SLIPS findings are not left without endpoints."""
    src = dst = ""
    ents = finding.get("entities")
    if isinstance(ents, str):
        try:
            ents = json.loads(ents)
        except (ValueError, TypeError):
            ents = []
    for e in ents or []:
        if not isinstance(e, dict):
            continue
        role = e.get("role")
        if role in _SRC_ROLES and not src:
            src = e.get("value", "")
        elif role in _DST_ROLES and not dst:
            dst = e.get("value", "")
    return src, dst


def _escape(v):
    return str(v).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _escape_ext(v):
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")


def to_cef(finding, vendor="Cernity", product="NDR", version="1.0"):
    """Return a CEF:0 line for a finding. Severity maps the finding's 0-10 scale
    straight onto CEF's 0-10."""
    detector = finding.get("detector_id", "unknown")
    name = finding.get("category", "finding")
    sev = finding.get("severity", 0)
    src, dst = _entities(finding)
    mitre = finding.get("mitre") or []
    if isinstance(mitre, list):
        mitre = ",".join(str(m) for m in mitre)
    ext = {
        "cs1": finding.get("finding_id", ""), "cs1Label": "findingId",
        "cs2": mitre, "cs2Label": "mitre",
        "cs3": finding.get("tenant_id", ""), "cs3Label": "tenant",
        "cat": finding.get("category", ""),
    }
    if src:
        ext["src"] = src
    if dst:
        ext["dst"] = dst
    # revision: distinguishes an enriched/timeout re-delivery from the original (R03).
    rev = finding.get("revision")
    if rev not in (None, ""):
        ext["cs4"] = rev
        ext["cs4Label"] = "revision"
    # reverse-DNS enrichment -> CEF's standard DNS-domain keys, keyed by the endpoint IP.
    rdns = (finding.get("intel") or {}).get("rdns") or {}
    if src and rdns.get(src):
        ext["sourceDnsDomain"] = rdns[src]
    if dst and rdns.get(dst):
        ext["destinationDnsDomain"] = rdns[dst]
    # evidence pointer: the first ref (e.g. MinIO pcap) — the analyst's link to the full context
    # CEF cannot carry. The complete finding (Zeek summary/iocs, full intel) rides the JSON sink.
    refs = finding.get("evidence_refs") or []
    if refs:
        ext["flexString1"] = refs[0]
        ext["flexString1Label"] = "evidence"
    # provenance pivot: CEF carries only the community_id (from the finding's source_events) — the
    # full originating EVE (source_events) rides the JSON/ES sink; CEF is a documented subset.
    se = finding.get("source_events") or []
    cid = se[0].get("community_id") if se and isinstance(se[0], dict) else None
    if cid:
        ext["cs5"] = cid
        ext["cs5Label"] = "communityId"
    ext_str = " ".join(f"{k}={_escape_ext(v)}" for k, v in ext.items() if v != "")
    header = f"CEF:0|{vendor}|{product}|{version}|{_escape(detector)}|{_escape(name)}|{sev}|"
    return header + ext_str
