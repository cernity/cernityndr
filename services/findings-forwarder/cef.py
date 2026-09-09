"""Map a Cernity finding to ArcSight CEF (the lingua franca for syslog-based
SIEMs: QRadar, ArcSight, Devo-syslog, etc.)."""
import json


def _entities(finding):
    """Pull src/dst IPs out of the finding's entities list."""
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
        if e.get("role") == "src" and not src:
            src = e.get("value", "")
        elif e.get("role") == "dst" and not dst:
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
    ext_str = " ".join(f"{k}={_escape_ext(v)}" for k, v in ext.items() if v != "")
    header = f"CEF:0|{vendor}|{product}|{version}|{_escape(detector)}|{_escape(name)}|{sev}|"
    return header + ext_str
