"""OT/ICS protocol detectors (Modbus v1). Pure scoring — app.py keeps the
per-tenant/per-outstation state (authorized masters, seen pairings, enumeration
and error windows) and consumes suricata.modbus.v1. Each check is a pure
(fields) -> (hit, why) function so it is covered entirely by test_ot.py.

Rides on Suricata's native Modbus app-layer parse (logs, not packets): unauthorized
control, master novelty, function-code/unit-id recon, illegal-function bursts,
Modbus-off-502, and program/operating-mode transfer. Findings carry ATT&CK-for-ICS
technique IDs (T08xx).

EVE FIELD CAVEAT (honest, like east-west's kerberos handling): Suricata's Modbus EVE
field spelling varies by build, and older builds log a thin modbus object. `mb_fields`
extracts defensively across the known spellings and returns None for absent fields, so
a detector that needs a field it cannot see simply does not fire (dormant) rather than
guessing. Confirm the field names against a live Suricata modbus capture before treating
these as continuously armed. The fixture in tools/eve-feeder/fixtures/modbus-ot-eve.jsonl
is the assumed-schema contract these are validated against.
"""
from __future__ import annotations

# --- Modbus function-code map (the plan's flagged open question, made editable) ------
# Standard Modbus function codes grouped by intent. Vendor/program codes are the honest
# grey area: Schneider Unity uses 0x5A(90); Modicon program/config commonly ride 0x28(40)
# and 0x7D(125). Adjust here as the function-code reference pass firms up.
READ_FCS = frozenset({1, 2, 3, 4, 7, 11, 12, 17, 20, 24})       # coils/inputs/registers/diag read
WRITE_FCS = frozenset({5, 6, 15, 16, 21, 22, 23})               # coil/register/file writes
DIAGNOSTIC_FCS = frozenset({8})                                 # incl. force-listen-only / restart subfns
PROGRAM_MODE_FCS = frozenset({40, 90, 125})                     # vendor program-download / mode-change


def mb_fields(modbus: dict) -> dict:
    """Normalize a Suricata Modbus EVE `modbus` object to {fc, access, unit_id, is_error}
    across the known field spellings. Missing values are None (fc/unit_id) or "" (access) so
    downstream checks stay dormant instead of guessing. `is_error` is True when the record
    carries a Modbus exception (illegal function / illegal data address / etc.)."""
    m = modbus or {}
    fn = m.get("function")
    if isinstance(fn, dict):                                     # {"function": {"code": N, "raw": N}}
        fc = fn.get("code", fn.get("raw"))
    else:                                                        # {"function": N} or {"function_code": N}
        fc = fn if fn is not None else m.get("function_code")
    try:
        fc = int(fc) if fc is not None else None
    except (TypeError, ValueError):
        fc = None
    access = m.get("access_type") or m.get("access") or ""
    if isinstance(access, dict):                                 # {"access": {"type": "WRITE"}}
        access = access.get("type", "")
    unit = m.get("unit_id", m.get("unit", m.get("uid")))
    err = m.get("error_flags") or m.get("exception") or m.get("error") or m.get("errors")
    is_error = bool(err) and str(err).lower() not in ("0", "none", "false", "no_error", "")
    return {"fc": fc, "access": str(access).upper(), "unit_id": unit, "is_error": is_error}


def is_write_control(fc, access: str = "") -> bool:
    """A write/control operation: a write function code, or an access flag that says WRITE.
    (Suricata's access_type is a bitmask string; either signal is sufficient.)"""
    if fc in WRITE_FCS:
        return True
    return "WRITE" in (access or "").upper()


def is_program_or_mode(fc) -> bool:
    """Program-download / operating-mode-change control — vendor/reserved codes that a normal
    HMI polling loop never issues (T0858 / T0843)."""
    return fc in PROGRAM_MODE_FCS


def unauthorized_write(fc, access: str, src_is_authorized: bool) -> tuple[bool, str]:
    """R3.1 — write/control from a source not in the authorized-masters set for the outstation.
    The authorized decision is made stateful in app.py (learned baseline + config override);
    this stays pure on the boolean it produces. T0855 / T0831."""
    if src_is_authorized:
        return False, ""
    if is_write_control(fc, access):
        return True, f"unauthorized write fc={fc} access={access or '?'}"
    return False, ""


def program_download(fc, src_is_authorized: bool) -> tuple[bool, str]:
    """R3.6 — program-download / mode-change from a non-EWS (unauthorized) source. T0858 / T0843."""
    if not src_is_authorized and is_program_or_mode(fc):
        return True, f"program/mode transfer fc={fc}"
    return False, ""


def enumeration_hit(distinct_fcs: int, distinct_units: int,
                    fc_min: int = 6, unit_min: int = 4) -> tuple[bool, str]:
    """R3.3 — one source touching an abnormal breadth of function codes and/or unit IDs in a
    window (recon). A real HMI polls a small, stable fc/unit set; breadth is the signal.
    T0846."""
    if distinct_fcs >= fc_min:
        return True, f"fc enumeration: {distinct_fcs} distinct function codes"
    if distinct_units >= unit_min:
        return True, f"unit enumeration: {distinct_units} distinct unit IDs"
    return False, ""


def error_spike_hit(error_count: int, threshold: int = 5) -> tuple[bool, str]:
    """R3.4 — a burst of Modbus exceptions (illegal-function / illegal-data-address) from a
    source in the window: probing or misconfiguration."""
    if error_count >= threshold:
        return True, f"{error_count} modbus exceptions in window"
    return False, ""


def modbus_port_anomaly(dst_port, allow_ports=frozenset()) -> tuple[bool, str]:
    """R3.5 — a Modbus transaction on a port other than 502 (and not operator-allowlisted): the
    protocol showing up where it is not expected. T0885. The complementary case (non-Modbus on
    502) is covered by the existing port_proto_mismatch primitive in protocol-detectors."""
    try:
        port = int(dst_port)
    except (TypeError, ValueError):
        return False, ""
    if port == 502 or port in allow_ports:
        return False, ""
    return True, f"modbus on port {port} (expected 502)"
