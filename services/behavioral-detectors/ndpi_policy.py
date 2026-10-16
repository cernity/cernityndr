"""Structured nDPI flow-risk parsing (plan 008 U1). Pure: turn the Suricata nDPI
`ndpi` object into typed risk entries the classifier (U2) and emitter (U3) can use,
preserving the native severity tier + risk_score that the legacy names-only path
(`app._ndpi_risks`) throws away.

The deployed producer (Suricata 8.0.6 built-in nDPI) emits the canonical shape
    "flow_risk": {"<id>": {"risk": <name>, "severity": <tier>,
                           "risk_score": {"total": n, "client": n, "server": n}}}
Older/custom builds may use `risk` instead, or degenerate {id: name} / {name: true} /
list shapes. `flow_risk` is preferred; `risk` is a fallback ONLY when flow_risk is
absent — a legacy value must never silently override the canonical one. Nothing here
does I/O, evals a string, or raises on bad input: a malformed risk is kept with a
`malformed` reason so one broken entry never discards its siblings.

`score_scope` stays "unverified" until U0 confirms the serializer's score semantics
(the enum-vs-bitmask ndpi_risk2score question); scores are evidence only (KTD2).
"""
from __future__ import annotations
import numbers
from itertools import islice

MAX_RISKS = 64          # > the whole nDPI risk enum; a larger set is malformed/hostile input
MAX_NAME = 200          # bound a single risk name

# nDPI severity tiers (KTD2). An unmapped/unknown tier is preserved but flagged, never guessed.
TIERS = ("Low", "Medium", "High", "Severe", "Critical", "Emergency")


def _num(v):
    """A finite, non-negative int/float, else None. bool is explicitly not a number.
    A hostile int can be too large for a float (10**400), so the conversion is the
    test, not a precondition — it drops that component and leaves the siblings."""
    if isinstance(v, bool) or not isinstance(v, numbers.Real):
        return None
    try:
        f = float(v)
    except (OverflowError, ValueError):
        return None
    if f != f or f in (float("inf"), float("-inf")) or f < 0:   # NaN / +/-inf / negative
        return None
    return v


def _score(rs):
    """risk_score object -> {total,client,server} keeping only valid components."""
    if not isinstance(rs, dict):
        return {}
    out = {}
    for k in ("total", "client", "server"):
        n = _num(rs.get(k))
        if n is not None:
            out[k] = n
    return out


def _entry(rid, name, severity=None, score=None, source="flow_risk", malformed=None,
           max_name=MAX_NAME):
    e = {
        "id": str(rid) if rid is not None else None,
        "name": name[:max_name] if isinstance(name, str) and max_name else name,
        "severity": severity if isinstance(severity, str) else None,   # raw native tier, preserved
        "severity_known": isinstance(severity, str) and severity in TIERS,
        "score": _score(score),
        "score_scope": "unverified",
        "source": source,
    }
    if isinstance(severity, str) and severity not in TIERS and not malformed:
        malformed = f"unknown severity tier {severity!r}"
    if malformed:
        e["malformed"] = malformed
    return e


# MAX_RISKS bounds the ENTRIES INSPECTED, not the result length: a hostile 10k-entry
# risk set must not be walked at all, and entries that produce no output ({name: false}
# membership flags, bools in a list) still cost a traversal step — so both loops slice
# the container itself instead of stopping once the output is full.
def _from_mapping(m, source, max_name):
    """A flow_risk/risk dict: {id: {risk,severity,risk_score}} | {id: name} | {name: true}.
    Value type disambiguates: dict -> full risk; str -> id:name; bool -> membership flag."""
    out = []
    for k, v in islice(m.items(), MAX_RISKS):
        if isinstance(v, dict):
            name = v.get("risk")
            if not isinstance(name, str):
                out.append(_entry(k, None, source=source, malformed="risk name missing or not a string"))
            else:
                out.append(_entry(k, name, v.get("severity"), v.get("risk_score"), source,
                                  max_name=max_name))
        elif isinstance(v, bool):                     # {name: true} — false contributes no risk
            if v:
                out.append(_entry(None, str(k), source=source, max_name=max_name))
        elif isinstance(v, str):                       # {id: name}
            out.append(_entry(k, v, source=source, max_name=max_name))
        else:
            out.append(_entry(k, None, source=source, malformed=f"unsupported risk value {type(v).__name__}"))
    return out


def _from_list(lst, source, max_name):
    out = []
    for v in islice(lst, MAX_RISKS):
        if isinstance(v, dict):
            name = v.get("risk")
            out.append(_entry(v.get("id"), name if isinstance(name, str) else None,
                              v.get("severity"), v.get("risk_score"), source,
                              None if isinstance(name, str) else "risk name missing or not a string",
                              max_name=max_name))
        elif isinstance(v, bool):
            continue
        elif isinstance(v, str):                       # a legacy stringified dict stays an opaque name; never eval'd
            out.append(_entry(None, v, source=source, max_name=max_name))
        else:
            out.append(_entry(None, None, source=source, malformed=f"unsupported risk value {type(v).__name__}"))
    return out


def parse_risk_value(raw, source, max_name=MAX_NAME):
    """Parse one risk CONTAINER (the value of `flow_risk` or `risk`) into entries.

    Split out from parse_ndpi_risks because the two consumers pick the field
    differently: the structured classifier prefers canonical `flow_risk`, while the
    legacy detector must keep its own historical `risk`-first precedence. The shape
    handling itself — every variant, bounded, malformed-tolerant — stays shared.
    `max_name=None` disables name truncation for the legacy path, whose matcher has
    always seen the sensor's full string.
    """
    if isinstance(raw, dict):
        return _from_mapping(raw, source, max_name)
    if isinstance(raw, list):
        return _from_list(raw, source, max_name)
    if isinstance(raw, bool) or raw is None:
        return []
    if isinstance(raw, str):
        return [_entry(None, raw, source=source, max_name=max_name)]
    return [_entry(None, None, source=source, malformed=f"unsupported {source} container {type(raw).__name__}")]


def parse_ndpi_risks(ndpi):
    """Bounded list of structured risk entries from an EVE `ndpi` object.

    Prefer canonical `flow_risk`; fall back to legacy `risk` only when flow_risk is
    absent (never merge both). A non-dict `ndpi`, or no risk field, yields []. The
    traversal is capped at MAX_RISKS; a set that large is malformed input.
    """
    if not isinstance(ndpi, dict):
        return []
    src = "flow_risk" if "flow_risk" in ndpi else ("risk" if "risk" in ndpi else None)
    if src is None:
        return []
    return parse_risk_value(ndpi.get(src), src)


# --- U2: versioned classification (plan 008 KTD1-KTD3) --------------------------
# Turn a parsed risk (or a risky protocol breed) into an honest Cernity verdict:
# category by risk TYPE, severity derived from the native tier (never a constant),
# confidence an uncalibrated policy weight (KTD2). No substring matching — exact
# normalized-name rules only; an unknown name is `unclassified`, never guessed as
# malware. Categories: observation (feature/heuristic, no harm claim), policy
# (actionable hygiene/config), anomaly (suspected threat indicator), exploit
# (possible attempt), unclassified (meaning unresolved). Pure, no I/O.
POLICY_VERSION = "ndpi-classification-v1"
DETECTOR_VERSION = "2.0"

# native nDPI severity tier -> Cernity base severity, before the rule's clamp (KTD2).
_TIER_SEV = {"Low": 2, "Medium": 4, "High": 6, "Severe": 7, "Critical": 8, "Emergency": 9}
# category -> uncalibrated confidence weight (KTD2). NOT a probability.
_CONF = {"policy": 0.80, "anomaly": 0.50, "exploit": 0.50, "observation": 0.20, "unclassified": 0.20}

# Exact rule table, keyed by normalized risk name. severity is either a fixed int or a
# (lo, hi) band that the native tier is mapped into then clamped. `verified` marks the
# eight names confirmed against the deployed producer (U0 manifest, 2026-09-24); the
# rest are provisional standard-nDPI names pending U0 enum verification (OQ2) — until
# then an unseen name still falls through to `unclassified`, so a wrong guess is safe.
_RULES = {
    # --- verified observed (U0 manifest) — hygiene/heuristic, honest low severity ---
    "known proto on non std port": ("observation", 2, "emit_low", True),
    "http susp user-agent": ("observation", 2, "emit_low", True),
    "tls (probably) not carrying https": ("observation", 2, "emit_low", True),
    "missing sni tls extn": ("observation", 2, "emit_low", True),
    "tls fatal alert": ("observation", 2, "emit_low", True),
    "susp entropy": ("observation", 2, "emit_low", True),
    "unidirectional traffic": ("observation", 2, "emit_low", True),
    "minor issues": ("observation", 2, "emit_low", True),
    # --- provisional (verify names against the Suricata-8.0.6 nDPI enum in U0) ---
    "smb insecure version": ("policy", 3, "emit", False),
    "clear-text credentials": ("policy", (2, 5), "emit", False),
    "obsolete tls version (1.1 or older)": ("policy", (2, 5), "emit", False),
    "weak tls cipher": ("policy", (2, 5), "emit", False),
    "tls certificate expired": ("policy", (2, 5), "emit", False),
    "self-signed certificate": ("observation", 2, "emit_low", False),
    "punycode idn": ("observation", 2, "emit_low", False),
    "malicious ja3 fingerprint": ("anomaly", (3, 7), "emit", False),
    "malicious sha1 certificate": ("anomaly", (3, 7), "emit", False),
    "suspicious dga domain": ("anomaly", (3, 7), "emit", False),
    "possible exploit": ("exploit", (4, 8), "emit", False),
}

RISKY_BREEDS = ("dangerous", "potentially dangerous", "unsafe")


def _norm(name):
    return " ".join(str(name).lower().split()) if isinstance(name, (str, int)) else ""


def _severity(mode, tier):
    """Resolve a rule severity: a fixed int as-is, or map the native tier into (lo,hi) and clamp."""
    if isinstance(mode, int):
        return mode
    lo, hi = mode
    base = _TIER_SEV.get(tier, lo)     # missing/unknown tier -> band floor (recorded elsewhere)
    return max(lo, min(hi, base))


def _verdict(category, severity, disposition, rule, severity_basis, verified):
    return {
        "category": category,
        "severity": int(severity),
        "confidence": _CONF[category],
        "confidence_basis": category,
        "calibrated": False,
        "disposition": disposition,          # emit | emit_low (both delivered; emit_low hidden by Vantage default)
        "rule": rule,
        "severity_basis": severity_basis,    # "native_tier" | "fixed" | "band_floor" | "fallback"
        "policy_version": POLICY_VERSION,
        "verified": verified,                # rule confirmed against the deployed producer?
    }


def classify_ndpi_risk(entry):
    """Classify one parsed risk entry (from parse_ndpi_risks) -> verdict dict (KTD1/KTD2).
    Unknown name -> unclassified/1 (delivered + counted, visibly unresolved), never malware."""
    rule = _RULES.get(_norm(entry.get("name")))
    if rule is None:
        return _verdict("unclassified", 1, "emit_low", "unclassified", "fallback", verified=False)
    category, mode, disposition, verified = rule
    tier = entry.get("severity") if entry.get("severity_known") else None
    sev = _severity(mode, tier)
    basis = "fixed" if isinstance(mode, int) else ("native_tier" if tier else "band_floor")
    return _verdict(category, sev, disposition, _norm(entry.get("name")), basis, verified)


def classify_breed(breed, proto=""):
    """Classify a risky nDPI protocol breed (the deployed SMBv1 case rides here, not flow_risk):
    a Dangerous/Unsafe breed on SMBv1 is a real hygiene finding (policy/3); any other risky
    breed is a generic `observation`. A safe/unrated breed is not a finding -> None."""
    if not breed or _norm(breed) not in RISKY_BREEDS:
        return None
    if "smbv1" in _norm(proto):
        return _verdict("policy", 3, "emit", "breed:smbv1", "fixed", verified=True)
    return _verdict("observation", 2, "emit_low", f"breed:{_norm(breed)}", "fixed", verified=True)


# --- U3: candidate assembly (plan 008 KTD4/KTD5) --------------------------------
# Pure: an EVE `ndpi` object -> Cernity finding args, one per emitting CATEGORY per
# flow (KTD4 — not one per arbitrary risk combination), max severity within it, with
# the contributing rules and a bounded `ndpi_evidence` object (KTD5). `identity` is a
# stable string (tenant/sensor/src/dst/transport/dport/category/sorted-rule-ids/policy
# version/severity) that the emitter hashes; mutable score/order/raw evidence is kept
# OUT of it so repeats don't multiply findings. app.py owns dedup, I/O, and delivery.
MAX_EVIDENCE = 16          # bounded contributing-rule evidence entries per finding


def _evidence(entry, verdict):
    return {"rule": verdict["rule"], "name": entry.get("name"), "id": entry.get("id"),
            "native_severity": entry.get("severity"), "score": entry.get("score"),
            "score_scope": entry.get("score_scope"), "category": verdict["category"],
            "severity": verdict["severity"], "severity_basis": verdict["severity_basis"]}


def ndpi_findings(ndpi, src, dst, tenant, sensor=None, transport=None, dport=None):
    """List of finding args (one per emitting category) for the structured classifier.
    Each item: {category, severity, confidence, disposition, entities (list), identity,
    rules, verified}. Empty when there is no risk/breed to report."""
    verdicts = []
    for e in parse_ndpi_risks(ndpi):
        if not e.get("name"):                      # malformed w/o a name: counted upstream, no standalone finding
            continue
        v = classify_ndpi_risk(e)
        v["_entry"] = e
        verdicts.append(v)
    if isinstance(ndpi, dict):
        bv = classify_breed(ndpi.get("breed") or "", ndpi.get("proto") or "")
        if bv:
            bv["_entry"] = {"name": bv["rule"], "severity": None, "id": None, "score": {},
                            "score_scope": "unverified"}
            verdicts.append(bv)
    if not verdicts:
        return []

    by_cat = {}
    for v in verdicts:
        g = by_cat.setdefault(v["category"], {"sev": 0, "conf": 0.0, "disp": v["disposition"],
                                              "rules": [], "ev": [], "verified": True})
        if v["severity"] > g["sev"]:               # represent the category by its most severe rule
            g["sev"], g["conf"], g["disp"] = v["severity"], v["confidence"], v["disposition"]
        g["rules"].append(v["rule"])
        g["verified"] = g["verified"] and v["verified"]
        if len(g["ev"]) < MAX_EVIDENCE:
            g["ev"].append(_evidence(v["_entry"], v))

    out = []
    for cat, g in sorted(by_cat.items()):
        rules = sorted({r for r in g["rules"] if r})
        names = sorted({e["name"] for e in g["ev"] if e.get("name")})
        entities = [
            {"type": "ip", "role": "src", "value": src},
            {"type": "ip", "role": "dst", "value": dst},
            {"type": "ndpi_risk", "value": names},                         # legacy-compatible list of names
            {"type": "ndpi_evidence", "value": {                           # KTD5 structured evidence
                "evidence_version": 1, "policy_version": POLICY_VERSION,
                "detector_version": DETECTOR_VERSION, "category": cat,
                "confidence_basis": cat, "calibrated": False, "risks": g["ev"]}},
        ]
        identity = "|".join(str(x) for x in
                            [tenant, sensor or "", src, dst, transport or "", dport or "",
                             cat, ",".join(rules), POLICY_VERSION, g["sev"]])
        out.append({"category": cat, "severity": g["sev"], "confidence": g["conf"],
                    "disposition": g["disp"], "entities": entities, "identity": identity,
                    "rules": rules, "verified": g["verified"]})
    return out
