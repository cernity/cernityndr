"""Pure extraction + result-composition for the benchmark (stdlib only).

The Docker/OpenSearch orchestration lives in run.py; the logic that turns raw
documents into scored results lives here so it is unit-testable without any
infrastructure. `flagged_from_*` pull the set of entities each arm implicates;
`build_results` composes the final report dict via the scorer.
"""
from __future__ import annotations
import json
import re
from datetime import datetime

import scorer

_TZ_OFFSET = re.compile(r'([+-]\d{2})(\d{2})$')    # +0000 -> +00:00 (fromisoformat rejects the compact form)


def _ips(*vals):
    return [v for v in vals if v]


def _epoch(v):
    """A timestamp field -> epoch seconds (float), or None. Accepts RFC3339 UTC strings and numeric
    epochs. CRITICAL FAIRNESS FIX: Suricata EVE stamps a COMPACT `+0000` offset (no colon), which
    datetime.fromisoformat REJECTS on Python < 3.11 (the scorer runs on the host, 3.10 here). Cernity
    findings use a trailing `Z` (which the old `.replace("Z","+00:00")` handled), so WITHOUT normalising
    `+0000` the scorer parsed Cernity timestamps but SILENTLY dropped Suricata alert timestamps to None
    -> Suricata alerts scored ambiguous/untimed and Arm A was asymmetrically UNDERSTATED. Normalise the
    compact offset so BOTH arms are timed on the same clock. Unparsable -> None (time-bounded episode
    then ambiguous, never silently in-window)."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    s = _TZ_OFFSET.sub(r'\1:\2', str(v).replace("Z", "+00:00"))
    try:
        return datetime.fromisoformat(s).timestamp()
    except (ValueError, TypeError):
        return None


def _interval(start, end=None):
    """A detection interval {start,end} in epoch seconds from two time fields, or None when start is
    absent/unparsable. A single instant (no end) collapses to start==end."""
    s = _epoch(start)
    if s is None:
        return None
    e = _epoch(end)
    return {"start": s, "end": e if e is not None else s}


def flagged_from_alerts(docs, granularity: str = "host") -> set:
    """Entities implicated by Suricata EVE ALERT records (Arm A). Only event_type='alert'
    is scored: flow/nsm telemetry is stored and searchable but is NOT an analyst detection,
    so counting its endpoints inflated Arm A's false positives (the flow-endpoint bug, §4
    'actual alert extraction'). host -> src_ip + dest_ip; flow -> community_id. Flagging
    both endpoints of a real alert is fair, not gamed (role-aware scoring is M2)."""
    out = set()
    for d in docs:
        if d.get("event_type") != "alert":
            continue
        if granularity == "flow":
            if d.get("community_id"):
                out.add(d["community_id"])
        else:
            out.update(_ips(d.get("src_ip"), d.get("dest_ip")))
    return out


def flagged_from_notices(docs, granularity: str = "host") -> set:
    """Entities implicated by Zeek notices (Arm C reference), parsed separately from
    Suricata alerts (§4). Zeek notice.log records ARE the notices (no event_type='alert');
    the arm-c shipper normalizes their src/dst to src_ip/dest_ip. host -> src_ip + dest_ip;
    flow -> community_id."""
    out = set()
    for d in docs:
        if granularity == "flow":
            if d.get("community_id"):
                out.add(d["community_id"])
        else:
            out.update(_ips(d.get("src_ip"), d.get("dest_ip")))
    return out


def flagged_from_findings(docs, granularity: str = "host") -> set:
    """Entities implicated by Cernity findings (Arm B). `entities` is a JSON string of
    typed objects; pull ip values (host) or the community_id entity (flow)."""
    out = set()
    for d in docs:
        ents = d.get("entities")
        try:
            ents = json.loads(ents) if isinstance(ents, str) else (ents or [])
        except (ValueError, TypeError):
            ents = []
        for e in ents:
            if granularity == "flow" and e.get("type") == "community_id" and e.get("value"):
                out.add(e["value"])
            elif granularity != "flow" and e.get("type") == "ip" and e.get("value"):
                out.add(e["value"])
    return out


def _alert_behavior(d) -> str | None:
    """Coarse behaviour class for a Suricata alert, for episode matching (M2)."""
    cat = str((d.get("alert") or {}).get("category") or d.get("category") or "").lower()
    for needle, behavior in (("trojan", "c2"), ("command and control", "c2"),
                             ("malware", "malware"), ("attack", "c2"),
                             ("scan", "recon"), ("exfil", "exfil")):
        if needle in cat:
            return behavior
    return cat or None


_MATCH_ENTITY_TYPES = ("ip", "domain", "community_id")


def _finding_entities(raw):
    """[{value, role}] for the matchable entities in a finding's `entities` (a JSON string):
    ip, domain (FQDN-beacon implicates a domain, not an ip), and community_id."""
    try:
        ents = json.loads(raw) if isinstance(raw, str) else (raw or [])
    except (ValueError, TypeError):
        ents = []
    return [{"value": e.get("value"), "role": e.get("role")}
            for e in ents if e.get("type") in _MATCH_ENTITY_TYPES and e.get("value")]


def _endpoint_entities(d):
    return [{"value": d[k], "role": r} for k, r in (("src_ip", "src"), ("dest_ip", "dst")) if d.get(k)]


def _tenant(d):
    """Authenticated tenant identity from the record's ACTUAL schema (§26 Major-2). The finding/flow
    contracts key everything by `tenant_id` (a partition invariant); a bare `tenant` is a legacy
    fallback. Reading only `tenant` collapsed every real finding to "default" and defeated the
    tenant-scoped matcher/dedup — so prefer `tenant_id`, then `tenant`, then default."""
    return d.get("tenant_id") or d.get("tenant") or "default"


def _alert_interval(d):
    flow = d.get("flow") or {}
    return _interval(flow.get("start") or d.get("timestamp"), flow.get("end"))


def detections_from_alerts(docs):
    """Suricata alert docs -> episode detections (initiator=src_ip, target=dest_ip). Observation
    interval from flow.start/flow.end (beacon time), else the EVE timestamp (§25.3)."""
    return [{"entities": _endpoint_entities(d), "behavior": _alert_behavior(d),
             "tenant": _tenant(d), "interval": _alert_interval(d)}
            for d in docs if d.get("event_type") == "alert"]


def _revision(d):
    """An explicit finding REVISION counter if the contract exposes one, else None. Deliberately
    does NOT treat a generic `version` field as a revision (§28 Major-4): equating them needs a
    schema-specific definition Cernity's finding contract does not yet provide. Absent an explicit
    `revision`, selection falls back to last_seen recency + lifecycle state (documented equivalent)."""
    v = d.get("revision")
    return float(v) if isinstance(v, (int, float)) else None


def _observation_interval(d):
    """The OBSERVED activity interval of a finding (R06/§33.3). An aggregating detector may correctly
    describe earlier activity while emitting later; first_seen/last_seen are the observation bounds ONLY
    when the finding says so. `observed=False` means they are emission-derived — return None so the
    scorer marks temporal attribution UNKNOWN rather than pretending emission is observation. Legacy
    findings without the flag keep first_seen/last_seen as the observation interval (unchanged)."""
    if d.get("observed") is False:
        return None
    return _interval(d.get("first_seen"), d.get("last_seen"))


def detections_from_findings(docs):
    """Cernity finding docs -> episode detections (entities already carry roles). Observation interval
    from the contract's first_seen/last_seen (unless observed=False); `available` = emitted_at, the
    availability signal used for deadline utility SEPARATELY from observation (R06); revision key +
    lifecycle state carried for deadline-aware revision selection (§25.3)."""
    return [{"entities": _finding_entities(d.get("entities")), "behavior": d.get("category"),
             "finding_id": d.get("finding_id"), "tenant": _tenant(d),
             "interval": _observation_interval(d), "available": _epoch(d.get("emitted_at")),
             "revision": _revision(d), "state": d.get("state")}
            for d in docs]


def detections_from_notices(docs):
    """Zeek notice docs -> episode detections (shipper normalized src/dst -> src_ip/dest_ip)."""
    return [{"entities": _endpoint_entities(d), "behavior": (d.get("note") or None),
             "tenant": _tenant(d), "interval": _interval(d.get("ts") or d.get("timestamp"))}
            for d in docs]


def build_results(meta: dict, arms_raw: dict, truth, honesty=None, caveats=None) -> dict:
    """Compose the report dict. `arms_raw[arm]` = {flagged:set, raw_events, alerts,
    delivered}. Accuracy comes from the flagged set vs truth; noise from the counts."""
    truth = set(truth)
    out = {"meta": meta, "arms": {}, "honesty": list(honesty or []), "caveats": list(caveats or [])}
    for arm, d in arms_raw.items():
        acc = scorer.score(d.get("flagged", set()), truth)
        nz = scorer.noise(d.get("raw_events", 0), d.get("alerts", 0), acc["tp"],
                          d.get("delivered", d.get("alerts", 0)))
        out["arms"][arm] = {"accuracy": acc, "noise": nz}
    return out
