"""Pure extraction + result-composition for the benchmark (stdlib only).

The Docker/OpenSearch orchestration lives in run.py; the logic that turns raw
documents into scored results lives here so it is unit-testable without any
infrastructure. `flagged_from_*` pull the set of entities each arm implicates;
`build_results` composes the final report dict via the scorer.
"""
from __future__ import annotations
import json

import scorer


def _ips(*vals):
    return [v for v in vals if v]


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
