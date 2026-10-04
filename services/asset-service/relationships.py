"""U3c observed entity-to-entity relationship edges (design §13.5 entity graph).

Pure, deterministic edge extraction from telemetry Suricata genuinely emits:

  * dns  — the querying entity --resolves--> each ANSWERED IP, carrying the queried
           name. Only A/AAAA answers become edges: a CNAME/other answer resolves to
           no IP entity, so it is an honest gap, never a fabricated edge.
  * flow — the src entity --communicates-with--> the dst entity.

Endpoints resolve through resolution.asset_key over the SAME time-bounded bindings
the rest of the service uses (§13.5), so an edge references a real entity UID
(mac:… when the IP is bound to a MAC at `ts`, ip:… otherwise) — never a raw IP.
Every edge carries provenance: {event_type, observed_at, detail}.
"""
from __future__ import annotations

import resolution

# dns answer types that resolve to an IP entity (and thus a `resolves` edge).
_IP_RRTYPES = {"A", "AAAA"}


def _entity(ip: str, bindings: dict, ts) -> str:
    """Resolve a raw IP to its entity UID via the shared spine (time-bounded)."""
    return resolution.asset_key({"ip": ip, "mac": None}, bindings, ts)


def _edge(src_ent: str, dst_ent: str, kind: str, event_type: str, ts, detail: str) -> dict:
    return {"src_entity": src_ent, "dst_entity": dst_ent, "kind": kind,
            "evidence": {"event_type": event_type,
                         "observed_at": resolution._iso(ts), "detail": detail}}


def _dns_edges(eve: dict, bindings: dict, ts) -> list[dict]:
    d = eve.get("dns", {}) or {}
    src = eve.get("src_ip")
    if not src:
        return []
    queries = d.get("queries") or []
    qname = (queries[0] if queries else d).get("rrname", "") or ""
    src_ent = _entity(src, bindings, ts)
    out: list[dict] = []
    for a in d.get("answers") or []:
        rdata = a.get("rdata")
        if a.get("rrtype") not in _IP_RRTYPES or not rdata:   # only IP answers -> entity edge
            continue
        out.append(_edge(src_ent, _entity(rdata, bindings, ts),
                         "resolves", "dns", ts, qname))
    return out


def _flow_edges(eve: dict, bindings: dict, ts) -> list[dict]:
    src, dst = eve.get("src_ip"), eve.get("dest_ip")
    if not (src and dst):
        return []
    detail = eve.get("app_proto") or eve.get("proto") or ""   # observed only, never guessed
    return [_edge(_entity(src, bindings, ts), _entity(dst, bindings, ts),
                 "communicates-with", "flow", ts, detail)]


def build_edges(eve: dict, bindings: dict, ts) -> list[dict]:
    """OBSERVED entity-to-entity edges for one EVE record (dns/flow only). Empty for
    any other event type. Pure + deterministic — same input yields the same edges."""
    et = eve.get("event_type")
    if et == "dns":
        return _dns_edges(eve, bindings, ts)
    if et == "flow":
        return _flow_edges(eve, bindings, ts)
    return []
