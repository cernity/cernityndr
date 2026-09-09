"""Reconstruct-by-source + entity graph (plan U19; v2 §16.6). Pure assembly logic
— app.py runs the ClickHouse queries and the HTTP API. Given an entity, assemble
a time-ordered security timeline and an entity-relationship subgraph so a
coordinated campaign reads as one picture, not scattered rows.
"""
from __future__ import annotations
import re

# Only allow safe chars in the entity/tenant params before they reach SQL.
_SAFE = re.compile(r"^[A-Za-z0-9_.:%-]{1,128}$")


def safe_param(v: str) -> str:
    if not _SAFE.match(v or ""):
        raise ValueError(f"unsafe param: {v!r}")
    return v


def build_timeline(flows: list[dict], sessions: list[dict], findings: list[dict]) -> list[dict]:
    """Merge the three record types into one time-sorted timeline."""
    tl = []
    for f in flows:
        tl.append({"t": str(f.get("event_time")), "kind": "flow",
                   "detail": f"{f.get('src_ip')} -> {f.get('dst_ip')}:{f.get('dst_port')} "
                             f"{f.get('app_proto') or f.get('ndpi_protocol') or ''}"})
    for s in sessions:
        tl.append({"t": str(s.get("started")), "kind": "session",
                   "detail": f"{s.get('session_type')} {s.get('src_ip')}<->{s.get('dst_ip')} "
                             f"{s.get('app_proto')} ({s.get('flows')} flows)"})
    for fi in findings:
        tl.append({"t": str(fi.get("first_seen")), "kind": "finding",
                   "detail": f"{fi.get('category')}/{fi.get('detector_id')} "
                             f"sev={fi.get('severity')} state={fi.get('state')}"})
    return sorted(tl, key=lambda e: e["t"])


def build_graph(asset: str, flows: list[dict], findings: list[dict]) -> dict:
    """Entity-relationship subgraph rooted at `asset`: source -> destinations,
    source -> findings. A coordinated campaign is a connected subgraph."""
    nodes = {asset: {"id": asset, "type": "source"}}
    edges = []
    for f in flows:
        dst = f.get("dst_ip")
        if dst and dst != asset:
            nodes.setdefault(dst, {"id": dst, "type": "dest"})
            edges.append({"from": asset, "to": dst, "rel": "flow",
                          "label": f.get("app_proto") or f.get("ndpi_protocol") or ""})
    for fi in findings:
        fid = fi.get("finding_id")
        nodes[fid] = {"id": fid, "type": "finding", "category": fi.get("category")}
        edges.append({"from": asset, "to": fid, "rel": "finding"})
    # dedup flow edges (source->dest can repeat across many flows)
    seen, uniq = set(), []
    for e in edges:
        k = (e["from"], e["to"], e["rel"], e.get("label", ""))
        if k not in seen:
            seen.add(k)
            uniq.append(e)
    return {"root": asset, "nodes": list(nodes.values()), "edges": uniq}
