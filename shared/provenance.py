"""Baseline provenance helper (plan U2): build a bounded `source_events` entry from a Suricata
EVE record, so a finding can carry the originating event to the SIEM.

Additive only — nothing here is read by detection, scoring, or the finding lifecycle. The native
EVE record is preserved verbatim (bounded by NDR_SOURCE_EVENTS_MAX_BYTES; a preview + truncated flag
on overflow), alongside the identifiers Suricata already emits (community_id/flow_id/tx_id/timestamp).
Absent identifiers are omitted, never fabricated (a null community_id is valid; a fake one is not).
Aggregates that can't inline every record use contributors().
"""
import json
import os

MAX_BYTES = int(os.environ.get("NDR_SOURCE_EVENTS_MAX_BYTES", "16384"))


def source_event(e, representative=False):
    """One `source_events` entry from an EVE record `e`, or None if `e` isn't a dict.
    The `record` is the native EVE object verbatim when within the size cap; over the cap it
    becomes `record_preview` (bounded string) + `truncated: True`. Emitted identifiers present on
    the record are lifted to the top of the entry as query pivots; absent ones are omitted."""
    if not isinstance(e, dict):
        return None
    entry = {}
    if e.get("event_type"):
        entry["event_type"] = e["event_type"]
    for k in ("community_id", "flow_id", "tx_id"):
        v = e.get(k)
        if v is not None:
            entry[k] = v
    if e.get("timestamp"):
        entry["timestamp"] = e["timestamp"]
    if representative:
        entry["representative"] = True
    body = json.dumps(e, separators=(",", ":"))
    if len(body.encode("utf-8")) > MAX_BYTES:
        entry["record_preview"] = body[:MAX_BYTES]
        entry["truncated"] = True
    else:
        entry["record"] = e
    return entry


def contributors(events):
    """Aggregate contributor summary for a finding that spans many records: total count plus the
    distinct community_ids/flow_ids seen (order-preserving, deduped). Never fabricates an id."""
    cids, fids, n = [], [], 0
    for e in events or []:
        if not isinstance(e, dict):
            continue
        n += 1
        c = e.get("community_id")
        if c and c not in cids:
            cids.append(c)
        f = e.get("flow_id")
        if f is not None and f not in fids:
            fids.append(f)
    return {"count": n, "community_ids": cids, "flow_ids": fids}
