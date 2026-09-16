"""Replay a Suricata EVE JSONL file onto the bus for testing/demo. Routes each
event to its topic by event_type and keys by src_ip so a source's whole window
lands on one partition (matching the production shipper).

Timestamps are re-anchored so the newest event lands at "now" (relative spacing
preserved), which keeps a recorded fixture inside the detectors' rolling window
no matter when it is replayed. Disable with CERNITY_FEED_NO_ANCHOR=1."""
import json
import os
import sys
from datetime import datetime, timezone, timedelta

TOPICS = {"flow": "suricata.flow.v1", "dns": "suricata.dns.v1",
          "tls": "suricata.tls.v1", "http": "suricata.http.v1",
          "modbus": "suricata.modbus.v1"}


def route(event):
    topic = TOPICS.get(event.get("event_type"), "suricata.raw.v1")
    key = event.get("src_ip", "unkeyed").encode()
    return topic, key


def _security_kwargs(env=os.environ):
    """SASL/SCRAM producer auth when the bus is secured (mirrors shared/ndr_runtime, but
    the feeder ships as a standalone tool without that module). The feeder is the SENSOR
    principal — produce-only on suricata.* — so it uses NDR_BUS_SASL_USER/PASSWORD =
    cernity-sensor. Mechanism-gated: an empty/unset NDR_BUS_SASL_MECHANISM means the
    plaintext (insecure/local) bus, so return nothing. A CA -> SASL_SSL (remote/TLS);
    none -> SASL_PLAINTEXT (internal Docker net). A mechanism without user+password raises
    so a half-configured secure bus fails loudly instead of silently going plaintext."""
    mech = env.get("NDR_BUS_SASL_MECHANISM")
    if not mech:
        return {}
    user, pw = env.get("NDR_BUS_SASL_USER"), env.get("NDR_BUS_SASL_PASSWORD")
    if not (user and pw):
        raise SystemExit("feeder: NDR_BUS_SASL_MECHANISM set but NDR_BUS_SASL_USER/PASSWORD missing")
    ca = env.get("NDR_BUS_TLS_CA")
    kw = {"security_protocol": "SASL_SSL" if ca else "SASL_PLAINTEXT",
          "sasl_mechanism": mech, "sasl_plain_username": user, "sasl_plain_password": pw}
    if ca:
        kw["ssl_cafile"] = ca
    return kw


import re as _re
_TZ_OFFSET = _re.compile(r'([+-]\d{2})(\d{2})$')    # +0000 -> +00:00


def _parse(ts):
    # Suricata emits a `+0000` offset with NO colon, which fromisoformat REJECTS on Python < 3.11.
    # Left unparsed, paced replay could not order/reanchor by flow.start and beacon timing collapsed
    # (§stage5). Normalise the offset before parsing.
    if ts is None:
        return None
    s = _TZ_OFFSET.sub(r'\1:\2', str(ts).replace("Z", "+00:00"))
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def _event_time(e):
    """Effective event time for ordering / pacing / anchoring: flow.start for flow records (the
    connection time). The EVE 'timestamp' is the flush time, which offline Suricata sets
    identically for every open flow at EOF — using it destroys inter-arrival timing (a beacon
    collapses to one instant). dns/other events have no flow.start and fall back to timestamp."""
    return _parse((e.get("flow") or {}).get("start") or e.get("timestamp"))


def reanchor(events, now=None, anchor="end"):
    """Shift event times uniformly so a reference event sits at `now`, preserving relative
    spacing, and RETURN the applied shift in seconds so the offline scorer can map episode truth
    onto the same replay clock (§25.3). Reference + spacing use the EFFECTIVE event time (flow.start
    for flows); both the EVE timestamp and flow.start are shifted by the same amount. anchor='end'
    (default) puts the NEWEST event at now (burst replay keeps a fixture inside the detectors'
    rolling window); anchor='start' puts the OLDEST at now (paced replay). Events without a time are
    left as-is. Returns (events, shift_seconds)."""
    now = now or datetime.now(timezone.utc)
    stamped = [(_event_time(e), e) for e in events]
    times = [t for t, _ in stamped if t]
    if not times:
        return events, 0.0
    shift = now - (min(times) if anchor == "start" else max(times))
    for t, e in stamped:
        if t is None:
            continue
        if _parse(e.get("timestamp")):
            e["timestamp"] = (_parse(e["timestamp"]) + shift).isoformat()
        f = e.get("flow")
        if isinstance(f, dict) and _parse(f.get("start")):
            f["start"] = (_parse(f["start"]) + shift).isoformat()
    return events, shift.total_seconds()


def paced_offsets(events, speed=1.0, max_gap=None):
    """Wall-clock offset in seconds (from the first timestamped event) at which each event
    should be sent for paced replay (M1.6/§5). Default: the TRUE recorded inter-arrival timing,
    so event-time and processing-clock stay aligned. `speed`>1 compresses the whole schedule
    uniformly (a labelled acceleration). `max_gap`, if set, caps each inter-event IDLE gap — a
    SEPARATE, explicitly-labelled transformation that BREAKS timing-equivalence; leave it unset
    for accuracy. Untimestamped events inherit the previous offset; out-of-order deltas clamp to
    0. Assumes events are ascending by timestamp."""
    offs, prev_t, cum = [], None, 0.0
    for e in events:
        t = _event_time(e)          # flow.start for flows; timestamp otherwise
        if t is not None:
            if prev_t is not None:
                delta = max(0.0, (t - prev_t).total_seconds())
                if max_gap is not None:
                    delta = min(delta, max_gap)
                cum += delta / (speed or 1.0)
            prev_t = t
        offs.append(cum)
    return offs


def _record_replay(shift, anchor):
    """Persist the single applied reanchor shift so offline scoring maps episode truth onto the
    replay clock (§25.3). Written only when CERNITY_FEED_REPLAY_OUT names a writable path."""
    out = os.environ.get("CERNITY_FEED_REPLAY_OUT", "").strip()
    if not out:
        return
    try:
        with open(out, "w") as f:
            json.dump({"replay_offset_seconds": shift, "anchor": anchor,
                       "recorded_at": datetime.now(timezone.utc).isoformat()}, f)
    except OSError as e:
        print(f"! could not record replay offset to {out}: {e}")


def main(*paths):
    import time
    from kafka import KafkaProducer
    # Merge ALL streams (alerts + NSM) and reanchor ONCE (§25.3): separate per-file reanchoring gave
    # each stream a different shift, so no single offset mapped the run. One sorted stream, one shift.
    events = [json.loads(l) for p in paths for l in open(p) if l.strip()]
    paced = os.environ.get("CERNITY_FEED_PACED", "").strip().lower() not in ("", "0", "false", "no")
    if paced:
        events.sort(key=lambda e: _event_time(e) or datetime.min.replace(tzinfo=timezone.utc))
    if not os.environ.get("CERNITY_FEED_NO_ANCHOR"):
        events, shift = reanchor(events, anchor="start" if paced else "end")
        _record_replay(shift, "start" if paced else "end")
    else:
        # §49.3: ALWAYS write the replay artifact — even when NOT reanchoring, record offset 0. The scorer
        # then requires the mapping unconditionally, so a transformed run cannot drop replay.json to escape
        # its own requirement (the replay-inventory circularity). A missing artifact is a real gap.
        _record_replay(0.0, "none")
    p = KafkaProducer(bootstrap_servers=os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092"),
                      value_serializer=lambda v: json.dumps(v).encode(),
                      **_security_kwargs())
    n = 0
    if paced:
        # Honour recorded inter-arrival timing (§5). CERNITY_FEED_MAX_GAP (if set) is a LABELLED
        # idle-gap compression applied to the SCHEDULE — it is not timing-equivalent; unset =
        # true timing. speed>1 compresses uniformly (also labelled).
        _mg = os.environ.get("CERNITY_FEED_MAX_GAP", "").strip()
        offsets = paced_offsets(events, float(os.environ.get("CERNITY_FEED_SPEED", "1") or "1"),
                                float(_mg) if _mg else None)
        start = time.monotonic()
        for ev, off in zip(events, offsets):
            while True:                       # wait to the FULL scheduled deadline, never a cap
                remaining = off - (time.monotonic() - start)
                if remaining <= 0:
                    break
                time.sleep(min(remaining, 1.0))   # interruptible 1s increments; keep waiting
            topic, key = route(ev)
            p.send(topic, key=key, value=ev)
            n += 1
    else:
        for ev in events:
            topic, key = route(ev)
            p.send(topic, key=key, value=ev)
            n += 1
    p.flush()
    _record_feed_manifest(paths, events, n)
    print(f"fed {n} events{' (paced)' if paced else ''}")


import hashlib as _hashlib

IDENTITY_SCHEME = "v1:flow5tuple"          # §59.1: canonical per-event identity (survives re-serialization)
_ID_CAP = 200_000                          # cap the stored id list; the digest still covers every event


def _event_identity(e):
    """A canonical per-event identity: the normalized event content with the REANCHORED fields removed.
    The feeder shifts `timestamp` and `flow.start`/`flow.end` in memory for Arm B, while the harness's
    source set (cat of the original eve files) still holds the original clock — so those fields MUST be
    excluded or every record would appear omitted. Everything else (flow_id, 5-tuple, dns query, alert
    signature, bytes, …) is retained, so an omission and a duplicate no longer cancel. Two records
    identical except for their clock collide (documented; real Suricata records differ by flow_id)."""
    e2 = {k: v for k, v in e.items() if k != "timestamp"}
    fl = e2.get("flow")
    if isinstance(fl, dict):
        e2["flow"] = {k: v for k, v in fl.items() if k not in ("start", "end")}
    return _hashlib.sha1(json.dumps(e2, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]


def _identity_digest(ids):
    """Order-independent MULTISET digest: sort so a permutation matches, but a drop/dup changes it."""
    h = _hashlib.sha256()
    for i in sorted(ids):
        h.update(i.encode()); h.update(b"\n")
    return h.hexdigest()


def _record_feed_manifest(paths, events, fed):
    """§49.3/§59.1 source coverage: record the feeder's canonical input inventory — per-source-file
    counts, totals, AND the per-event identity multiset (as a digest, plus the raw ids when under the
    cap). The harness reconciles the feeder's read set against Suricata's produced set by IDENTITY, so an
    equal-count omission+duplication (which cancels under a count check) is caught. Written to
    CERNITY_FEED_MANIFEST_OUT (default /eve/feed-manifest.json when writable)."""
    out = os.environ.get("CERNITY_FEED_MANIFEST_OUT", "/eve/feed-manifest.json").strip()
    if not out:
        return
    by_file = {}
    for pth in paths:
        try:
            by_file[os.path.basename(pth)] = sum(1 for l in open(pth) if l.strip())
        except OSError:
            by_file[os.path.basename(pth)] = None
    read_ids = [_event_identity(e) for e in events]
    fed_ids = read_ids[:fed]                                 # the events actually sent (all, unless a send failed)
    payload = {"read_events": len(events), "fed_events": fed, "by_source_file": by_file,
               "identity_scheme": IDENTITY_SCHEME,
               "read_identity_digest": _identity_digest(read_ids),
               "fed_identity_digest": _identity_digest(fed_ids),
               "recorded_at": datetime.now(timezone.utc).isoformat()}
    if len(read_ids) <= _ID_CAP:                            # keep raw ids for a precise set-diff at bench scale
        payload["read_ids"] = read_ids
        payload["fed_ids"] = fed_ids
    try:
        with open(out, "w") as f:
            json.dump(payload, f)
    except OSError as e:
        print(f"! could not record feed manifest to {out}: {e}")


if __name__ == "__main__":
    main(*(sys.argv[1:] or ["fixtures/beacon-eve.jsonl"]))
