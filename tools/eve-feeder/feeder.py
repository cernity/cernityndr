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
          "tls": "suricata.tls.v1", "http": "suricata.http.v1"}


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


def _parse(ts):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def reanchor(events, now=None, anchor="end"):
    """Shift every event timestamp uniformly so a reference event sits at `now`, preserving
    relative spacing. anchor='end' (default) puts the NEWEST event at now — burst replay keeps
    a recorded fixture inside the detectors' rolling window whenever it is replayed.
    anchor='start' puts the OLDEST at now, so paced replay sends each event at its real offset
    from the start. Events without a parseable timestamp are left untouched."""
    now = now or datetime.now(timezone.utc)
    stamped = [(_parse(e.get("timestamp")), e) for e in events]
    times = [t for t, _ in stamped if t]
    if not times:
        return events
    shift = now - (min(times) if anchor == "start" else max(times))
    for t, e in stamped:
        if t:
            e["timestamp"] = (t + shift).isoformat()
            f = e.get("flow")
            if isinstance(f, dict) and _parse(f.get("start")):
                f["start"] = (_parse(f["start"]) + shift).isoformat()
    return events


def paced_offsets(events, speed=1.0):
    """Wall-clock offset in seconds (from the first timestamped event) at which each event
    should be sent for paced replay (M1.6/§5): the feeder honours the recorded inter-arrival
    timing instead of bursting, so event-time and processing-clock stay aligned. `speed` >1
    compresses the schedule (a labelled acceleration, validated separately per §5). Events with
    no timestamp inherit the previous offset. Assumes events are ascending by timestamp."""
    offs, base, last = [], None, 0.0
    for e in events:
        t = _parse(e.get("timestamp"))
        if t is not None:
            base = base if base is not None else t
            last = (t - base).total_seconds() / (speed or 1.0)
        offs.append(last)
    return offs


def main(path):
    import time
    from kafka import KafkaProducer
    events = [json.loads(l) for l in open(path) if l.strip()]
    paced = os.environ.get("CERNITY_FEED_PACED", "").strip().lower() not in ("", "0", "false", "no")
    if paced:
        events.sort(key=lambda e: _parse(e.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc))
    if not os.environ.get("CERNITY_FEED_NO_ANCHOR"):
        events = reanchor(events, anchor="start" if paced else "end")
    p = KafkaProducer(bootstrap_servers=os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092"),
                      value_serializer=lambda v: json.dumps(v).encode(),
                      **_security_kwargs())
    n = 0
    if paced:
        # Honour recorded inter-arrival timing (§5). max_gap bounds any long idle stretch so a
        # sparse fixture does not stall the run; speed>1 compresses (labelled acceleration).
        offsets = paced_offsets(events, float(os.environ.get("CERNITY_FEED_SPEED", "1") or "1"))
        max_gap = float(os.environ.get("CERNITY_FEED_MAX_GAP", "10"))
        start = time.monotonic()
        for ev, off in zip(events, offsets):
            delay = min(off - (time.monotonic() - start), max_gap)
            if delay > 0:
                time.sleep(delay)
            topic, key = route(ev)
            p.send(topic, key=key, value=ev)
            n += 1
    else:
        for ev in events:
            topic, key = route(ev)
            p.send(topic, key=key, value=ev)
            n += 1
    p.flush()
    print(f"fed {n} events{' (paced)' if paced else ''}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "fixtures/beacon-eve.jsonl")
