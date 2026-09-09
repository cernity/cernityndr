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


def _parse(ts):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def reanchor(events, now=None):
    """Shift every event timestamp so the latest one sits at `now`, preserving
    relative spacing. Events without a parseable timestamp are left untouched."""
    now = now or datetime.now(timezone.utc)
    stamped = [(_parse(e.get("timestamp")), e) for e in events]
    times = [t for t, _ in stamped if t]
    if not times:
        return events
    shift = now - max(times)
    for t, e in stamped:
        if t:
            e["timestamp"] = (t + shift).isoformat()
            f = e.get("flow")
            if isinstance(f, dict) and _parse(f.get("start")):
                f["start"] = (_parse(f["start"]) + shift).isoformat()
    return events


def main(path):
    from kafka import KafkaProducer
    events = [json.loads(l) for l in open(path) if l.strip()]
    if not os.environ.get("CERNITY_FEED_NO_ANCHOR"):
        events = reanchor(events)
    p = KafkaProducer(bootstrap_servers=os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092"),
                      value_serializer=lambda v: json.dumps(v).encode())
    n = 0
    for ev in events:
        topic, key = route(ev)
        p.send(topic, key=key, value=ev)
        n += 1
    p.flush()
    print(f"fed {n} events")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "fixtures/beacon-eve.jsonl")
