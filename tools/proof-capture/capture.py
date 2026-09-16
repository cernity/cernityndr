"""Detector-stage proof capture — REAL data, no stack required.

Runs a detector's ACTUAL code over an EVE fixture and records, side by side:
  - what Suricata alone emits (the source EVE, and how many of those are `alert` events), and
  - what Cernity computes from that same input (the real candidate findings the detector emits).

Every Cernity finding here is produced by the detector, not authored by hand — the only inputs
are the fixture and the detector's own logic. This is DETECTOR-STAGE capture (candidate findings);
the full finding-service lifecycle (FINAL state, revisions) and SIEM delivery are a separate,
stack-dependent layer (existing full-pipeline cases + the evidence-campaign plan). Output JSON is
shaped for the website's proof section.

Usage:
  python capture.py <service> <fixture.jsonl> <out.json>
The invoker must put services/<service> and shared/ on PYTHONPATH.
"""
import argparse
import importlib
import json
import time


class _Producer:
    def __init__(self):
        self.sent = []

    def send(self, topic, msg, key=None):
        self.sent.append(msg)

    def flush(self):
        pass


def _load(fixture):
    with open(fixture) as fh:
        return [json.loads(ln) for ln in fh if ln.strip()]


def _deliver(candidate):
    """Carry a candidate through the REAL finding-service lifecycle and findings-forwarder to the
    document a SOC analyst actually queries. build_finding decides delivery: metadata-sufficient
    findings finalize immediately; low-severity non-threat findings are SUPPRESSED (kept for
    correlation, not delivered); low-confidence content findings route to capture and — on the
    no-forensics MDR path (Parser→Cernity→SIEM) — timeout-finalize so they still reach the SIEM.
    Delivered findings are formatted with the actual Elasticsearch adapter (_doc/_doc_id) and CEF
    mapper. Requires finding-service + findings-forwarder on PYTHONPATH (uniquely-named modules)."""
    import state_machine as sm
    import cef
    from adapters import ElasticsearchAdapter as ES
    from datetime import datetime, timezone
    cand = {k: v for k, v in candidate.items() if k != "entities_decoded"}   # viz artifact, not a real field
    final, route = sm.build_finding(cand)
    if route == "capture":                        # no-forensics MDR path: timeout-finalize (deliver-now)
        final = sm.finalize_timeout(final)
    delivered = final.get("state") == "FINAL"
    rec = {"finding_id": candidate.get("finding_id"), "detector_id": candidate.get("detector_id"),
           "route": route, "delivered": delivered,
           "lifecycle": {k: final.get(k) for k in
                         ("state", "enrichment_state", "devo_delivery_state", "revision", "suppression_reason")}}
    if delivered:
        d = ES._doc(dict(final))                  # adds @timestamp, normalizes first/last_seen (as stored)
        idx = "ndr-findings-" + datetime.now(timezone.utc).strftime("%Y.%m.%d")
        rec["siem"] = {"elasticsearch": {"_index": idx, "_id": ES._doc_id(d), "_source": d},
                       "cef": cef.to_cef(final)}
    return rec


# --- per-service drivers: replay the fixture through the detector's real interface -----
def _drive_per_record(app, events, p):            # _handle(e, producer)
    for e in events:
        app._handle(e, p)


def _drive_dns(app, events, p):                   # _handle(e, p, part) + evaluate(p, parts)
    for e in events:
        app._handle(e, p, 0)
    app.evaluate(p, parts={0})


def _drive_ew(app, events, p):                    # east-west: _handle(e,p,part) + evaluate(...)
    for e in events:
        app._handle(e, p, 0)
    app.evaluate(p, flow_parts={0}, raw_parts={0}, dns_parts={0})


def _drive_behavioral(app, events, p):            # _handle(e,p,now,part,cfg) + evaluate(...)
    now = time.time()
    for e in events:
        app._handle(e, p, now, 0, None)
    app.evaluate(p, flow_parts={0}, dns_parts={0})


def _drive_coverage(app, events, p):              # evaluate(p, eve) per stats event
    for e in events:
        app.evaluate(p, e)


def _drive_anomaly(app, events, p):               # anomaly.to_candidate(e, tenant) per event
    anomaly = importlib.import_module("anomaly")
    for e in events:
        c = anomaly.to_candidate(e, "default")
        if c:
            p.send("ndr.finding.candidate.v1", c)


DRIVERS = {
    "ot-detectors": _drive_per_record,
    "protocol-detectors": _drive_per_record,
    "http-detector": _drive_per_record,
    "dns-detector": _drive_dns,
    "east-west-detectors": _drive_ew,
    "behavioral-detectors": _drive_behavioral,
    "coverage-detector": _drive_coverage,
    "anomaly-detector": _drive_anomaly,
}


def capture(service, fixture):
    app = importlib.import_module("app")
    store = importlib.import_module("store")
    if hasattr(app, "_store"):
        app._store = store.make_store("memory")   # deterministic, isolated per run
    p = _Producer()
    events = _load(fixture)
    DRIVERS.get(service, _drive_per_record)(app, events, p)

    alerts = sum(1 for e in events if e.get("event_type") == "alert")
    findings = p.sent
    detectors = sorted({f.get("detector_id") for f in findings if f.get("detector_id")})
    for f in findings:
        ents = f.get("entities")
        if isinstance(ents, str):
            try:
                f["entities_decoded"] = json.loads(ents)
            except (ValueError, TypeError):
                pass
    return {
        "service": service,
        "fixture": fixture.split("/")[-1],
        "capture_stage": "detector (candidate findings; full lifecycle/SIEM delivery validated separately)",
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "suricata_baseline": {
            "source_event_count": len(events),
            "alerts": alerts,
            "note": ("Suricata parsed these events to EVE. Alerts fire only on signature matches; "
                     "the behavior below is not a signature, so Suricata raises %d alert(s) on it." % alerts),
            "records": events,           # the ACTUAL source EVE records (raw), not a summary
        },
        "cernity": {
            "detectors_fired": detectors,
            "finding_count": len(findings),
            "findings": findings,        # the ACTUAL candidate findings (raw), entities decoded alongside
            "delivered": [_deliver(f) for f in findings],   # real lifecycle + forwarder -> SIEM document
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("service")
    ap.add_argument("fixture")
    ap.add_argument("out")
    a = ap.parse_args()
    result = capture(a.service, a.fixture)
    with open(a.out, "w") as fh:
        json.dump(result, fh, indent=2)
    print(f"{a.service}: {result['cernity']['finding_count']} findings from "
          f"{result['suricata_baseline']['source_events']} events "
          f"({result['suricata_baseline']['alerts']} suricata alerts) -> {a.out}")
    print("detectors:", result["cernity"]["detectors_fired"])


if __name__ == "__main__":
    main()
