"""Threat-intel detector: U2 live U1-store matching, with legacy static fallback
only when INTEL_DB is unset. Consumes flow/TLS/DNS/HTTP EVE telemetry and emits
ndr.finding.candidate.v1. Suppressed and red hits remain in the local intel audit.
"""
import json
import os
import signal
import hashlib
import ssl
import threading
import time
import urllib.request
from collections import OrderedDict

import ndr_runtime                      # shared tuned consumer/producer (plan 003 U5/U6)
import ti

log = ndr_runtime.setup_logging("threat-intel")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
TENANT = os.environ.get("NDR_TENANT", "default")
REFRESH_SECS = float(os.environ.get("REFRESH_SECS", "21600"))   # 6h
# Managed U1/U2 intel: configured store is authoritative; no static-feed bypass.
INTEL_DB = os.environ.get("INTEL_DB", "")            # per-tenant SQLite path; empty => lifecycle off
INTEL_FEEDS = os.environ.get("INTEL_FEEDS", "")      # JSON list of feed specs, or a path to one
# Operator-supplied known-C2 server-fingerprint list (JA3S/JA4S/JARM), one per
# line. No feed is bundled; unset => this match is a no-op. See docs/enrichment.md.
C2_FP_LIST = os.environ.get("C2_FP_LIST", "")
CTX = ssl.create_default_context()

FEEDS = {
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "sslbl_cert": "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
    "sslbl_ja3": "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text/",   # G4/P2: malware distribution URLs/IPs
}
_feeds = {"feodo": set(), "ja3": set(), "cert": set(), "c2fp": set()}
_running = True


def _stop(*_):
    global _running
    _running = False


def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "ndr-threat-intel/1.0"})
    with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def refresh():
    try:
        _feeds["feodo"] = ti.parse_feodo(_get(FEEDS["feodo"]))
        _feeds["cert"] = ti.parse_hash_csv(_get(FEEDS["sslbl_cert"]))
        _feeds["ja3"] = ti.parse_hash_csv(_get(FEEDS["sslbl_ja3"]))
        log.info("feeds refreshed: feodo=%d ja3=%d cert=%d",
                 len(_feeds["feodo"]), len(_feeds["ja3"]), len(_feeds["cert"]))
    except Exception as e:
        log.warning("feed refresh failed (keeping old): %s", e)
    if C2_FP_LIST:                          # operator-supplied local file, not a feed URL
        try:
            with open(C2_FP_LIST) as fh:
                _feeds["c2fp"] = ti.parse_fp_list(fh.read())
            log.info("c2 fingerprint list loaded: %d", len(_feeds["c2fp"]))
        except OSError as e:
            log.warning("c2 fp list load failed (keeping old): %s", e)
    _intel_refresh()


# --- managed intel lifecycle (U1): configured connectors -> lifecycle.ingest -> store --
# store.py must be loaded BY PATH: shared/store.py owns the name `store` on
# PYTHONPATH=shared (see store.py's module docstring / test_lifecycle.py).
_intel = {"store": None, "connectors": [], "lifecycle": None}


def _build_connector(feeds, spec):
    spec = dict(spec)
    kind = spec.pop("connector")
    if kind == "abusech":
        return feeds.AbuseChConnector(**spec)
    return {"http": feeds.HttpConnector, "stix_taxii": feeds.StixTaxiiConnector,
            "misp": feeds.MispConnector}[kind](**spec)


def _init_intel():
    """Build the per-tenant SQLite store + configured connectors from env. No config =>
    a no-op (legacy static-set matching unchanged). Imported lazily so `import app`
    under PYTHONPATH=shared never pulls the path-loaded store."""
    if not INTEL_DB:
        return
    import importlib.util
    import lifecycle
    import feeds
    spec = importlib.util.spec_from_file_location(
        "intel_store", os.path.join(os.path.dirname(os.path.abspath(__file__)), "store.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    raw = INTEL_FEEDS
    if raw and os.path.exists(raw):
        with open(raw) as fh:
            raw = fh.read()
    specs = json.loads(raw) if raw.strip() else []
    _intel["store"] = mod.IntelStore(INTEL_DB)
    _intel["connectors"] = [_build_connector(feeds, s) for s in specs]
    _intel["lifecycle"] = lifecycle
    log.info("managed intel lifecycle: %d feed(s) -> %s", len(_intel["connectors"]), INTEL_DB)


def _intel_refresh():
    """Fetch each configured feed and ingest into the persistent store. Per-feed
    try/except: one feed's fetch/parse failure is logged and skipped — a failed fetch
    never reaches ingest, so the store is never corrupted or half-written."""
    if _intel["store"] is None:
        return
    lifecycle = _intel["lifecycle"]
    now = time.time()
    for conn in _intel["connectors"]:
        try:
            payload = conn.fetch()
            recs = conn.records(payload, TENANT, now)
            revs = conn.revocations(payload, TENANT, now)
            lifecycle.ingest(_intel["store"], recs, now, revocations=revs)
            log.info("intel feed %s: %d indicator(s) ingested, %d revoked",
                     conn.feed, len(recs), len(revs))
        except Exception as e:
            log.warning("intel feed %s refresh failed (store intact): %s", conn.feed, e)


def refresher():
    ndr_runtime.start_health()          # /healthz /readyz /metrics (plan 003 obs)
    while _running:
        time.sleep(REFRESH_SECS)
        refresh()


def join_key_entities(eve: dict) -> list[dict]:
    """community_id/flow_id join a finding back to the exact connection's
    flow/tls/dns telemetry in ClickHouse (metadata enrichment, no capture).
    Only added when the source event carries them. Keep in sync with the same
    helper in file-threat/filematch.py and ids-alerts/promote.py."""
    out = []
    if eve.get("community_id"):
        out.append({"type": "community_id", "value": eve["community_id"]})
    if eve.get("flow_id"):
        out.append({"type": "flow_id", "value": eve["flow_id"]})
    return out


# B-U3/R04: bounded windowed dedup keyed by (feed, ioc, dst, hour). Was a process-lifetime set keyed
# by (feed, ioc), which suppressed every OTHER host that hit the same IOC for the process's whole life.
# Now a different host is not suppressed, a new hour re-emits, and the store is size-bounded.
_SEEN_MAX = int(os.environ.get("NDR_TI_DEDUP_MAX", "50000"))
_seen = OrderedDict()


def _seen_once(key):
    if key in _seen:
        return False
    _seen[key] = True
    _seen.move_to_end(key)
    while len(_seen) > _SEEN_MAX:
        _seen.popitem(last=False)
    return True


def _candidate(feed, ioc, dst, extra):
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    ents = [{"type": "ioc", "feed": feed, "value": ioc}]
    if dst:
        ents.append({"type": "ip", "role": "dst", "value": dst})
    ents += extra
    # id carries dst + hour so two hosts hitting the same IOC are distinct findings (R04)
    return {"finding_id": f"ti-{feed}-{ioc}-{dst or 'none'}-{int(time.time() // 3600)}",
            "tenant_id": TENANT, "detector_id": "threat_intel", "detector_version": "1.0",
            "category": "c2", "severity": 8, "confidence": 0.95,
            "first_seen": now, "last_seen": now,
            "entities": json.dumps(ents), "state": "CANDIDATE"}



def _managed_matches(e, producer, now):
    import lifecycle
    for hit in ti.match(e, _intel["store"], TENANT, now):
        # Include policy/provenance in identity so a lapsed suppression or changed
        # trust decision takes effect even within the current dedup window.
        identity = json.dumps([TENANT, e.get("src_ip"), e.get("dest_ip"),
                               {k: v for k, v in hit.items() if k != "suppressed"},
                               int(now // 3600)], sort_keys=True)
        key = hashlib.sha256(identity.encode()).hexdigest()
        if key in _seen and _seen[key] == hit["suppressed"]:
            continue
        if hit["suppressed"] or not lifecycle.is_exportable(hit):
            _intel["store"].record_match(TENANT, hit, e, now)
        else:
            src = e.get("src_ip")
            extra = [{"type": "ip", "role": "src", "value": src}] if src else []
            candidate = _candidate(hit["feed"], hit["indicator"], e.get("dest_ip"),
                                   extra + join_key_entities(e))
            candidate["finding_id"] = "ti-" + key
            candidate["intel_match"] = hit
            # Preserve the U1 score, and use trust to weight candidate confidence.
            candidate["confidence"] = hit["score"] / 100 * hit["source_trust"]
            candidate["severity"] = max(1, min(10, int(hit["score"] / 10)))
            producer.send("ndr.finding.candidate.v1", candidate)
        _seen.pop(key, None)
        _seen_once(key)
        _seen[key] = hit["suppressed"]


def process_observation(e, producer, now=None):
    now = time.time() if now is None else now
    if any(e.get(k) is not None and e[k] != TENANT for k in ("tenant", "tenant_id")):
        return
    if _intel["store"] is not None:
        _managed_matches(e, producer, now)
        return
    dst = e.get("dest_ip")
    t = e.get("tls", {}) or {}
    ja3 = (t.get("ja3", {}) or {}).get("hash") if isinstance(t.get("ja3"), dict) else t.get("ja3")
    cert = t.get("fingerprint") or (e.get("tls", {}) or {}).get("fingerprint")
    hit, feed, ioc = ti.match_static(dst, ja3 or "", cert or "",
                              _feeds["feodo"], _feeds["ja3"], _feeds["cert"])
    if hit and _seen_once((feed, ioc, dst, int(time.time() // 3600))):
        src = e.get("src_ip")
        extra = [{"type": "ip", "role": "src", "value": src}] if src else []
        extra += join_key_entities(e)
        producer.send("ndr.finding.candidate.v1", _candidate(feed, ioc, dst, extra))
        log.info("THREAT_INTEL %s match %s (src=%s dst=%s)", feed, ioc, src, dst)
    # known-C2 server-fingerprint match (operator list): JA3S/JA4S/JARM
    sja3 = (t.get("ja3s", {}) or {}).get("hash") if isinstance(t.get("ja3s"), dict) else t.get("ja3s")
    sh, sfeed, sioc = ti.match_server_fp(sja3 or "", t.get("ja4s") or "",
                                         t.get("jarm") or "", _feeds["c2fp"])
    if sh and _seen_once((sfeed, sioc, dst, int(time.time() // 3600))):
        src = e.get("src_ip")
        extra = [{"type": "ip", "role": "src", "value": src}] if src else []
        extra += join_key_entities(e)
        producer.send("ndr.finding.candidate.v1", _candidate(sfeed, sioc, dst, extra))
        log.info("THREAT_INTEL %s match %s (src=%s dst=%s)", sfeed, sioc, src, dst)


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    _init_intel()
    refresh()
    threading.Thread(target=refresher, daemon=True).start()
    producer = ndr_runtime.make_producer()
    consumer = ndr_runtime.make_consumer("suricata.flow.v1", "suricata.tls.v1", "suricata.dns.v1", "suricata.http.v1", group_id="ndr-threat-intel", auto_offset_reset="latest")
    log.info("threat-intel up")
    while _running:
        for _tp, records in consumer.poll(timeout_ms=1000, max_records=1000).items():
            for rec in records:
                e = rec.value
                process_observation(e, producer)
        producer.flush()
    consumer.close(); producer.close()


if __name__ == "__main__":
    main()
