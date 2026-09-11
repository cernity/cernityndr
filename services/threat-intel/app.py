"""Threat-intel detector (plan U8 Tier 1). Loads abuse.ch blocklists (Feodo C2
IPs, SSLBL cert SHA1, SSLBL JA3), refreshes periodically, and matches observed
flow/tls telemetry against them -> ndr.finding.candidate.v1. Matching logic is
covered by test_ti.py; this is the fetch + consume shell.
"""
import json
import logging
import os
import signal
import ssl
import threading
import time
import urllib.request

import ndr_runtime                      # shared tuned consumer/producer (plan 003 U5/U6)
import ti

log = ndr_runtime.setup_logging("threat-intel")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
TENANT = os.environ.get("NDR_TENANT", "default")
REFRESH_SECS = float(os.environ.get("REFRESH_SECS", "21600"))   # 6h
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


def _candidate(feed, ioc, dst, extra):
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    ents = [{"type": "ioc", "feed": feed, "value": ioc}]
    if dst:
        ents.append({"type": "ip", "role": "dst", "value": dst})
    ents += extra
    return {"finding_id": f"ti-{feed}-{ioc}-{int(time.time() // 3600)}",
            "tenant_id": TENANT, "detector_id": "threat_intel", "detector_version": "1.0",
            "category": "c2", "severity": 8, "confidence": 0.95,
            "first_seen": now, "last_seen": now,
            "entities": json.dumps(ents), "state": "CANDIDATE"}


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    refresh()
    threading.Thread(target=refresher, daemon=True).start()
    producer = ndr_runtime.make_producer()
    consumer = ndr_runtime.make_consumer("suricata.flow.v1", "suricata.tls.v1", group_id="ndr-threat-intel", auto_offset_reset="latest")
    log.info("threat-intel up")
    seen = set()
    while _running:
        for _tp, records in consumer.poll(timeout_ms=1000, max_records=1000).items():
            for rec in records:
                e = rec.value
                dst = e.get("dest_ip")
                t = e.get("tls", {}) or {}
                ja3 = (t.get("ja3", {}) or {}).get("hash") if isinstance(t.get("ja3"), dict) else t.get("ja3")
                cert = t.get("fingerprint") or (e.get("tls", {}) or {}).get("fingerprint")
                hit, feed, ioc = ti.match(dst, ja3 or "", cert or "",
                                          _feeds["feodo"], _feeds["ja3"], _feeds["cert"])
                if hit and (feed, ioc) not in seen:
                    seen.add((feed, ioc))
                    src = e.get("src_ip")
                    extra = [{"type": "ip", "role": "src", "value": src}] if src else []
                    extra += join_key_entities(e)
                    producer.send("ndr.finding.candidate.v1", _candidate(feed, ioc, dst, extra))
                    log.info("THREAT_INTEL %s match %s (src=%s dst=%s)", feed, ioc, src, dst)
                # known-C2 server-fingerprint match (operator list): JA3S/JA4S/JARM
                sja3 = (t.get("ja3s", {}) or {}).get("hash") if isinstance(t.get("ja3s"), dict) else t.get("ja3s")
                sh, sfeed, sioc = ti.match_server_fp(sja3 or "", t.get("ja4s") or "",
                                                     t.get("jarm") or "", _feeds["c2fp"])
                if sh and (sfeed, sioc) not in seen:
                    seen.add((sfeed, sioc))
                    src = e.get("src_ip")
                    extra = [{"type": "ip", "role": "src", "value": src}] if src else []
                    extra += join_key_entities(e)
                    producer.send("ndr.finding.candidate.v1", _candidate(sfeed, sioc, dst, extra))
                    log.info("THREAT_INTEL %s match %s (src=%s dst=%s)", sfeed, sioc, src, dst)
        producer.flush()
    consumer.close(); producer.close()


if __name__ == "__main__":
    main()
