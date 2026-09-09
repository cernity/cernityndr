"""Asset service (plan U17). Consumes suricata.flow.v1 + suricata.raw.v1 (arp/dhcp
carry L2 identity), resolves each observation to a stable asset_key
(resolution.py), and upserts the ndr.asset entity table. Resolution correctness
is covered by test_resolution.py; this is the I/O shell.
"""
import logging
import os
import ndr_runtime
import signal
import time
from datetime import datetime, timezone

from kafka import KafkaConsumer
import clickhouse_connect

import resolution

log = ndr_runtime.setup_logging("asset-service")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
CH_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse")
CH_USER = os.environ.get("CLICKHOUSE_USER", "ndr")
CH_PASS = os.environ["CLICKHOUSE_PASSWORD"]
TENANT = os.environ.get("NDR_TENANT", "default")
FLUSH_SECS = float(os.environ.get("NDR_FLUSH_SECS", "15"))
COLS = ["tenant_id", "asset_key", "first_seen", "last_seen", "ip_set", "mac_set",
        "hostname_set", "role_if_known", "evidence_sources", "confidence"]

_running = True
_assets: dict = {}          # asset_key -> asset dict
_ip_to_mac: dict = {}       # ip -> mac (learned from arp/dhcp)
_dirty: set = set()


def _stop(*_):
    global _running
    _running = False


def _dt(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def observe(eve: dict):
    now = eve.get("timestamp") or datetime.now(timezone.utc).isoformat()
    for obs in resolution.extract_evidence(eve):
        if obs.get("mac") and obs.get("ip"):
            _ip_to_mac[obs["ip"]] = obs["mac"]
        key = resolution.asset_key(obs, _ip_to_mac)
        _assets[key] = resolution.merge(_assets.get(key), obs, now)
        _dirty.add(key)


def flush(ch):
    if not _dirty:
        return
    rows = []
    for key in list(_dirty):
        a = _assets[key]
        rows.append([TENANT, key, _dt(a["first_seen"]), _dt(a["last_seen"]),
                     a["ip_set"], a["mac_set"], a["hostname_set"],
                     a.get("role_if_known", ""), a["evidence_sources"], a["confidence"]])
    ch.insert("ndr.asset", rows, column_names=COLS)
    log.info("upserted %d assets (%d total tracked)", len(rows), len(_assets))
    _dirty.clear()


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    ch = clickhouse_connect.get_client(host=CH_HOST, username=CH_USER, password=CH_PASS)
    consumer = KafkaConsumer(
        "suricata.flow.v1", "suricata.raw.v1", bootstrap_servers=BOOTSTRAP,
        group_id="ndr-asset-service", auto_offset_reset="latest",
        enable_auto_commit=True,
        value_deserializer=lambda b: __import__("json").loads(b.decode()),
    )
    log.info("asset-service up (tenant=%s)", TENANT)
    last = time.monotonic()
    while _running:
        for _tp, records in consumer.poll(timeout_ms=1000, max_records=500).items():
            for rec in records:
                try:
                    observe(rec.value)
                except Exception as e:
                    log.warning("observe error: %s", e)
        if time.monotonic() - last >= FLUSH_SECS:
            flush(ch)
            last = time.monotonic()
    flush(ch)
    consumer.close()


if __name__ == "__main__":
    main()
