"""Managed config (plan U4): detector thresholds and allowlists delivered as data
on a compacted Kafka topic (`ndr.config.behavioral.v1`), hot-reloadable at runtime,
with the current in-code constants as the bootstrap default.

A background thread consumes the compacted topic and atomically swaps an immutable
snapshot; a cold start with no config message runs identically to the hardcoded
service (DEFAULTS == today's constants), so the 35 detector unit tests are unchanged.
A malformed config message is rejected and the previous good snapshot is retained.
detectors.py is untouched; app.py reads `current()` and passes the values in.
"""
import json
import logging
import os
import threading

log = logging.getLogger("behavioral-detectors.config")

# DEFAULTS mirror the current detector constants exactly, so no config message ==
# today's behavior.
DEFAULTS = {
    "beacon_threshold": 0.80,
    "beacon_count_target": 12,
    "strobe_min_conns": 90,
    "exfil_bytes": 50_000_000,
    "dns_min_queries": 50,
    "dns_len_threshold": 40.0,
    "dns_entropy_threshold": 3.5,
    "exploded_min_subdomains": 30,
    "longconn_cum_secs": None,          # None -> app uses CUM_LONGCONN_SECS (window-relative)
    "longconn_cum_min_conns": 4,
    # allowlists applied to detectors at runtime (prefix / exact-ip sets)
    "beacon_allowlist": [],             # extra beacon-noise dst IPs (added to built-ins)
    "exfil_allowlist": [],              # extra trusted egress prefixes (added to built-ins)
}

_ALLOWED_KEYS = set(DEFAULTS)
_lock = threading.Lock()
_snapshot = dict(DEFAULTS)
_running = True


def current() -> dict:
    with _lock:
        return _snapshot


def _validate_and_merge(doc: dict) -> dict:
    """Merge a config document onto DEFAULTS, keeping only known keys with
    type-compatible values. Unknown/bad values are dropped, not fatal."""
    merged = dict(DEFAULTS)
    for k, v in (doc or {}).items():
        if k not in _ALLOWED_KEYS:
            continue
        default = DEFAULTS[k]
        if isinstance(default, list):
            if isinstance(v, list):
                merged[k] = [str(x) for x in v]
        elif default is None:
            if v is None or isinstance(v, (int, float)):
                merged[k] = v
        elif isinstance(v, (int, float)) and not isinstance(v, bool):
            merged[k] = type(default)(v)
    return merged


_base_allow = {}


def apply_allowlists(det, snap: dict) -> None:
    """Rebuild the detector's runtime allowlists as (built-in base | config), so a
    config that REMOVES an entry actually takes effect (append-only union would let
    a once-added allowlist entry live forever). The base is captured once."""
    if "beacon" not in _base_allow:
        _base_allow["beacon"] = set(det._BEACON_ALLOW)
        _base_allow["exfil"] = tuple(det._EXFIL_ALLOW)
    det._BEACON_ALLOW = _base_allow["beacon"] | set(snap.get("beacon_allowlist") or [])
    det._EXFIL_ALLOW = tuple(sorted(set(_base_allow["exfil"]) | set(snap.get("exfil_allowlist") or [])))


def start(bootstrap: str, det, on_reload=None,
          topic: str = "ndr.config.behavioral.v1") -> None:
    """Consume the compacted config topic on a daemon thread; swap the snapshot on
    each valid message. Never blocks startup: if Kafka/topic is unavailable the
    bootstrap DEFAULTS stay in effect."""
    def _run():
        global _snapshot
        try:
            from kafka import KafkaConsumer
            consumer = KafkaConsumer(topic, bootstrap_servers=bootstrap,
                                     auto_offset_reset="earliest", enable_auto_commit=True,
                                     group_id=None,
                                     value_deserializer=lambda b: b)
        except Exception as e:
            log.info("config topic unavailable, using defaults: %s", e)
            return
        while _running:
            for _tp, records in consumer.poll(timeout_ms=1000).items():
                for rec in records:
                    try:
                        doc = json.loads(rec.value.decode()) if rec.value else {}
                    except Exception as e:
                        log.warning("bad config message ignored: %s", e)
                        continue
                    merged = _validate_and_merge(doc)
                    with _lock:
                        _snapshot = merged
                    apply_allowlists(det, merged)
                    if on_reload:
                        on_reload()
                    log.info("config snapshot applied")
    if os.environ.get("NDR_CONFIG_TOPIC_DISABLE") != "1":
        threading.Thread(target=_run, daemon=True).start()
