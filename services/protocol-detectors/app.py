"""Protocol-detectors service (plan U8 Tier 2): ja4-rarity / cloud-staging / DoH /
cert-anomaly / suspicious-UA / ssh-brute / icmp-exfil. Consumes the protocol
topics. Scoring covered by test_proto.py.

State is externalized to the shared Redis so the service scales horizontally with
no double-emit (plan 006): the JA4-rarity "seen" set is a GLOBAL shared set (a JA4
is rare only if the WHOLE fleet has not seen it, so a per-replica set would false-
positive); ssh session counts and icmp byte totals are TTL'd counters keyed by
src|dst (the old in-process dicts never reset -- a latent leak); emission dedup is
shared-Redis with a STABLE cross-process finding hash (Python hash() is per-process
seeded). Detection is otherwise stateless per record.
"""
import hashlib
import json
import logging
import os
import signal
import time

import ndr_runtime                      # shared tuned consumer/producer + metrics
import store as store_mod
import proto

log = logging.getLogger("protocol-detectors")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

TENANT = os.environ.get("NDR_TENANT", "default")
APPROVED_RESOLVERS = set(x for x in os.environ.get("APPROVED_RESOLVERS", "").split(",") if x)
GROUP_ID = os.environ.get("NDR_GROUP_ID", "ndr-protocol-detectors")
STATE_BACKEND = os.environ.get("NDR_STATE_BACKEND", "memory")
REDIS_URL = os.environ.get("NDR_REDIS_URL", "redis://ndr-redis:6379/0")
JA4_WARMUP = int(os.environ.get("JA4_WARMUP", "5"))
JA4_TTL = float(os.environ.get("JA4_SEEN_TTL", "86400"))         # rarity window (1 day)
SSH_WINDOW = float(os.environ.get("SSH_WINDOW_SECS", "600"))
ICMP_WINDOW = float(os.environ.get("ICMP_WINDOW_SECS", "600"))
CAND = "ndr.finding.candidate.v1"

_store = store_mod.make_store(STATE_BACKEND, REDIS_URL)
_JA4KEY = f"ja4seen:{TENANT}"
_running = True


def _stop(*_):
    global _running
    _running = False


def _stable(s):
    return int(hashlib.sha1(s.encode()).hexdigest()[:15], 16)


def _ja4_rare(ja4):
    """Fleet-wide JA4 rarity via a shared Redis set (mirrors proto.is_rare_ja4:
    warmed up + not previously seen). Adds the JA4 to the global seen-set."""
    if not ja4:
        return False
    rare = _store.set_len(_JA4KEY) >= JA4_WARMUP and not _store.set_contains(_JA4KEY, ja4)
    _store.set_add(_JA4KEY, ja4, JA4_TTL)
    return rare


def _emit(producer, detector, category, sev, conf, entities):
    bucket = int(time.time() // 3600)
    if not _store.dedup_seen(f"emit:{TENANT}:{detector}:{_stable(entities) % 10**12}:{bucket}", 3600):
        return                                                  # already emitted (shared across replicas)
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    producer.send(CAND, {"finding_id": f"{detector}-{_stable(entities) % 10**10}-{bucket}",
                         "tenant_id": TENANT, "detector_id": detector, "detector_version": "1.0",
                         "category": category, "severity": sev, "confidence": conf,
                         "first_seen": now, "last_seen": now, "entities": entities,
                         "state": "CANDIDATE"})
    log.info("%s %s", detector.upper(), entities[:120])


def _handle(e, producer):
    et = e.get("event_type")
    src, dst, dport = e.get("src_ip"), e.get("dest_ip"), e.get("dest_port")
    if et in ("tls", "quic"):
        obj = e.get(et, {}) or {}
        sni, ja4 = obj.get("sni"), obj.get("ja4")
        transport = [{"type": "ja4", "value": ja4}] if et == "tls" else [{"type": "ja4", "value": ja4, "transport": "quic"}]
        if _ja4_rare(ja4):
            _emit(producer, "ja4_rarity", "c2", 5, 0.5,
                  json.dumps(transport + [{"type": "ip", "role": "src", "value": src},
                                          {"type": "sni", "value": sni}]))
        ch, c = proto.cloud_staging_hit(sni)
        if ch:
            _emit(producer, "cloud_staging", "exfil", 5, 0.5,
                  json.dumps([{"type": "ip", "role": "src", "value": src},
                              {"type": "sni", "value": sni}, {"type": "service", "value": c}]))
        dh, d = proto.doh_hit(sni, dport, APPROVED_RESOLVERS)
        if dh:
            _emit(producer, "doh_detect", "defense_evasion", 4, 0.5,
                  json.dumps([{"type": "ip", "role": "src", "value": src},
                              {"type": "sni", "value": sni}, {"type": "why", "value": d}]))
        if et == "tls":
            t = e.get("tls", {}) or {}
            an, why = proto.cert_anomaly(t.get("subject", ""), t.get("issuer", ""),
                                         t.get("notbefore", ""), t.get("notafter", ""))
            if an:
                _emit(producer, "tls_cert_anomaly", "c2", 5, 0.5,
                      json.dumps([{"type": "ip", "role": "dst", "value": dst},
                                  {"type": "sni", "value": sni}, {"type": "why", "value": why}]))
    elif et == "http":
        h = e.get("http", {}) or {}
        su, w = proto.suspicious_ua(h.get("http_user_agent"))
        if su and proto.is_external(dst):
            _emit(producer, "suspicious_ua", "c2", 4, 0.5,
                  json.dumps([{"type": "ip", "role": "src", "value": src},
                              {"type": "ip", "role": "dst", "value": dst},
                              {"type": "ua", "value": w}]))
    if (et == "ssh" or (et == "flow" and dport == 22)) and src and dst:
        n = _store.counter_add(f"ssh:{TENANT}:{src}|{dst}", "c", 1, SSH_WINDOW)
        if proto.ssh_brute_hit(int(n)):
            _emit(producer, "ssh_bruteforce", "credential_access", 6, 0.6,
                  json.dumps([{"type": "ip", "role": "src", "value": src},
                              {"type": "ip", "role": "dst", "value": dst},
                              {"type": "attempts", "value": int(n)}]))
    if et == "flow" and src and dst:
        f = e.get("flow", {}) or {}
        b = int(f.get("bytes_toserver", 0) or 0) + int(f.get("bytes_toclient", 0) or 0)
        tot = _store.counter_add(f"icmp:{TENANT}:{src}|{dst}", "b", b, ICMP_WINDOW)
        if proto.icmp_exfil_hit(e.get("proto", ""), int(tot), dst):
            _emit(producer, "icmp_exfil", "exfil", 7, 0.6,
                  json.dumps([{"type": "ip", "role": "src", "value": src},
                              {"type": "ip", "role": "dst", "value": dst},
                              {"type": "bytes", "value": int(tot)}]))


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    producer = ndr_runtime.make_producer()
    # quic events land in raw.v1 (unmapped by the shipper); QUIC-dominant traffic is
    # where the encrypted-C2 JA4/SNI signal is.
    consumer = ndr_runtime.make_consumer("suricata.tls.v1", "suricata.http.v1", "suricata.ssh.v1",
                                         "suricata.flow.v1", "suricata.raw.v1",
                                         group_id=GROUP_ID, auto_offset_reset="latest")
    m = ndr_runtime.metrics
    m.start(int(os.environ.get("NDR_METRICS_PORT", "9108")))
    m.set_ready("store", False)
    m.set_ready("consumer")
    log.info("protocol-detectors up (state=%s, ja4/cloud-staging/doh/cert/ua/ssh-brute/icmp-exfil)", STATE_BACKEND)
    while _running:
        if not m.is_ready():
            try:
                _store.dedup_seen("readyprobe", 1); m.set_ready("store")
            except Exception:
                pass
        for _tp, records in consumer.poll(timeout_ms=1000, max_records=1000).items():
            for rec in records:
                try:
                    _handle(rec.value, producer)
                except Exception as ex:
                    m.dropped("handler"); log.debug("skip record: %s", ex)
        producer.flush()
    consumer.close()
    producer.close()


if __name__ == "__main__":
    main()
