"""Sensor-side capture agent — I/O shell (plan U10-follow-up).

Consumes ndr.capture.arm.v1, actuates Suricata's conditional PCAP over the LOCAL
command socket, ships the bounded PCAP to MinIO, disarms, and emits
ndr.enrichment.request.v1 (-> zeek-central) + ndr.capture.status.v1 (completion,
so the orchestrator frees the budget). Pure logic + policy live in agent.py.

Deployed ON the sensor. No inbound SSH, no network-exposed Suricata socket:
directives arrive over the same authenticated Kafka bus as everything else.
"""
import json
import logging
import os
import ndr_runtime
import signal
import threading
import time

import boto3
from kafka import KafkaConsumer, KafkaProducer

import agent
import suricata_socket as ss

log = ndr_runtime.setup_logging("capture-agent")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
SENSOR_ID = os.environ.get("SENSOR_ID", "sensor-1")
SOCK = os.environ.get("SURICATA_SOCKET", "/var/run/suricata/suricata-command.socket")
PCAP_DIR = os.environ.get("PCAP_DIR", "/var/log/suricata/ndr-capture")
BUCKET = os.environ.get("PCAP_BUCKET", "ndr-pcap")
RING_DIR = os.environ.get("RING_DIR", "/var/log/suricata/ndr-ring")   # rolling-buffer dir (U2)
LOOKBACK_SECS = float(os.environ.get("NDR_LOOKBACK_SECS", "120"))

ARM_TOPIC = "ndr.capture.arm.v1"
ENRICH_TOPIC = "ndr.enrichment.request.v1"
STATUS_TOPIC = "ndr.capture.status.v1"
FILE_TOPIC = "ndr.file.extracted.v1"          # plan U5: carved files -> file-yara

FILESHIP_SECS = float(os.environ.get("FILESHIP_SECS", "10"))

_running = True
_active = 0
_lock = threading.Lock()
_shipped_shas = set()


def _stop(*_):
    global _running
    _running = False


def _entries_in(directory):
    out = []
    try:
        for name in os.listdir(directory):
            p = os.path.join(directory, name)
            # ring/conditional pcap-log names files <base>.pcap.<ts> or <base>.pcap
            if (".pcap" in name) and os.path.isfile(p):
                out.append((p, os.path.getmtime(p)))
    except FileNotFoundError:
        pass
    return out


def _pcap_entries():
    return _entries_in(PCAP_DIR)


def _capture(directive, producer, s3):
    """One capture lifecycle: arm -> bounded wait -> disarm -> ship -> emit."""
    global _active
    profile = directive.get("capture_profile", "ip")
    value = directive["value"].strip()
    fid = directive.get("finding_id", "")
    setname, settype = agent.dataset_for(profile)
    key = agent.pcap_key(directive)
    ttl = agent.ttl_secs(directive)
    cap_bytes = agent.max_bytes(directive)
    status = {"finding_id": fid, "sensor_id": SENSOR_ID, "profile": profile, "value": value}
    start = time.time()
    armed = False
    try:
        ss.dataset_add(SOCK, setname, settype, value)
        armed = True
        log.info("ARMED %s %s=%s ttl=%ss cap=%dB", setname, settype, value, ttl, cap_bytes)
        # Bounded wait: stop at TTL or when captured bytes hit the cap.
        while time.time() - start < ttl and _running:
            time.sleep(2)
            wpcaps = agent.window_pcaps(_pcap_entries(), start)
            if sum(os.path.getsize(p) for p in wpcaps) >= cap_bytes:
                log.info("byte cap hit for %s", value)
                break
    finally:
        if armed:
            try:
                ss.dataset_remove(SOCK, setname, settype, value)
                log.info("DISARMED %s=%s", setname, value)
            except Exception as e:  # noqa: BLE001
                log.error("DISARM FAILED %s=%s: %s", setname, value, e)

    wpcaps = agent.window_pcaps(_pcap_entries(), start)
    wpcaps = [p for p in wpcaps if os.path.getsize(p) > 24]  # skip empty pcap headers
    bucket, _, okey = key.partition("/")
    try:
        if not wpcaps:
            raise RuntimeError("no packets captured in window")
        # ponytail: upload the largest window file; concurrent arms share the
        # conditional pcap-log, so BPF-narrow here if per-arm isolation matters.
        src = max(wpcaps, key=os.path.getsize)
        s3.upload_file(src, bucket, okey)
        size = os.path.getsize(src)
        producer.send(ENRICH_TOPIC, {"finding_id": fid, "sensor_id": SENSOR_ID, "pcap_ref": key})
        producer.send(STATUS_TOPIC, {"finding_id": fid, "sensor_id": SENSOR_ID, "profile": profile,
                                     "value": value, "state": "completed", "bytes": size,
                                     "pcap_ref": key, "armed": False})
        log.info("SHIPPED %s (%dB) -> %s; enrichment requested", src, size, key)
    except Exception as e:  # noqa: BLE001
        producer.send(STATUS_TOPIC, {**status, "state": "failed", "error": str(e), "armed": False})
        log.error("CAPTURE FAILED %s=%s: %s", profile, value, e)
    finally:
        producer.flush()
        with _lock:
            _active -= 1


def _lookback_capture(directive, producer, s3):
    """Look-back retrieval (plan 2026-08-25-002, U2): slice the pre-trigger window
    out of the rolling ring, carve the finding's connection by BPF, and ship it on
    the same MinIO -> zeek-central path as a forward capture. Honest bounds: reports
    the window it actually recovered when the ring holds less than requested."""
    import subprocess
    fid = directive.get("finding_id", "")
    trigger = float(directive.get("trigger_ts") or time.time())
    lookback = float(directive.get("lookback_secs") or LOOKBACK_SECS)
    files = agent.lookback_pcaps(_entries_in(RING_DIR), trigger, lookback)
    key = agent.lookback_key(directive)
    bucket, _, okey = key.partition("/")
    if not files:
        producer.send(STATUS_TOPIC, {"finding_id": fid, "sensor_id": SENSOR_ID, "kind": "lookback",
                                     "state": "no_data", "covered_secs": 0, "armed": False})
        producer.flush()
        log.info("LOOKBACK no ring data for %s", fid)
        return
    # actual recovered window (honest bounds, U3): oldest..newest ring mtime we used
    mtimes = [m for _p in files for _pp, m in [_ring_mtime(_p)]]
    covered = int(trigger - min(mtimes)) if mtimes else 0
    bpf = agent.lookback_bpf(directive)
    carved = []
    try:
        for i, f in enumerate(files):
            out = f"/tmp/lb-{fid}-{i}.pcap"
            cmd = ["tcpdump", "-r", f, "-w", out] + ([bpf] if bpf else [])
            subprocess.run(cmd, check=False, stderr=subprocess.DEVNULL)
            if os.path.exists(out) and os.path.getsize(out) > 24:
                carved.append(out)
        if not carved:
            raise RuntimeError("no packets matched in look-back window")
        src = max(carved, key=os.path.getsize)      # ship the largest slice (forward-path parity)
        s3.upload_file(src, bucket, okey)
        size = os.path.getsize(src)
        producer.send(ENRICH_TOPIC, {"finding_id": fid, "sensor_id": SENSOR_ID, "pcap_ref": key})
        producer.send(STATUS_TOPIC, {"finding_id": fid, "sensor_id": SENSOR_ID, "kind": "lookback",
                                     "state": "completed", "bytes": size, "pcap_ref": key,
                                     "covered_secs": covered, "requested_secs": int(lookback), "armed": False})
        log.info("LOOKBACK shipped %s (%dB, covered %ds of %ds) -> %s", src, size, covered, int(lookback), key)
    except Exception as e:  # noqa: BLE001
        producer.send(STATUS_TOPIC, {"finding_id": fid, "sensor_id": SENSOR_ID, "kind": "lookback",
                                     "state": "failed", "error": str(e), "armed": False})
        log.error("LOOKBACK FAILED %s: %s", fid, e)
    finally:
        for c in carved:
            try:
                os.remove(c)
            except OSError:
                pass
        producer.flush()


def _ring_mtime(path):
    try:
        return path, os.path.getmtime(path)
    except OSError:
        return path, 0.0


def _walk_filestore():
    """(path, name, sha256, size) for every file under the Suricata file-store."""
    out = []
    for root, _dirs, files in os.walk(agent.FILESTORE_DIR):
        for name in files:
            p = os.path.join(root, name)
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            out.append((p, name, agent.sha_from_name(name), size))
    return out


def _file_ship_loop(producer, s3):
    """Ship newly carved Suricata files to MinIO and announce them (plan U5).
    Runs alongside the arm consumer; reuses the same MinIO/Kafka clients."""
    while _running:
        entries = _walk_filestore()
        for p, name, sha, size in entries:
            if not agent.should_ship_file(size, sha, _shipped_shas):
                continue
            try:
                s3.upload_file(p, agent.FILES_BUCKET, sha)
                producer.send(FILE_TOPIC, agent.file_extracted_event(SENSOR_ID, sha, size))
                _shipped_shas.add(sha)
                log.info("FILE SHIPPED %s (%dB) -> %s/%s", name, size, agent.FILES_BUCKET, sha)
            except Exception as e:  # noqa: BLE001
                log.error("file ship %s failed: %s", name, e)
        # Bound the dedup set to what is still on disk, so it cannot grow without
        # limit as the file-store rotates. Re-shipping a file after a restart is
        # harmless: file-yara keys its finding on the sha, so downstream dedups it.
        _shipped_shas.intersection_update(sha for _p, _n, sha, _s in entries if sha)
        producer.flush()
        for _ in range(int(FILESHIP_SECS)):
            if not _running:
                return
            time.sleep(1)


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    os.makedirs(PCAP_DIR, exist_ok=True)
    producer = KafkaProducer(bootstrap_servers=BOOTSTRAP,
                             value_serializer=lambda v: json.dumps(v).encode())
    consumer = KafkaConsumer(ARM_TOPIC, bootstrap_servers=BOOTSTRAP,
                             group_id=f"ndr-capture-agent-{SENSOR_ID}",
                             auto_offset_reset="latest", enable_auto_commit=True,
                             value_deserializer=lambda b: json.loads(b.decode()))
    s3 = boto3.client("s3", endpoint_url=os.environ.get("MINIO_ENDPOINT", "http://minio:9000"),
                      aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
                      aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"])
    log.info("capture-agent up sensor=%s socket=%s pcap_dir=%s", SENSOR_ID, SOCK, PCAP_DIR)
    threading.Thread(target=_file_ship_loop, args=(producer, s3), daemon=True).start()

    global _active
    while _running:
        for _tp, records in consumer.poll(timeout_ms=1000, max_records=10).items():
            for rec in records:
                d = rec.value
                if not agent.for_this_sensor(d, SENSOR_ID):
                    continue
                ok, why = agent.validate(d)
                if not ok:
                    producer.send(STATUS_TOPIC, {"finding_id": d.get("finding_id", ""),
                                                 "sensor_id": SENSOR_ID, "state": "rejected",
                                                 "reason": why, "armed": False})
                    producer.flush()
                    log.warning("REJECTED %s: %s", d, why)
                    continue
                # Look-back retrieval (U2/U3): admitted by the SAME sensor+validate
                # gate as a forward capture (parity), but it is time-critical (the
                # ring is overwriting the pre-trigger packets right now) and cheap
                # (it slices existing files), so it is NOT blocked by the forward
                # concurrency budget. It races to grab the slice before it is gone.
                if agent.wants_lookback(d):
                    threading.Thread(target=_lookback_capture, args=(d, producer, s3), daemon=True).start()
                with _lock:
                    bok, breason = agent.budget_ok(_active)
                    if not bok:
                        producer.send(STATUS_TOPIC, {"finding_id": d.get("finding_id", ""),
                                                     "sensor_id": SENSOR_ID, "state": "refused",
                                                     "reason": breason, "armed": False})
                        producer.flush()
                        log.warning("AGENT REFUSED %s: %s", d.get("value"), breason)
                        continue
                    _active += 1
                threading.Thread(target=_capture, args=(d, producer, s3), daemon=True).start()

    consumer.close()
    producer.close()


if __name__ == "__main__":
    main()
