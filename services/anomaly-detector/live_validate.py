"""Live end-to-end validation for the anomaly tier (ce-doc-review A2/B follow-up).

Proves that suricata.anomaly.v1 -> anomaly-detector -> ndr.finding.candidate.v1
works on a real Redpanda, i.e. the tier is not injection-only. This is the piece
the review flagged as "config-done, live-validation-pending": the config cutover
(anomaly logged onto eve-nsm, the stream Vector tails) plus this driver together
prove the path end to end.

Prereq: Redpanda up with topics (docker/ndr/redpanda), reachable at $BOOT.
Run:  REDPANDA_BOOTSTRAP=127.0.0.1:19092 python live_validate.py
"""
import json
import os
import subprocess
import sys
import time

from kafka import KafkaProducer, KafkaConsumer

BOOT = os.environ.get("REDPANDA_BOOTSTRAP", "127.0.0.1:19092")
HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    env = dict(os.environ, REDPANDA_BOOTSTRAP=BOOT, NDR_TENANT="homelab")
    det = subprocess.Popen([sys.executable, "app.py"], cwd=HERE, env=env)
    try:
        time.sleep(6)  # let the detector join the group (auto_offset_reset=latest)
        cons = KafkaConsumer("ndr.finding.candidate.v1", bootstrap_servers=BOOT,
                             group_id="anomaly-live-validate", auto_offset_reset="latest",
                             value_deserializer=lambda b: json.loads(b.decode()),
                             consumer_timeout_ms=15000)
        cons.poll(timeout_ms=1000)  # assign + seek to end before publishing

        prod = KafkaProducer(bootstrap_servers=BOOT,
                             value_serializer=lambda v: json.dumps(v).encode())
        # a threat-relevant applayer anomaly, plus a decode-noise event that must drop
        prod.send("suricata.anomaly.v1", {
            "event_type": "anomaly", "src_ip": "10.0.0.9", "dest_ip": "45.9.148.2",
            "app_proto": "http",
            "anomaly": {"type": "applayer", "event": "APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION"}})
        prod.send("suricata.anomaly.v1", {
            "event_type": "anomaly", "src_ip": "10.0.0.9", "dest_ip": "8.8.8.8",
            "anomaly": {"type": "decode", "event": "decode.bad_checksum"}})
        prod.flush()

        got = []
        for rec in cons:
            got.append(rec.value)
            if rec.value.get("detector_id") == "protocol_anomaly":
                break
    finally:
        det.terminate()
        try:
            det.wait(timeout=5)
        except Exception:
            det.kill()

    hits = [c for c in got if c.get("detector_id") == "protocol_anomaly"]
    noise = any("bad_checksum" in c.get("entities", "") for c in got)
    if hits and not noise:
        print(f"PASS: live anomaly path works -> protocol_anomaly sev {hits[0]['severity']}; "
              "decode-noise dropped")
        return 0
    print(f"FAIL: hits={len(hits)} noise_leaked={noise}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
