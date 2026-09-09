"""SOAR forwarder (plan U13). Consumes ndr.finding.final.v1, runs the playbook
(playbook.py), and drives effects: emits the action record to ndr.soar.action.v1
(assertable), optionally notifies ntfy, optionally POSTs to a real SOAR webhook
(Shuffle / n8n / TheHive). Self-contained — needs no external cred to run.

Env (all optional):
  NTFY_URL      e.g. https://ntfy.example/ndr-soc   (notification)
  SOAR_WEBHOOK  e.g. Shuffle/n8n webhook URL         (hand off to a real SOAR)
"""
import json
import logging
import os
import signal

import ndr_runtime                      # shared tuned consumer/producer (plan 003 U6 rollout)
import urllib.request

import playbook

log = ndr_runtime.setup_logging("soar-forwarder")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
NTFY_URL = os.environ.get("NTFY_URL", "")
SOAR_WEBHOOK = os.environ.get("SOAR_WEBHOOK", "")
ACTION_TOPIC = "ndr.soar.action.v1"

_running = True


def _stop(*_):
    global _running
    _running = False


def _post(url: str, data: bytes, headers: dict):
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (homelab)
        return r.status


def notify(n: dict):
    if NTFY_URL:
        try:
            _post(NTFY_URL, n["message"].encode(),
                  {"Title": n["title"], "Priority": str(n["priority"]),
                   "Tags": ",".join(t for t in n["tags"] if t)})
        except Exception as e:  # never let a notify failure drop the pipeline
            log.warning("ntfy failed: %s", e)


def handoff(result: dict):
    if SOAR_WEBHOOK:
        try:
            _post(SOAR_WEBHOOK, json.dumps(result).encode(),
                  {"Content-Type": "application/json"})
        except Exception as e:
            log.warning("SOAR webhook failed: %s", e)


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    producer = ndr_runtime.make_producer()
    consumer = ndr_runtime.make_consumer("ndr.finding.final.v1", group_id="ndr-soar-forwarder", auto_offset_reset="earliest")
    log.info("soar-forwarder up (ntfy=%s webhook=%s)", bool(NTFY_URL), bool(SOAR_WEBHOOK))

    ndr_runtime.start_health()          # /healthz /readyz /metrics (plan 003 obs)

    while _running:
        for _tp, records in consumer.poll(timeout_ms=1000, max_records=100).items():
            for rec in records:
                result = playbook.playbook(rec.value)
                producer.send(ACTION_TOPIC, result)
                notify(result["notification"])
                handoff(result)
                log.info("PLAYBOOK %s actions=%s", result["finding_id"], result["actions"])
        producer.flush()

    consumer.close()
    producer.close()


if __name__ == "__main__":
    main()
