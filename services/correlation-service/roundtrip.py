"""Local integration round-trip for the correlation service (build manual 9.5).

Proves the full bus round-trip on throwaway infrastructure, no full stack needed:
publish four FINAL findings for one host to Redpanda, let the running
correlation service consume them, correlate, persist window state to ClickHouse,
and emit an incident on the candidate topic; then consume that incident back off
the bus and read the persisted state from ClickHouse.

Prerequisites (see build manual section 9.5):
  1. Throwaway Redpanda + ClickHouse on localhost, topics + ndr.entity_risk_state created.
  2. The correlation service running against that infra:
       REDPANDA_BOOTSTRAP=localhost:19092 CLICKHOUSE_HOST=localhost CLICKHOUSE_USER=ndr \\
       CLICKHOUSE_PASSWORD=demo NDR_TENANT=acme EVAL_SECS=5 PERSIST_SECS=5 python app.py &
  3. pip install kafka-python-ng clickhouse-connect

Run:  BOOT=localhost:19092 CH_PASSWORD=demo python roundtrip.py
Exit code 0 on a successful round-trip, 1 if no incident arrives.
"""
import json
import os
import sys
import time

from kafka import KafkaConsumer, KafkaProducer
import clickhouse_connect

BOOT = os.environ.get("BOOT", os.environ.get("REDPANDA_BOOTSTRAP", "localhost:19092"))
CH_HOST = os.environ.get("CH_HOST", "localhost")
CH_PORT = int(os.environ.get("CH_PORT", "8123"))
CH_USER = os.environ.get("CH_USER", "ndr")
CH_PASSWORD = os.environ.get("CH_PASSWORD", "demo")
TENANT = os.environ.get("NDR_TENANT", "acme")
HOST = os.environ.get("TEST_HOST", "10.0.0.50")

FINAL = "ndr.finding.final.v1"
CAND = "ndr.finding.candidate.v1"

# A scripted multi-stage attack on one host: recon -> access -> C2 -> lateral.
STAGES = [
    ("horizontal_scan", "recon", 5, ["T1046"]),
    ("ids_signature", "malware", 9, ["T1071"]),
    ("beacon", "c2", 7, ["T1071"]),
    ("lateral_movement", "lateral", 7, ["T1021"]),
]


def final_finding(det, cat, sev, mitre):
    return {"finding_id": f"{det}-{HOST}", "tenant_id": TENANT, "detector_id": det,
            "category": cat, "severity": sev, "confidence": 0.8, "mitre": mitre,
            "state": "FINAL",
            "entities": json.dumps([{"type": "ip", "role": "src", "value": HOST}])}


def main():
    prod = KafkaProducer(bootstrap_servers=BOOT,
                         value_serializer=lambda v: json.dumps(v).encode())
    cons = KafkaConsumer(CAND, bootstrap_servers=BOOT, group_id="roundtrip-demo",
                         auto_offset_reset="latest",
                         value_deserializer=lambda b: json.loads(b.decode()))
    cons.poll(timeout_ms=3000)   # force partition assignment before we produce

    print(f"[1] producing {len(STAGES)} FINAL findings for {HOST} -> {FINAL}")
    for det, cat, sev, mitre in STAGES:
        prod.send(FINAL, final_finding(det, cat, sev, mitre))
        print(f"      sent  {det:<17} sev {sev}")
    prod.flush()

    print(f"[2] waiting for an incident on {CAND} ...")
    deadline = time.time() + 90
    incident = None
    while time.time() < deadline and not incident:
        for _tp, recs in cons.poll(timeout_ms=1000).items():
            for r in recs:
                if r.value.get("detector_id") == "correlation_incident":
                    incident = r.value
                    break
    if not incident:
        print("    NO incident received within 90s")
        return 1

    print("\n>>> [3] INCIDENT consumed back off the bus:")
    keep = ("finding_id", "detector_id", "category", "severity", "mitre", "evidence_refs")
    print(json.dumps({k: incident.get(k) for k in keep}, indent=2))
    ents = json.loads(incident.get("entities", "[]"))
    narr = next((e["value"] for e in ents if e.get("type") == "narrative"), "")
    print(f"    narrative: {narr}")

    print("\n>>> [4] window state persisted in ClickHouse (ndr.entity_risk_state):")
    ch = clickhouse_connect.get_client(host=CH_HOST, port=CH_PORT,
                                       username=CH_USER, password=CH_PASSWORD, database="ndr")
    rows = ch.query("SELECT entity, length(JSONExtractArrayRaw(findings_json)) AS n, updated "
                    "FROM ndr.entity_risk_state FINAL").result_rows
    for entity, n, updated in rows:
        print(f"    entity={entity}  findings_in_window={n}  updated={updated}")

    print("\nROUND-TRIP COMPLETE: produce -> correlation-service -> ClickHouse -> incident -> consume.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
