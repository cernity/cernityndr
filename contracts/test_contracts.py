#!/usr/bin/env python3
"""Contract tests for the NDR data model (plan U2).

Guards coherence between the JSON Schemas, sample docs, and topics.md — the
contract every downstream service (normalizer, detectors, finding service)
depends on. Runnable two ways:

    python3 test_contracts.py     # self-check, zero dependencies
    pytest test_contracts.py

Uses `jsonschema` for full validation when it is installed; otherwise falls back
to a minimal checker that enforces `required`, `enum`, and `additionalProperties:
false` — the only rules the plan's named failure cases exercise.

ponytail: the fallback checker is intentionally partial (required/enum/unknown-key
only). Full JSON Schema semantics are enforced at runtime by consumers via
`jsonschema`; upgrade this to import jsonschema unconditionally once it is a
declared dependency of the contracts package.
"""
import json
import re
from pathlib import Path

HERE = Path(__file__).parent

try:
    import jsonschema  # type: ignore

    def check(schema, doc):
        jsonschema.validate(doc, schema)

    ENGINE = "jsonschema"
except ImportError:  # zero-dep fallback
    class ValidationError(Exception):
        pass

    def _check(schema, doc, path="$"):
        t = schema.get("type")
        if t == "object" or "properties" in schema:
            if not isinstance(doc, dict):
                raise ValidationError(f"{path}: expected object")
            for req in schema.get("required", []):
                if req not in doc:
                    raise ValidationError(f"{path}: missing required '{req}'")
            props = schema.get("properties", {})
            if schema.get("additionalProperties") is False:
                for k in doc:
                    if k not in props:
                        raise ValidationError(f"{path}: unknown property '{k}'")
            for k, v in doc.items():
                if k in props:
                    _check(props[k], v, f"{path}.{k}")
        if "enum" in schema and doc not in schema["enum"]:
            raise ValidationError(f"{path}: {doc!r} not in {schema['enum']}")

    def check(schema, doc):
        _check(schema, doc)

    ENGINE = "fallback"


def load(name):
    return json.loads((HERE / name).read_text())


def rejects(schema, doc):
    try:
        check(schema, doc)
        return False
    except Exception:
        return True


# --- fixtures -----------------------------------------------------------------
ENVELOPE = load("envelope.schema.json")
FLOW = load("network_flow.schema.json")
TLS = load("tls_observation.schema.json")
DNS = load("dns_transaction.schema.json")
ASSET = load("asset.schema.json")
FINDING = load("finding.schema.json")

VALID_ENVELOPE = {
    "schema_version": "1.0",
    "tenant_id": "customer-381",
    "sensor_id": "ol9-suri",
    "event_time": "2026-08-18T16:40:11.842Z",
    "source_product": "suricata",
    "event_type": "tls",
    "community_id": "1:abcdef",
    "payload": {},
}

VALID_FLOW = {
    "tenant_id": "customer-381", "sensor_id": "ol9-suri",
    "event_time": "2026-08-18T16:40:11Z", "community_id": "1:abc",
    "src_ip": "10.0.0.5", "dst_ip": "1.1.1.1", "transport": "TCP",
    "app_proto": "tls", "ndpi_risk_set": ["XSS"], "alerted": False,
}

VALID_TLS = {
    "tenant_id": "customer-381", "sensor_id": "ol9-suri",
    "event_time": "2026-08-18T16:40:11Z", "community_id": "1:abc",
    "src_ip": "10.0.0.5", "dst_ip": "1.1.1.1", "ja4": "t13d1516h2_...",
}

VALID_DNS_V3 = {
    "tenant_id": "customer-381", "sensor_id": "ol9-suri",
    "event_time": "2026-08-18T16:40:11Z", "dns_version": 3,
    "client_ip": "10.0.0.5", "query_name": "example.com", "query_type": "A",
}

VALID_ASSET = {
    "tenant_id": "customer-381", "asset_key": "asset-0001",
    "first_seen": "2026-08-18T00:00:00Z", "last_seen": "2026-08-18T16:40:11Z",
    "ip_set": ["10.0.0.5"], "confidence": 0.9,
}

VALID_FINDING = {
    "finding_id": "f-0001", "tenant_id": "customer-381",
    "detector_id": "beacon", "detector_version": "1.0",
    "category": "c2", "severity": 7, "confidence": 0.8,
    "first_seen": "2026-08-18T00:00:00Z", "last_seen": "2026-08-18T16:40:11Z",
    "state": "CANDIDATE",
    # detectors emit entities as a JSON-serialized string on the wire (see below)
    "entities": json.dumps([{"type": "ip", "role": "src", "value": "10.0.0.5"}]),
}

CANONICAL_TOPICS = {
    "suricata.raw.v1", "suricata.flow.v1", "suricata.dns.v1", "suricata.tls.v1",
    "suricata.http.v1", "suricata.ssh.v1", "suricata.windows.v1",
    "suricata.file.v1", "suricata.anomaly.v1", "suricata.stats.v1",
    "ndr.finding.candidate.v1", "ndr.finding.final.v1",
    "ndr.capture.request.v1", "ndr.capture.status.v1",
    "ndr.enrichment.request.v1", "ndr.enrichment.result.v1",
}
FINDING_STATES = {
    "CANDIDATE", "SCORED", "CAPTURE_REQUESTED", "ENRICHED",
    "ENRICHMENT_FAILED", "SUPPRESSED", "FINAL", "DEVO_QUEUED", "DEVO_SENT",
}


# --- tests --------------------------------------------------------------------
def test_valid_docs_pass():
    check(ENVELOPE, VALID_ENVELOPE)
    check(FLOW, VALID_FLOW)
    check(TLS, VALID_TLS)
    check(DNS, VALID_DNS_V3)
    check(ASSET, VALID_ASSET)
    check(FINDING, VALID_FINDING)


def test_finding_entities_accepts_wire_string_and_array():
    # Detectors emit `entities` as a JSON-serialized string (east-west/behavioral/
    # protocol/... all do `json.dumps([...])`). Guard that the published contract
    # accepts the real wire form AND the raw array, so the two never drift again.
    as_string = dict(VALID_FINDING)
    as_string["entities"] = json.dumps([{"type": "ip", "value": "10.0.0.5"}])
    check(FINDING, as_string)
    as_array = dict(VALID_FINDING)
    as_array["entities"] = [{"type": "ip", "value": "10.0.0.5"}]
    check(FINDING, as_array)


def test_envelope_requires_identity():
    for missing in ("tenant_id", "sensor_id", "schema_version"):
        doc = dict(VALID_ENVELOPE)
        del doc[missing]
        assert rejects(ENVELOPE, doc), f"envelope must reject missing {missing}"


def test_dns_v2_shape_flagged():
    # A v2-shaped record (no explicit dns_version) is rejected, not silently accepted.
    doc = dict(VALID_DNS_V3)
    del doc["dns_version"]
    assert rejects(DNS, doc)
    # An explicit non-v3 version is also rejected (we pin v3).
    doc2 = dict(VALID_DNS_V3, dns_version=2)
    assert rejects(DNS, doc2)


def test_finding_state_enum_enforced():
    assert rejects(FINDING, dict(VALID_FINDING, state="BOGUS"))
    for st in FINDING_STATES:
        check(FINDING, dict(VALID_FINDING, state=st))


def test_finding_enum_matches_canonical():
    assert set(FINDING["properties"]["state"]["enum"]) == FINDING_STATES


def test_topics_md_matches_canonical():
    text = (HERE / "topics.md").read_text()
    found = set(re.findall(r"^(?:suricata|ndr)\.[a-z.]+\.v\d+$", text, re.MULTILINE))
    assert found == CANONICAL_TOPICS, (
        f"topics.md drift: missing={CANONICAL_TOPICS - found} "
        f"extra={found - CANONICAL_TOPICS}"
    )


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} contract tests passed (engine: {ENGINE})")
