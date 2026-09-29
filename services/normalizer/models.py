"""Normalizer transforms (plan U6): raw Suricata EVE -> typed NDR rows.

Pure functions, no I/O — this is the trusted-ingress boundary where tenant/sensor
identity is injected and the schema is pinned. `app.py` wraps these with the
Kafka consumer + ClickHouse writer. Contracts: docker/ndr/contracts/*.schema.json.
"""
from __future__ import annotations

# Suricata EVE event_type -> transform name. Only these are persisted; other
# telemetry (arp, mdns, dhcp, ...) is kept in the raw MinIO archive, not typed.
SUPPORTED = {"flow", "tls", "dns"}   # canonical bidirectional flow only; netflow
                                     # (unidirectional) is dropped so it does not
                                     # double-write network_flow rows


def inject_identity(eve: dict, cfg_tenant: str, cfg_sensor: str) -> tuple[str, str]:
    """Trusted-ingress identity. Prefer a sensor id the edge stamped on the
    event (fleet case); fall back to the configured sensor (single-sensor lab).
    tenant is always config-driven — it is never trusted from the wire."""
    sensor = eve.get("host") or eve.get("sensor_id") or cfg_sensor
    return cfg_tenant, sensor


def _ndpi(eve: dict) -> dict:
    n = eve.get("ndpi")
    return n if isinstance(n, dict) else {}


def _risks(ndpi: dict) -> list[str]:
    # nDPI 'risk' shape is 3rd-party/opaque (v6 §20); accept list or dict or str.
    r = ndpi.get("risk")
    if isinstance(r, list):
        return [str(x) for x in r]
    if isinstance(r, dict):
        return [str(k) for k in r]
    return [str(r)] if r else []


def flow_row(eve: dict, tenant: str, sensor: str) -> dict:
    f = eve.get("flow", {}) or {}
    n = _ndpi(eve)
    return {
        "tenant_id": tenant,
        "sensor_id": sensor,
        "event_time": eve.get("timestamp", ""),
        "flow_id": int(eve.get("flow_id", 0) or 0),
        "community_id": eve.get("community_id", ""),
        "src_ip": eve.get("src_ip", ""),
        "src_port": int(eve.get("src_port", 0) or 0),
        "dst_ip": eve.get("dest_ip", ""),
        "dst_port": int(eve.get("dest_port", 0) or 0),
        "transport": eve.get("proto", ""),
        "app_proto": eve.get("app_proto", ""),
        # nDPI kept best-effort + opaque — no hard dependency on 3rd-party keys.
        "ndpi_protocol": str(n.get("proto", "")),
        "ndpi_application": str(n.get("app_protocol", n.get("application", ""))),
        "ndpi_risk_set": _risks(n),
        "pkts_to_server": int(f.get("pkts_toserver", 0) or 0),
        "pkts_to_client": int(f.get("pkts_toclient", 0) or 0),
        "bytes_to_server": int(f.get("bytes_toserver", 0) or 0),
        "bytes_to_client": int(f.get("bytes_toclient", 0) or 0),
        "state": f.get("state", ""),
        "alerted": 1 if eve.get("alert") else 0,
    }


def tls_row(eve: dict, tenant: str, sensor: str) -> dict:
    t = eve.get("tls", {}) or {}
    ja3 = t.get("ja3", {})
    ja3s = t.get("ja3s", {})
    return {
        "tenant_id": tenant,
        "sensor_id": sensor,
        "event_time": eve.get("timestamp", ""),
        "community_id": eve.get("community_id", ""),
        "src_ip": eve.get("src_ip", ""),
        "dst_ip": eve.get("dest_ip", ""),
        "dst_port": int(eve.get("dest_port", 0) or 0),
        "sni": t.get("sni", ""),
        "tls_version": t.get("version", ""),
        "ja3": ja3.get("hash", "") if isinstance(ja3, dict) else str(ja3 or ""),
        "ja3s": ja3s.get("hash", "") if isinstance(ja3s, dict) else str(ja3s or ""),
        "ja4": t.get("ja4", "") or "",
        "ndpi_application": str(_ndpi(eve).get("app_protocol", "")),
    }


class QuarantineError(ValueError):
    """Raised when a record cannot be trusted to the pinned schema."""


def dns_row(eve: dict, tenant: str, sensor: str, stream_version: int = 3) -> dict:
    """Key by declared schema, never by sniffing (v6 §15). Our nsm stream is
    pinned v3; a record that explicitly declares a different version is
    quarantined rather than silently coerced."""
    d = eve.get("dns", {}) or {}
    declared = d.get("version")
    if declared is not None and int(declared) != stream_version:
        raise QuarantineError(f"dns version {declared} != stream {stream_version}")

    # v3 groups queries/answers; fall back to flat legacy fields defensively.
    queries = d.get("queries") or []
    q0 = queries[0] if queries else d
    return {
        "tenant_id": tenant,
        "sensor_id": sensor,
        "event_time": eve.get("timestamp", ""),
        "dns_version": stream_version,
        "community_id": eve.get("community_id", ""),
        "client_ip": eve.get("src_ip", ""),
        "resolver_ip": eve.get("dest_ip", ""),
        "query_name": q0.get("rrname", d.get("rrname", "")),
        "query_type": q0.get("rrtype", d.get("rrtype", "")),
        "rcode": d.get("rcode", ""),
    }


TABLE_FOR = {"flow": "network_flow",
             "tls": "tls_observation", "dns": "dns_transaction"}


def normalize(eve: dict, tenant: str, sensor: str, dns_version: int = 3):
    """Dispatch one EVE record -> (table, row) or None if not persisted."""
    et = eve.get("event_type")
    if et not in SUPPORTED:
        return None
    tenant, sensor = inject_identity(eve, tenant, sensor)
    if et == "flow":
        return "network_flow", flow_row(eve, tenant, sensor)
    if et == "tls":
        return "tls_observation", tls_row(eve, tenant, sensor)
    if et == "dns":
        return "dns_transaction", dns_row(eve, tenant, sensor, dns_version)
    return None


# U4 canonical evidence. The preserved record is the decoded bus EVE object,
# not a claim of byte-identical sensor log preservation.
import copy
import hashlib
import json
import math
from datetime import datetime, timedelta, timezone

OBSERVATION_TOPIC = "ndr.observation.normalized.v1"
OBSERVATION_TABLES = {**TABLE_FOR, "http": "http_observation"}


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _datetime(value):
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError("timezone required")
        return result.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError) as exc:
        raise QuarantineError("invalid or missing observation timestamp") from exc


def observation(eve, tenant, sensor, *, topic, partition, offset,
                ingested_at, clock_offset_ms=None, dns_version=3):
    """Return (typed table, extended row, observation), or None.

    Coordinates identify one bus occurrence, scoped to configured tenant/sensor.
    ingested_at must be stable across replay (Kafka record timestamp in app.py).
    clock_offset_ms is an optional TRUSTED measured sensor-minus-reference delta;
    never read it from EVE. Without it use ingest time and label that fallback.
    """
    et = eve.get("event_type")
    if et not in OBSERVATION_TABLES:
        return None
    tenant, sensor = inject_identity(eve, tenant, sensor)
    if not tenant or not isinstance(sensor, str) or not sensor:
        raise QuarantineError("observation identity required")
    sensor_time = _datetime(eve.get("timestamp"))
    ingest_time = _datetime(ingested_at)
    if clock_offset_ms is not None:
        if isinstance(clock_offset_ms, bool) or not math.isfinite(clock_offset_ms):
            raise QuarantineError("invalid trusted clock offset")
        normalized = sensor_time - timedelta(milliseconds=clock_offset_ms)
        method = "clock-offset"
    else:
        normalized, method = ingest_time, "ingest-fallback"
    table = OBSERVATION_TABLES[et]
    if et == "http":
        row = {"tenant_id": tenant, "sensor_id": sensor,
               "event_time": eve["timestamp"]}
    else:
        _, row = normalize(eve, tenant, sensor, dns_version)
    raw = canonical_json(eve)
    identity = [tenant, sensor, topic, partition, offset]
    obs_id = "obs:" + hashlib.sha256(canonical_json(identity).encode()).hexdigest()
    fields = {key: copy.deepcopy(eve[key]) for key in
              ("flow_id", "community_id", "src_ip", "src_port", "dest_ip",
               "dest_port", "proto", "app_proto", "tx_id") if key in eve}
    # A flow record does not establish handshake, payload, or packet access.
    payload = eve.get(et)
    if not isinstance(payload, dict) or not payload:
        raise QuarantineError(f"missing {et} evidence")
    fields[et] = copy.deepcopy(payload)
    capabilities = ["flow-only"] if et == "flow" else [
        {"dns": "dns-transaction", "tls": "tls-handshake", "http": "http-metadata"}[et]]
    if fields.get("community_id"):
        capabilities.append("community-id")
    if et == "tls":
        for fingerprint in ("ja3", "ja4"):
            value = payload.get(fingerprint)
            if isinstance(value, dict):
                value = value.get("hash")
            if isinstance(value, str) and value:
                capabilities.append(fingerprint)
    entities = [{"type": "ip", "role": role, "value": eve[key]}
                for key, role in (("src_ip", "src"), ("dest_ip", "dst"))
                if isinstance(eve.get(key), str) and eve[key]]
    doc = {"schema": "cernity.observation.v1", "obs_id": obs_id,
           "tenant": tenant, "sensor_id": sensor,
           "ts": {"sensor": eve["timestamp"], "normalized": normalized.isoformat(),
                  "ingested": ingest_time.isoformat(), "method": method,
                  "clock_offset_ms": clock_offset_ms},
           "entities": entities, "type": "conn" if et == "flow" else et,
           "fields": fields, "capabilities": capabilities,
           "source_ref": {"kind": "clickhouse-row", "table": "ndr." + table,
                          "tenant": tenant, "obs_id": obs_id,
                          "sha256": hashlib.sha256(raw.encode()).hexdigest(),
                          "topic": topic, "partition": partition, "offset": offset}}
    row.update(observation=canonical_json(doc), raw_record=raw)
    return table, row, doc
