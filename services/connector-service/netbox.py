"""NetBox CMDB connector (entity-graph U4) — ONE-WAY ingest, NetBox -> Cernity.

Pulls device records from a NetBox CMDB and emits asset-fact.v1 messages carrying the
EXTERNALLY-ASSIGNED attributes NetBox is authority for: owner + criticality. It NEVER writes
back to NetBox and NEVER emits an OBSERVED fact (ip/mac/hostname/role/ja4/certs/applications/
listening_services come from telemetry, not a CMDB).

netbox_to_facts() is a PURE, deterministic mapping — unit-tested without a broker or NetBox.
The run loop is config-gated: with NETBOX_URL unset it is a clean no-op (secure default — many
deployments have no CMDB). Heavy imports (kafka via ndr_runtime, requests) are lazy.
"""
import os

import ndr_runtime

# Topic the connector produces onto. Pointing asset-service at it (merge() already sets
# owner/criticality when supplied) is a thin follow-up — out of U4 scope.
ASSET_FACT_TOPIC = os.environ.get("ASSET_FACT_TOPIC", "ndr.asset.fact.v1")
SOURCE = "netbox-cmdb"


def _entity_ref(device):
    """The entity a device's facts describe: its primary IP (CIDR stripped). NetBox nests it
    under primary_ip{,4,6}.address as '10.0.0.5/24'."""
    for field in ("primary_ip", "primary_ip4", "primary_ip6"):
        ip = device.get(field)
        if isinstance(ip, dict) and ip.get("address"):
            return str(ip["address"]).split("/")[0]
    return None


def _owner(device):
    """Owner from the device's tenant (NetBox's ownership model) or an explicit owner custom-field."""
    tenant = device.get("tenant")
    if isinstance(tenant, dict) and tenant.get("name"):
        return str(tenant["name"])
    cf = device.get("custom_fields") or {}
    return str(cf["owner"]) if cf.get("owner") else None


def _criticality(device):
    """Criticality from a NetBox criticality custom-field."""
    cf = device.get("custom_fields") or {}
    return str(cf["criticality"]) if cf.get("criticality") else None


def netbox_to_facts(devices, tenant, synced_at):
    """PURE mapping: NetBox device payload -> list[asset-fact.v1]. Emits ONLY owner/criticality,
    one fact per PRESENT field; SKIPS a device with no entity_ref and SKIPS a missing field (never
    fabricates a value).

    `synced_at` is a REQUIRED explicit input (an RFC3339 instant). It is deliberately NOT defaulted
    to a wall-clock read: the mapping must be pure and deterministic — same (devices, tenant,
    synced_at) -> same facts, in stable device-then-predicate order. The sync instant is generated
    once at the runtime boundary (run() calls _now()) and threaded in, so one sync stamps every
    fact identically and the mapping stays testable without a clock."""
    facts = []
    for device in devices:
        ref = _entity_ref(device)
        if not ref:
            continue
        for predicate, value in (("owner", _owner(device)), ("criticality", _criticality(device))):
            if value:
                facts.append({
                    "tenant_id": tenant, "entity_ref": ref, "predicate": predicate,
                    "value": value, "source": SOURCE, "authority": True,
                    "synced_at": synced_at})
    return facts


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _fetch_devices(url, token):
    """Pull ALL pages of the NetBox device list (requests lazy). NetBox paginates with an absolute
    `next` URL; follow it until exhausted so later devices still receive facts. The authenticated
    requests are restricted to the configured NetBox origin — a `next` that points at a different
    scheme/host is NOT followed with our token, so a misconfigured or hostile CMDB cannot redirect
    the credential off-box."""
    import requests
    from urllib.parse import urlsplit
    base = url.rstrip("/")
    origin = (urlsplit(base).scheme, urlsplit(base).netloc)
    next_url = base + "/api/dcim/devices/"
    devices = []
    while next_url:
        cur = urlsplit(next_url)
        if (cur.scheme, cur.netloc) != origin:
            break                                     # never send the token off the NetBox origin
        resp = requests.get(next_url, headers={"Authorization": f"Token {token}"}, timeout=30)
        resp.raise_for_status()
        body = resp.json()
        devices.extend(body.get("results", []))
        next_url = body.get("next")
    return devices


# Per-send broker-ACK wait. The CMDB sync is rare and low-volume (one periodic pass, not a
# stream), so a blocking ack per fact is fine and keeps delivery confirmation simple.
# ponytail: per-send .get(); batch the futures only if a future CMDB dwarfs this volume.
PUBLISH_TIMEOUT = 30


def run():
    """Config-gated sync. NETBOX_URL or NETBOX_TOKEN unset/empty -> clean no-op (NO producer
    created, NO fetch): a CMDB-less deployment is the secure default, and a half-configured one
    (URL without token) must not fetch unauthenticated. Otherwise fetch every device page, map to
    owner/criticality facts stamped with ONE sync instant (_now() at this boundary — the mapping
    itself is clock-free), and emit each onto ASSET_FACT_TOPIC keyed by (tenant, entity_ref).

    Each send is confirmed with .get(): the broker ACK must land before the next fact, so a delivery
    failure RAISES here and the success line is never reached — a failed sync cannot masquerade as a
    successful one (flush() alone does not surface per-record delivery errors). The producer is this
    sync's own and is ALWAYS closed in finally — on success, on a fetch error, and on a delivery
    error — so the periodic app loop (app.main) never leaks a producer per pass."""
    url = os.environ.get("NETBOX_URL")
    token = os.environ.get("NETBOX_TOKEN")
    if not url or not token:
        return
    tenant = os.environ.get("NDR_TENANT", "default")
    log = ndr_runtime.setup_logging("connector-service")
    producer = ndr_runtime.make_producer()
    try:
        facts = netbox_to_facts(_fetch_devices(url, token), tenant, _now())
        for fact in facts:
            producer.send(ASSET_FACT_TOPIC,
                          key=f'{fact["tenant_id"]}:{fact["entity_ref"]}'.encode(),
                          value=fact).get(timeout=PUBLISH_TIMEOUT)   # raises on failed delivery
        producer.flush()
        log.info("netbox-cmdb sync emitted %d facts to %s", len(facts), ASSET_FACT_TOPIC)
    finally:
        producer.close()


if __name__ == "__main__":
    run()
