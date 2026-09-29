"""B-U9/R14: the sensor stack must pass one consistent tenant/sensor identity to the shipper — the
router reads NDR_TENANT/NDR_SENSOR, so the compose must declare them, sourced from the same vars the
capture-agent uses (so telemetry and capture identities cannot diverge).

U3a extension: the registry consumer must ingest EXACTLY the topic U2's sensor-agent produces (one
topic name binds producer↔consumer), and it must never treat the producer-set heartbeat as verified
identity — the ingest path stamps producer_verified=False (verified identity is U3b)."""
import importlib.util
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_COMPOSE = open(os.path.join(_ROOT, "deploy", "sensor", "docker-compose.yml"), encoding="utf-8").read()
_ROUTE = open(os.path.join(_ROOT, "deploy", "fluent-bit", "route.lua"), encoding="utf-8").read()


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fluentbit_service_declares_identity_env():
    assert "NDR_TENANT:" in _COMPOSE and "NDR_SENSOR:" in _COMPOSE, "fluent-bit must receive NDR_TENANT/NDR_SENSOR"


def test_telemetry_and_capture_share_one_sensor_source():
    # the shipper (NDR_SENSOR) and the capture-agent (SENSOR_ID) both interpolate ${NDR_SENSOR}
    assert "${NDR_SENSOR:-sensor-1}" in _COMPOSE
    assert _COMPOSE.count("${NDR_SENSOR") >= 2, "one identity source shared by shipper + capture-agent"


def test_route_reads_env_identity():
    assert 'os.getenv("NDR_TENANT")' in _ROUTE and 'os.getenv("NDR_SENSOR")' in _ROUTE


def test_registry_consumes_the_topic_the_agent_emits():
    # One topic name binds U2's producer and U3a's consumer; a drift here silently
    # drops every heartbeat on the floor (the very break U3 was rejected for).
    reg = _load("registry_app", os.path.join(_ROOT, "services", "sensor-registry", "app.py"))
    agent = _load("sensor_health_agent", os.path.join(_ROOT, "services", "sensor-agent", "agent.py"))
    assert reg.HEALTH_TOPIC == agent.TOPIC == "ndr.sensor.health.v1"


def test_registry_ingest_never_trusts_producer_identity():
    # The ingest path must record the heartbeat's claimed identity but mark it
    # UNVERIFIED (producer_verified=False) — verified producer identity is U3b.
    reg = _load("registry_app", os.path.join(_ROOT, "services", "sensor-registry", "app.py"))
    contract = _load("sensor_health_contract", os.path.join(_ROOT, "contracts", "test_sensor_health.py"))
    store = reg.RegistryStore(":memory:")
    assert store.upsert_heartbeat(contract.FULL) is True
    row = store.get(contract.FULL["sensor_uuid"], [contract.FULL["tenant"]])
    assert row["producer_verified"] == 0


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok  " + _n)
    print("\nall sensor-identity compose tests passed")
