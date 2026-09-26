"""B-U9/R14: the sensor stack must pass one consistent tenant/sensor identity to the shipper — the
router reads NDR_TENANT/NDR_SENSOR, so the compose must declare them, sourced from the same vars the
capture-agent uses (so telemetry and capture identities cannot diverge)."""
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_COMPOSE = open(os.path.join(_ROOT, "deploy", "sensor", "docker-compose.yml"), encoding="utf-8").read()
_ROUTE = open(os.path.join(_ROOT, "deploy", "fluent-bit", "route.lua"), encoding="utf-8").read()


def test_fluentbit_service_declares_identity_env():
    assert "NDR_TENANT:" in _COMPOSE and "NDR_SENSOR:" in _COMPOSE, "fluent-bit must receive NDR_TENANT/NDR_SENSOR"


def test_telemetry_and_capture_share_one_sensor_source():
    # the shipper (NDR_SENSOR) and the capture-agent (SENSOR_ID) both interpolate ${NDR_SENSOR}
    assert "${NDR_SENSOR:-sensor-1}" in _COMPOSE
    assert _COMPOSE.count("${NDR_SENSOR") >= 2, "one identity source shared by shipper + capture-agent"


def test_route_reads_env_identity():
    assert 'os.getenv("NDR_TENANT")' in _ROUTE and 'os.getenv("NDR_SENSOR")' in _ROUTE


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok  " + _n)
    print("\nall sensor-identity compose tests passed")
