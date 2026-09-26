"""U5/R5: the default monitoring stack scrapes the real targets with reproducible, bounded config.
Structural checks against deploy/central/monitoring/ (no live stack needed)."""
import os
import re

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MON = os.path.join(_ROOT, "deploy", "central", "monitoring")
_PROM = open(os.path.join(_MON, "prometheus.yml"), encoding="utf-8").read()
_COMPOSE = open(os.path.join(_MON, "docker-compose.yml"), encoding="utf-8").read()
_DS = open(os.path.join(_MON, "grafana", "provisioning", "datasources", "prometheus.yml"), encoding="utf-8").read()


def test_core_services_are_scrape_targets():
    for svc in ("ndr-finding-service", "ndr-threat-intel", "ndr-coverage-detector",
                "behavioral-detectors-behavioral-detectors-1"):
        assert svc + ":9108" in _PROM, "missing scrape target " + svc


def test_host_and_container_and_broker_exporters_present():
    assert "9100" in _PROM and "node" in _PROM                 # node_exporter (host)
    assert "cadvisor:8080" in _PROM                             # cAdvisor
    assert "/public_metrics" in _PROM and "redpanda:9644" in _PROM  # broker


def test_node_exporter_observes_host_not_container():
    assert "--path.rootfs=/host/root" in _COMPOSE
    assert "/:/host/root:ro" in _COMPOSE and "network_mode: host" in _COMPOSE


def test_retention_has_duration_and_size_on_persistent_volume():
    assert "--storage.tsdb.retention.time=" in _COMPOSE          # duration
    assert "--storage.tsdb.retention.size=" in _COMPOSE          # size budget (R5)
    assert "cernity-prometheus-data:/prometheus" in _COMPOSE     # persistent volume


def test_images_are_pinned_not_latest():
    for line in _COMPOSE.splitlines():
        m = re.search(r"image:\s*(\S+)", line)
        if m:
            assert not m.group(1).endswith(":latest"), "monitoring image must be pinned (R5): " + m.group(1)
            assert ":" in m.group(1), "monitoring image needs an explicit tag: " + m.group(1)


def test_grafana_datasource_points_at_prometheus():
    assert "http://prometheus:9090" in _DS and "type: prometheus" in _DS


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok  " + _n)
    print("\nall prometheus scrape-target tests passed")
