"""U2 lifecycle and deferred-arm regression tests."""
import ast
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

import pytest

from authz import Unauthorized, allow_actors
from lifecycle import IllegalTransition, RegistryLifecycle
from store import RegistryStore


def seeded(status="draft"):
    store = RegistryStore()
    store.create({
        "detection_id": "dns-tunnel-entropy", "source": "dns", "status": status,
        "version": "1.0.0",
        "manifest_ref": "detections/manifest/dns-detector.manifest.json",
        "change_history": [{"ts": "2026-09-01T00:00:00Z", "actor": "author",
                            "from": None, "to": status}],
    })
    return store, RegistryLifecycle(store, allow_actors("promoter"))


def test_staged_promotion():
    store, lifecycle = seeded()
    original = store.get("dns-tunnel-entropy")
    for target in ("shadow", "active"):
        result = lifecycle.promote("dns-tunnel-entropy", target, "promoter")
        assert result == store.get("dns-tunnel-entropy")
        assert result["status"] == target
    assert result["change_history"][:1] == original["change_history"]
    assert [(h["from"], h["to"]) for h in result["change_history"][1:]] == [
        ("draft", "shadow"), ("shadow", "active")]
    for record in result["change_history"][1:]:
        assert record["actor"] == "promoter"
        assert datetime.fromisoformat(record["ts"]).utcoffset().total_seconds() == 0


@pytest.mark.parametrize("current", ["draft", "shadow", "active", "retired"])
@pytest.mark.parametrize("target", ["draft", "shadow", "active", "retired", "unknown"])
def test_transition_matrix(current, target):
    allowed = {("draft", "shadow"), ("draft", "retired"),
               ("shadow", "active"), ("shadow", "retired"), ("active", "retired")}
    store, lifecycle = seeded(current)
    before = store.list()
    if (current, target) in allowed:
        result = lifecycle.promote("dns-tunnel-entropy", target, "promoter")
        assert result["status"] == target
        assert len(result["change_history"]) == 2
    else:
        with pytest.raises(IllegalTransition):
            lifecycle.promote("dns-tunnel-entropy", target, "promoter")
        assert store.list() == before


@pytest.mark.parametrize("actor", ["viewer", "", " ", None, "x" * 257])
@pytest.mark.parametrize("target", ["shadow", "retired"])
def test_unauthorized_unchanged(actor, target):
    store, lifecycle = seeded()
    before = store.list()
    with pytest.raises(Unauthorized):
        lifecycle.promote("dns-tunnel-entropy", target, actor)
    assert store.list() == before


def test_default_deny_and_no_request_policy_override():
    store, _ = seeded()
    lifecycle = RegistryLifecycle(store)
    with pytest.raises(Unauthorized):
        lifecycle.promote("dns-tunnel-entropy", "shadow", "promoter")
    with pytest.raises(TypeError):
        lifecycle.promote("dns-tunnel-entropy", "shadow", "viewer", authorize=lambda _: True)
    assert store.get("dns-tunnel-entropy")["status"] == "draft"


def test_unknown_detection():
    _, lifecycle = seeded()
    with pytest.raises(KeyError):
        lifecycle.promote("missing", "shadow", "promoter")


def test_promotion_only_calls_registry_store():
    store, _ = seeded()
    # A strict dependency spy: the sole integration receives only get/update;
    # any delivery/bundle or other integration call fails this assertion.
    boundary = Mock(wraps=store)
    lifecycle = RegistryLifecycle(boundary, allow_actors("promoter"))
    before = store.get("dns-tunnel-entropy")
    for target in ("shadow", "active", "retired"):
        result = lifecycle.promote("dns-tunnel-entropy", target, "promoter")
    assert [c[0] for c in boundary.mock_calls] == ["get", "update"] * 3
    assert {k: v for k, v in result.items() if k not in {"status", "change_history"}} == {
        k: v for k, v in before.items() if k not in {"status", "change_history"}}
    # U5 has no shipped delivery/bundle seam to patch. Pin the dependency surface
    # so adding a bus/sensor/bundle integration requires changing this guard.
    for name in ("lifecycle.py", "authz.py"):
        tree = ast.parse(Path(__file__).with_name(name).read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module)
        assert imports <= {"collections.abc", "datetime", "authz", "store"}
