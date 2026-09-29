"""U1a — tenant-safe PCAP object keys.

Characterization + fix guard for the cross-tenant PCAP object-key collision.

Current tree (pre-fix): the object key is `ndr-pcap/{fid or value}-{profile}.pcap`
with NO tenant segment (capture-orchestrator app.object_key, capture-agent
agent.pcap_key). Two tenants that produce the same flow tuple therefore resolve to
the SAME stored object and silently overwrite each other's PCAP — a live, pre-existing
tenant-isolation bug (the capture request already carries `tenant_id`; the key just
drops it). A naive `str(tenant)` fix would emit the literal 'None' segment for an
absent tenant. These tests forbid BOTH: distinct tenants must never collide, and an
absent tenant must use an explicit documented default, never 'None'.

Run: .venv/bin/python -m pytest services/capture-orchestrator/test_object_keys.py
"""
import importlib.util
import os
import shutil
import subprocess

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, "..", ".."))
_COMPOSE = os.path.join(_ROOT, "deploy", "sensor", "docker-compose.yml")


def _load(name, path, *extra_paths):
    """Import a service module by explicit file path (unique module name) so a
    whole-repo pytest run's same-basename `app.py` files can't shadow each other."""
    import sys
    for p in (os.path.dirname(path), os.path.join(_ROOT, "shared"), *extra_paths):
        if p not in sys.path:
            sys.path.insert(0, p)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


orch = _load("orch_app", os.path.join(_HERE, "app.py"))
agent = _load("cap_agent", os.path.join(_ROOT, "services", "capture-agent", "agent.py"))

FLOW = dict(fid="f-1", value="203.0.113.9", profile="ip")


def _agent_dir():
    # the fallback-key inputs an ARM directive always carries alongside tenant_id
    return {"finding_id": FLOW["fid"], "capture_profile": FLOW["profile"]}


def _agent_key(tenant):
    # exercise the fallback path (no advertised pcap_ref) so the agent derives the key
    return agent.pcap_key({"tenant_id": tenant, **_agent_dir()})


# --- the collision (both the orchestrator and the agent derive the key) ----------
def test_orchestrator_distinct_tenants_never_collide():
    a = orch.object_key("acme", **FLOW)
    b = orch.object_key("globex", **FLOW)
    assert a != b, f"cross-tenant collision: both tenants -> {a}"


def test_agent_distinct_tenants_never_collide():
    assert _agent_key("acme") != _agent_key("globex")


def test_same_tenant_same_flow_is_stable():
    assert orch.object_key("acme", **FLOW) == orch.object_key("acme", **FLOW)
    assert _agent_key("acme") == _agent_key("acme")


# --- absent tenant: documented default, never str(None) --------------------------
def test_orchestrator_absent_tenant_uses_default_not_none():
    for absent in (None, "", "   "):
        k = orch.object_key(absent, **FLOW)
        assert orch.DEFAULT_TENANT_SEGMENT in k.split("/"), k
        assert "None" not in k.split("/"), k


def test_agent_absent_tenant_uses_default_not_none():
    for absent in (None, "", "   "):
        k = _agent_key(absent)
        assert agent.DEFAULT_TENANT_SEGMENT in k.split("/"), k
        assert "None" not in k.split("/"), k


# --- orchestrator and agent must agree on the key --------------------------------
def test_orchestrator_and_agent_agree():
    # what the orchestrator advertises is what the agent stores under. The real
    # ARM directive carries pcap_ref AND tenant_id together (app._handle_request),
    # and the agent honors the advertised ref because it belongs to that tenant's
    # namespace — so the loop stays consistent.
    ref = orch.object_key("acme", **FLOW)
    assert agent.pcap_key({"pcap_ref": ref, "tenant_id": "acme"}) == ref
    # and the agent's own fallback lands in the same tenant namespace
    assert orch.tenant_segment("acme") in _agent_key("acme").split("/")


# --- advertised refs must not escape the directive's tenant namespace -------------
# The agent honors pcap_ref verbatim, then uploads to it (_capture). A legacy
# unnamespaced ref or another tenant's ref must NOT be honored, or one tenant's
# capture overwrites another's object.
def test_agent_rejects_legacy_unnamespaced_ref():
    # pre-fix regression: a legacy ref with no tenant segment was honored for ANY
    # tenant, so two tenants sharing it collided. Now each is redirected into its
    # own namespace.
    legacy = "ndr-pcap/f1-ip.pcap"
    a = agent.pcap_key({"pcap_ref": legacy, "tenant_id": "acme", **_agent_dir()})
    b = agent.pcap_key({"pcap_ref": legacy, "tenant_id": "globex", **_agent_dir()})
    assert a != legacy and b != legacy, (a, b)
    assert a != b, f"legacy ref still collides across tenants: {a}"
    assert agent.tenant_segment("acme") in a.split("/")
    assert agent.tenant_segment("globex") in b.split("/")


def test_agent_rejects_other_tenants_ref():
    # a globex directive advertising acme's namespaced key must land in globex's
    # namespace, never acme's — no cross-tenant overwrite via a forged ref.
    acme_ref = orch.object_key("acme", **FLOW)
    k = agent.pcap_key({"pcap_ref": acme_ref, "tenant_id": "globex", **_agent_dir()})
    assert k != acme_ref, k
    assert agent.tenant_segment("acme") not in k.split("/"), k
    assert agent.tenant_segment("globex") in k.split("/"), k


# --- collision hardness: readable prefix may collide, the FULL digest must not -----
# Regression for the review finding that a 48-bit (hexdigest()[:12]) suffix left a
# feasible ~2^24 birthday collision when two tenant ids shared their sanitized/
# truncated prefix. The distinguishing part must be the full SHA-256 digest.
_PREFIX = "t" * 40  # longer than the 32-char readable-prefix truncation


@pytest.mark.parametrize("a,b", [
    ("acme!!!", "acme###"),               # identical AFTER sanitization ("acme")
    (_PREFIX + "-alpha", _PREFIX + "-beta"),  # identical first 32 chars (truncation)
])
def test_distinct_tenants_with_shared_prefix_never_collide(a, b):
    # readable prefixes are allowed to be equal; the segments (and keys) must not be
    assert orch.tenant_segment(a) != orch.tenant_segment(b)
    assert orch.object_key(a, **FLOW) != orch.object_key(b, **FLOW)
    assert _agent_key(a) != _agent_key(b)


def test_tenant_segment_uses_full_sha256_digest():
    # the collision-free part is the entire 64-hex digest, not a truncation
    import hashlib
    for svc in (orch, agent):
        assert svc.tenant_segment("acme").endswith(hashlib.sha256(b"acme").hexdigest())


@pytest.mark.parametrize("tenant", ["acme", "globex", _PREFIX + "-alpha", "acme!!!"])
def test_services_agree_on_tenant_segment(tenant):
    # the two services derive the identical namespace, so the loop stays consistent
    assert orch.tenant_segment(tenant) == agent.tenant_segment(tenant)


def test_namespaced_key_within_agent_safe_key_bound():
    # the full digest lengthens the key; a realistic UUID finding_id must still fit
    # the agent's 256-char _SAFE_KEY so the orchestrator's advertised ref is honored
    ref = orch.object_key("acme", fid="123e4567-e89b-12d3-a456-426614174000",
                          value="203.0.113.9", profile="ip")
    assert agent._valid_key(ref), (len(ref), ref)
    assert agent.pcap_key({"pcap_ref": ref, "tenant_id": "acme"}) == ref


def test_tenant_segment_is_path_safe():
    # a hostile tenant id can't inject a path or leave the ndr-pcap prefix
    for hostile in ("../../etc", "a/b/c", "..", "a b; rm", "acct\n../x"):
        k = orch.object_key(hostile, **FLOW)
        assert k.startswith("ndr-pcap/") and ".." not in k, (hostile, k)


# --- capture stays optional: base sensor compose validates without it -------------
@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not available")
def test_base_sensor_compose_validates_without_capture():
    # no --profile capture: the base sensor stack must still be a valid compose
    r = subprocess.run(["docker", "compose", "-f", _COMPOSE, "config", "--services"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    services = r.stdout.split()
    assert "capture-agent" not in services, "capture-agent must be gated behind the capture profile"


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not available")
def test_capture_agent_present_under_capture_profile():
    r = subprocess.run(["docker", "compose", "-f", _COMPOSE, "--profile", "capture",
                        "config", "--services"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "capture-agent" in r.stdout.split()


if __name__ == "__main__":
    import sys
    raise SystemExit(pytest.main([__file__, "-q", *sys.argv[1:]]))
