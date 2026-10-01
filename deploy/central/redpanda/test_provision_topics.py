"""Offline deployment contract for suricata input-topic provisioning (LogAppendTime).

Executes the REAL provision-topics.sh shell, faking only the external `rpk` CLI (it logs
argv to a file). Never claims broker connectivity. Run from the repository root:

    PYTHONPATH=shared .venv/bin/python -m pytest -q deploy/central/redpanda/test_provision_topics.py
"""
import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "deploy/central/redpanda/provision-topics.sh"
ENTRYPOINT = ROOT / "deploy/central/redpanda/entrypoint.sh"
TOPICS_MD = ROOT / "contracts/topics.md"

# The standard suricata ingest topics the script must provision as LogAppendTime — ALL of
# them, not just the four the normalizer currently consumes (asset-service reads
# suricata.raw.v1, file-observer reads suricata.file.v1, and every one must be LogAppendTime).
EXPECTED_TOPICS = {
    "suricata.raw.v1", "suricata.flow.v1", "suricata.dns.v1", "suricata.tls.v1",
    "suricata.http.v1", "suricata.ssh.v1", "suricata.windows.v1", "suricata.file.v1",
    "suricata.anomaly.v1", "suricata.stats.v1", "suricata.modbus.v1",
}
TS_CONFIG = "message.timestamp.type=LogAppendTime"


def _fake_rpk(tmp_path):
    """A fake `rpk` that logs each invocation's argv to $CALLS and exits 0 — except it exits
    nonzero on `topic create` when FAIL_CREATE=1 (to exercise the reconcile-via-alter path).
    `redpanda start` / `cluster health` also just log+exit 0 so the entrypoint can be driven
    end to end offline (start backgrounds, health passes first try, wait returns at once)."""
    fake = tmp_path / "rpk"
    fake.write_text(
        "#!" + os.sys.executable + "\nimport json, os, sys\n"
        'with open(os.environ["CALLS"], "a") as f: f.write(json.dumps(sys.argv[1:])+"\\n")\n'
        'sys.exit(1 if os.environ.get("FAIL_CREATE") == "1" '
        'and sys.argv[1:3] == ["topic", "create"] else 0)\n')
    fake.chmod(0o755)
    return fake


def run(tmp_path, **env_overrides):
    """Run the real provision-topics.sh with a fake rpk; return (result, [argv...])."""
    _fake_rpk(tmp_path)
    calls = tmp_path / "calls"
    env = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"], CALLS=str(calls),
               ADMIN="local:9644", KAFKA="local:9092",
               ADMIN_USER="cernity-admin", CERNITY_BUS_ADMIN_PASSWORD="admin secret")
    env.update(env_overrides)
    result = subprocess.run(["sh", str(SCRIPT)], env=env, capture_output=True, text=True)
    parsed = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
    return result, parsed


def run_entrypoint(tmp_path, **env_overrides):
    """Drive the REAL entrypoint.sh end to end with a fake rpk (no broker), proving the
    bootstrap ordering that closes the CreateTime race. The container mounts these scripts at
    /, so materialize a copy with the absolute paths rewritten to the in-repo sources — no
    production behavior changes. Returns (result, [argv...], marker_path)."""
    _fake_rpk(tmp_path)
    prov = tmp_path / "provision-topics.sh"; prov.write_text(SCRIPT.read_text())
    (tmp_path / "provision-capture.sh").write_text("")          # sourced only if capture on (it isn't)
    marker = tmp_path / "ready"
    yaml_out = tmp_path / "redpanda.yaml"
    tmpl = ROOT / "deploy/central/redpanda/redpanda.yaml.tmpl"
    ep = ENTRYPOINT.read_text()
    ep = ep.replace("/etc/redpanda/redpanda.yaml.tmpl", str(tmpl))   # longer path first
    ep = ep.replace("/etc/redpanda/redpanda.yaml", str(yaml_out))
    ep = ep.replace("/provision-topics.sh", str(prov))
    ep = ep.replace("/provision-capture.sh", str(tmp_path / "provision-capture.sh"))
    ep = ep.replace("/tmp/cernity-bus-ready", str(marker))
    ep_path = tmp_path / "entrypoint.sh"; ep_path.write_text(ep)
    calls = tmp_path / "calls"
    env = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"], CALLS=str(calls),
               CERNITY_BUS_USER="cernity-sensor", CERNITY_BUS_PASSWORD="sensor secret",
               CERNITY_BUS_CENTRAL_PASSWORD="central secret",
               CERNITY_BUS_ADMIN_PASSWORD="admin secret")
    env.update(env_overrides)
    result = subprocess.run(["sh", str(ep_path)], env=env, capture_output=True, text=True, timeout=30)
    parsed = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
    return result, parsed, marker


def _idx(calls, pred):
    return next(i for i, c in enumerate(calls) if pred(c))


def _last_idx(calls, pred):
    return max(i for i, c in enumerate(calls) if pred(c))


_is_create = lambda c: c[:2] == ["topic", "create"]
_ac_off = lambda c: c[:5] == ["cluster", "config", "set", "auto_create_topics_enabled", "false"]
_ac_on = lambda c: c[:5] == ["cluster", "config", "set", "auto_create_topics_enabled", "true"]
_default = lambda c: c[:4] == ["cluster", "config", "set", "log_message_timestamp_type=LogAppendTime"]
_start = lambda c: c[:2] == ["redpanda", "start"]
_cfg_set = lambda c: c[:3] == ["cluster", "config", "set"]


def _start_sets(argv, kv):
    """True if a `redpanda start` argv carries `--set <kv>` (cluster config seeded at boot)."""
    return any(argv[i] == "--set" and i + 1 < len(argv) and argv[i + 1] == kv
               for i in range(len(argv)))


def creates(calls):
    return {c[2]: c for c in calls if c[:2] == ["topic", "create"]}


def alters(calls):
    return {c[2]: c for c in calls if c[:2] == ["topic", "alter-config"]}


def test_expected_topics_match_contract():
    """EXPECTED_TOPICS stays in sync with the Ingest family in contracts/topics.md."""
    ingest = TOPICS_MD.read_text().split("## Ingest", 1)[1].split("\n## ", 1)[0]
    assert set(re.findall(r"suricata\.\w+\.v1", ingest)) == EXPECTED_TOPICS


def test_fresh_secure_creates_all_topics_with_logappendtime(tmp_path):
    result, calls = run(tmp_path)
    assert result.returncode == 0, result.stderr

    # Cluster default is set, and BEFORE the first topic create (so auto-created topics inherit it).
    default = ["cluster", "config", "set", "log_message_timestamp_type=LogAppendTime"]
    default_idx = next(i for i, c in enumerate(calls) if c[:4] == default)
    first_create = next(i for i, c in enumerate(calls) if c[:2] == ["topic", "create"])
    assert default_idx < first_create

    created = creates(calls)
    assert set(created) == EXPECTED_TOPICS          # ALL standard input topics, not just 4
    for topic, argv in created.items():
        # create-with-config carries message.timestamp.type=LogAppendTime atomically (-c).
        assert argv[argv.index("-c") + 1] == TS_CONFIG, topic
        # secure posture authenticates as the admin superuser over the internal SASL listener.
        assert "user=cernity-admin" in argv and "sasl.mechanism=SCRAM-SHA-512" in argv
    assert not alters(calls)                        # fresh deploy: nothing to reconcile


def test_insecure_posture_is_plaintext_no_sasl(tmp_path):
    result, calls = run(tmp_path, CERNITY_INSECURE_BUS="1")
    assert result.returncode == 0, result.stderr

    created = creates(calls)
    assert set(created) == EXPECTED_TOPICS
    for topic, argv in created.items():
        assert argv[argv.index("-c") + 1] == TS_CONFIG, topic
        # demo posture: NO SASL — the insecure listener has no seeded principals.
        assert not any(a.startswith("user=") or a.startswith("sasl.") for a in argv), topic
    # Cluster default still applied via the admin API.
    assert any(c[:4] == ["cluster", "config", "set", "log_message_timestamp_type=LogAppendTime"]
               for c in calls)


def test_existing_topics_are_reconciled_via_alter(tmp_path):
    # Every `topic create` fails (topic already exists from a pre-flip CreateTime deploy).
    result, calls = run(tmp_path, FAIL_CREATE="1")
    assert result.returncode == 0, result.stderr

    altered = alters(calls)
    assert set(altered) == EXPECTED_TOPICS
    for topic, argv in altered.items():
        assert argv[argv.index("--set") + 1] == TS_CONFIG, topic


def test_script_uses_admin_not_sensor_credential():
    text = SCRIPT.read_text()
    # Topics are admin-provisioned; the sensor keeps produce-only least privilege.
    assert "CERNITY_BUS_ADMIN_PASSWORD" in text
    assert "CERNITY_BUS_USER" not in text and "CERNITY_BUS_PASSWORD" not in text


def test_migration_for_committed_offset_backlog_documented():
    text = SCRIPT.read_text()
    # The false "latest reads only post-reconcile records" claim is gone; the real
    # committed-offset caveat and the explicit stop -> Empty -> seek -> start steps are present.
    assert "committed offset" in text.lower()
    assert "rpk group seek ndr-normalizer --to end" in text
    assert "suricata.flow.v1,suricata.tls.v1,suricata.dns.v1,suricata.http.v1" in text
    assert "docker compose stop normalizer" in text


def test_entrypoint_provisions_in_both_postures():
    text = ENTRYPOINT.read_text()
    # The v1 defect: the insecure branch `exec`-ed and returned before provisioning.
    assert "exec rpk redpanda start" not in text
    # Provisioning is sourced in BOTH branches (insecure demo + secure default).
    assert text.count(". /provision-topics.sh") == 2
    insecure_branch = text.split("# secure mode.", 1)[0]
    assert ". /provision-topics.sh" in insecure_branch          # insecure branch provisions
    assert 'wait "$RP"' in insecure_branch                      # background start, not exec


def test_healthcheck_gates_on_provisioning_marker():
    """Dependent compose services must gate on topic provisioning, not just broker liveness:
    the redpanda healthcheck requires the readiness marker the entrypoint writes post-provision."""
    compose = (ROOT / "deploy/central/docker-compose.yml").read_text()
    assert "test -f /tmp/cernity-bus-ready" in compose
    assert ": > \"$READY_MARKER\"" in ENTRYPOINT.read_text()   # marker written by the entrypoint


def test_bootstrap_is_createtime_race_free_secure(tmp_path):
    """End to end: a producer reaching the broker mid-bootstrap can never birth a CreateTime
    topic. Auto-create is forced OFF before any topic exists and re-enabled only AFTER the
    LogAppendTime default is set and every input topic is created; the sensor credential (the
    only produce-capable external principal) is seeded only after the topics already exist."""
    result, calls, marker = run_entrypoint(tmp_path)
    assert result.returncode == 0, result.stderr
    assert marker.exists()                                     # readiness written after provisioning

    first_create = _idx(calls, _is_create)
    assert _idx(calls, _ac_off) < first_create                # no topic can be born until provisioned
    assert first_create < _idx(calls, _ac_on)                 # auto-create re-enabled only after
    assert _idx(calls, _default) < _idx(calls, _ac_on)        # LogAppendTime default effective first
    admin = lambda c: c[:3] == ["security", "user", "create"] and "cernity-admin" in c
    sensor = lambda c: c[:3] == ["security", "user", "create"] and "cernity-sensor" in c
    assert _idx(calls, admin) < first_create                  # admin seeded before topic creation
    assert _last_idx(calls, _is_create) < _idx(calls, sensor)  # sensor usable only after topics exist


def test_bootstrap_is_createtime_race_free_insecure(tmp_path):
    """Same guarantee in the plaintext demo posture: no principals are seeded, and auto-create
    stays OFF until the LogAppendTime default + all input topics are in place."""
    result, calls, marker = run_entrypoint(tmp_path, CERNITY_INSECURE_BUS="1")
    assert result.returncode == 0, result.stderr
    assert marker.exists()

    first_create = _idx(calls, _is_create)
    assert _idx(calls, _ac_off) < first_create < _idx(calls, _ac_on)
    assert _idx(calls, _default) < _idx(calls, _ac_on)
    assert not any(c[:3] == ["security", "user", "create"] for c in calls)   # demo seeds no principals


def test_boot_seeds_safe_config_before_any_admin_call_insecure(tmp_path):
    """A producer reaching the plaintext :19092 the instant it opens — BEFORE the entrypoint's
    first admin-API config call — must still be unable to birth a CreateTime topic. Prove the
    safe cluster config is seeded on the `rpk redpanda start` line itself (effective before the
    Kafka API accepts traffic), not only via a later `cluster config set`. This closes the
    window the reviewer flagged: the dev start path bundles auto-create ON, so the post-start
    toggle alone left CreateTime auto-creation possible until the first admin call."""
    result, calls, _ = run_entrypoint(tmp_path, CERNITY_INSECURE_BUS="1")
    assert result.returncode == 0, result.stderr

    start = next(c for c in calls if _start(c))
    # Boot-time --set: auto-create off AND LogAppendTime default (either alone closes the race;
    # the timestamp default is the belt-and-suspenders that survives auto-create being on).
    assert _start_sets(start, "redpanda.auto_create_topics_enabled=false"), start
    assert _start_sets(start, "redpanda.log_message_timestamp_type=LogAppendTime"), start
    # The broker starts (with safe config) strictly before ANY admin-API config call.
    assert _idx(calls, _start) < _idx(calls, _cfg_set)


def test_boot_seeds_safe_config_before_any_admin_call_secure(tmp_path):
    """Secure posture is auth-closed during bootstrap, but seeds the identical boot-time safe
    config (defense in depth) — and, like the demo path, before any admin-API config call."""
    result, calls, _ = run_entrypoint(tmp_path)
    assert result.returncode == 0, result.stderr

    start = next(c for c in calls if _start(c))
    assert _start_sets(start, "redpanda.auto_create_topics_enabled=false"), start
    assert _start_sets(start, "redpanda.log_message_timestamp_type=LogAppendTime"), start
    assert _idx(calls, _start) < _idx(calls, _cfg_set)
