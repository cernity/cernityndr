"""East-west detectors service (plan U8 Tier 2). Consumes suricata.flow.v1 (for
lateral fan-out / RDP) and suricata.raw.v1 (krb5 / dcerpc events land there), and
emits ndr.finding.candidate.v1. Scoring covered by test_ew.py.

BLUEPRINT: quiet in this homelab (no east-west Windows/AD/SMB traffic); fires the
moment such traffic reaches the sensor.

State (lateral targets / RDP dsts / kerberoast requests per source) is
externalized to a WindowStore (Redis in production, in-memory for tests), so it
survives crash and rebalance and N replicas never double-emit (shared-Redis dedup
keyed with a STABLE cross-process hash; Python's hash() is per-process seeded).
Keys are partition-tagged and enumerated via a per-partition index (plan 005; HA
parity with behavioral-detectors). lat/rdp come from flow.v1, krb from raw.v1, so
each is scoped by that topic's partition assignment.
"""
import hashlib
import json
import logging
import os
import signal
import time

import ndr_runtime
import store as store_mod
import ew

log = ndr_runtime.setup_logging("east-west-detectors")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
TENANT = os.environ.get("NDR_TENANT", "default")
WINDOW = float(os.environ.get("EW_WINDOW_SECS", "600"))
EVAL_EVERY = float(os.environ.get("EVAL_SECS", "30"))
GROUP_ID = os.environ.get("NDR_GROUP_ID", "ndr-east-west")
STATE_BACKEND = os.environ.get("NDR_STATE_BACKEND", "memory")
REDIS_URL = os.environ.get("NDR_REDIS_URL", "redis://ndr-redis:6379/0")
ENUM_INDEX = os.environ.get("NDR_ENUM_INDEX", "1") not in ("0", "false", "False", "")
CAND = "ndr.finding.candidate.v1"

_store = store_mod.make_store(STATE_BACKEND, REDIS_URL)
_running = True


def _stop(*_):
    global _running
    _running = False


def _stable(s):
    return int(hashlib.sha1(s.encode()).hexdigest()[:15], 16)


def _index_key(prefix, part):
    return f"idx:{prefix}{part}"


def _part_of(key):
    return key.split(":", 2)[1]


def _scoped_keys(prefix, parts):
    if parts is None:
        return _store.keys_matching(prefix)
    if ENUM_INDEX:
        out = []
        for p in parts:
            out += _store.set_members(_index_key(prefix, p))
        return out
    return [k for k in _store.keys_matching(prefix)
            if (seg := k.split(":", 2)[1]).isdigit() and int(seg) in parts]


def _prune_index(key):
    if ENUM_INDEX:
        _store.set_remove(_index_key(key.split(":", 1)[0] + ":", _part_of(key)), key)


def _ew_add(prefix, part, src, member):
    key = f"{prefix}{part}:{TENANT}:{src}"
    _store.set_add(key, member, WINDOW)
    if ENUM_INDEX:
        _store.set_add(_index_key(prefix, part), key, WINDOW)   # partition index


def _cand(detector, category, sev, conf, entities, mitre=None):
    bucket = int(time.time() // 600)
    if not _store.dedup_seen(f"emit:{TENANT}:{detector}:{_stable(entities) % 10**12}:{bucket}", 600):
        return None
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    c = {"finding_id": f"{detector}-{_stable(entities) % 10**10}-{bucket}",
            "tenant_id": TENANT, "detector_id": detector, "detector_version": "1.0",
            "category": category, "severity": sev, "confidence": conf,
            "first_seen": now, "last_seen": now, "entities": entities, "state": "CANDIDATE"}
    if mitre:
        c["mitre"] = mitre                          # precise technique(s); finding-service prefers this
    return c


def _src_of(key):
    return key.split(":", 3)[3]                                  # prefix:part:tenant:src (IPv6-safe)


def _asrep_preauthless(k):
    """AS-REQ with Kerberos pre-auth absent (AS-REP roastable). Suricata eve does
    not currently expose a pre-auth flag, so this only fires when an explicit
    field says pre-auth was absent — dormant by default, honest about the gap."""
    mt = str(k.get("msg_type") or k.get("message_type") or "").upper()
    is_as_req = "AS_REQ" in mt or mt in ("AS-REQ", "10")
    preauth = k.get("preauth", k.get("pa_data", "unknown"))
    return is_as_req and preauth in (False, None, [], "")


def evaluate(producer, flow_parts=None, raw_parts=None):
    # lateral fan-out (flow.v1)
    for key in _scoped_keys("lat:", flow_parts):
        members = _store.set_members(key)
        if not members:
            _prune_index(key); continue
        targets = {tuple(m.rsplit("|", 1)) for m in members}    # (dst, port)
        hit, n = ew.lateral_fanout(targets)
        if hit:
            ent = json.dumps([{"type": "ip", "role": "src", "value": _src_of(key)},
                              {"type": "count", "internal_targets": n}])
            c = _cand("lateral_movement", "lateral", 7, 0.7, ent)
            if c:
                producer.send(CAND, c); log.info("LATERAL %s -> %d internal hosts", _src_of(key), n)
    # internal scan (flow.v1): one src -> many hosts (horizontal) or many ports (vertical)
    for key in _scoped_keys("scan:", flow_parts):
        members = _store.set_members(key)
        if not members:
            _prune_index(key); continue
        pairs = {tuple(m.rsplit("|", 1)) for m in members}
        hit, kind, n = ew.scan_score(pairs)
        if hit:
            ent = json.dumps([{"type": "ip", "role": "src", "value": _src_of(key)},
                              {"type": "scan", "kind": kind, "count": n}])
            c = _cand("internal_scan", "discovery", 6, 0.6, ent, mitre=["T1046"])
            if c:
                producer.send(CAND, c); log.info("INTERNAL_SCAN %s %s=%d", _src_of(key), kind, n)
    # RDP fan-out (flow.v1)
    for key in _scoped_keys("rdp:", flow_parts):
        dsts = set(_store.set_members(key))
        if not dsts:
            _prune_index(key); continue
        hit, n = ew.rdp_fanout(dsts)
        if hit:
            ent = json.dumps([{"type": "ip", "role": "src", "value": _src_of(key)},
                              {"type": "count", "rdp_targets": n}])
            c = _cand("rdp_fanout", "lateral", 6, 0.6, ent)
            if c:
                producer.send(CAND, c); log.info("RDP_FANOUT %s -> %d hosts", _src_of(key), n)
    # kerberoasting (raw.v1 / krb5)
    for key in _scoped_keys("krb:", raw_parts):
        members = _store.set_members(key)
        if not members:
            _prune_index(key); continue
        reqs = [json.loads(m) for m in members]
        hit, spns, rc4 = ew.kerberoast_score(reqs)
        if hit:
            ent = json.dumps([{"type": "ip", "role": "src", "value": _src_of(key)},
                              {"type": "kerberoast", "distinct_spns": spns, "rc4": rc4}])
            c = _cand("kerberoasting", "credential_access", 8, 0.8, ent)
            if c:
                producer.send(CAND, c); log.info("KERBEROAST %s spns=%d rc4=%s", _src_of(key), spns, rc4)
    # password spraying (raw.v1): one src failing auth across many distinct accounts
    for key in _scoped_keys("spray:", raw_parts):
        accts = set(_store.set_members(key))
        if not accts:
            _prune_index(key); continue
        hit, n = ew.spray_score(accts)
        if hit:
            ent = json.dumps([{"type": "ip", "role": "src", "value": _src_of(key)},
                              {"type": "spray", "distinct_accounts": n}])
            c = _cand("password_spraying", "credential_access", 7, 0.7, ent, mitre=["T1110.003"])
            if c:
                producer.send(CAND, c); log.info("PASSWORD_SPRAY %s accounts=%d", _src_of(key), n)
    # AS-REP roasting (raw.v1): AS-REQs for pre-auth-disabled accounts
    for key in _scoped_keys("asrep:", raw_parts):
        accts = set(_store.set_members(key))
        if not accts:
            _prune_index(key); continue
        hit, n = ew.asrep_roast_score(accts)
        if hit:
            ent = json.dumps([{"type": "ip", "role": "src", "value": _src_of(key)},
                              {"type": "asrep", "preauthless_accounts": n}])
            c = _cand("as_rep_roasting", "credential_access", 7, 0.75, ent, mitre=["T1558.004"])
            if c:
                producer.send(CAND, c); log.info("ASREP_ROAST %s accounts=%d", _src_of(key), n)
    # ransomware over SMB (raw.v1): write-heavy file flood across many distinct files
    for key in _scoped_keys("rw:", raw_parts):
        members = _store.set_members(key)
        if not members:
            _prune_index(key); continue
        files = {m.split("|", 1)[1] for m in members if "|" in m}
        writes = sum(1 for m in members if m.startswith("w|"))
        reads = sum(1 for m in members if m.startswith("r|"))
        hit, _w = ew.ransomware_smb_score(len(files), writes, reads)
        if hit:
            ent = json.dumps([{"type": "ip", "role": "src", "value": _src_of(key)},
                              {"type": "ransomware", "distinct_files": len(files), "writes": writes}])
            c = _cand("ransomware_smb", "impact", 9, 0.8, ent, mitre=["T1486"])
            if c:
                producer.send(CAND, c); log.info("RANSOMWARE_SMB %s files=%d writes=%d", _src_of(key), len(files), writes)
    # lateral exec (raw.v1): known exec named-pipe / RPC signals per source
    for key in _scoped_keys("lex:", raw_parts):
        sigs = set(_store.set_members(key))
        if not sigs:
            _prune_index(key); continue
        ent = json.dumps([{"type": "ip", "role": "src", "value": _src_of(key)},
                          {"type": "lateral_exec", "signals": sorted(sigs)}])
        c = _cand("lateral_exec", "lateral", 7, 0.75, ent, mitre=["T1021.002"])
        if c:
            producer.send(CAND, c); log.info("LATERAL_EXEC %s signals=%d", _src_of(key), len(sigs))


def _handle(e, producer, part):
    et = e.get("event_type")
    if et == "flow":
        src, dst, port = e.get("src_ip"), e.get("dest_ip"), e.get("dest_port")
        if src and dst and ew.is_internal(src) and ew.is_internal(dst):
            _ew_add("scan:", part, src, f"{dst}|{port}")        # internal scan fan-out
            if port in ew.ADMIN_PORTS:
                _ew_add("lat:", part, src, f"{dst}|{port}")
            if port == 3389:
                _ew_add("rdp:", part, src, dst)
    elif et == "krb5":
        k = e.get("krb5", {}) or {}
        src = e.get("src_ip")
        if k.get("msg_type") in ("KRB_TGS_REQ", "TGS-REQ") or "sname" in k:
            _ew_add("krb:", part, src,
                    json.dumps({"sname": k.get("sname"),
                                "encryption": k.get("encryption") or k.get("weak_encryption")}))
        # password spraying: AS-REQ pre-auth failures accrue distinct failed accounts.
        err = str(k.get("error_code", "")).upper()
        if ("PREAUTH_FAILED" in err or err in ("24", "0x18")) and k.get("cname"):
            _ew_add("spray:", part, src, k.get("cname"))
        # AS-REP roasting: AS-REQ with pre-auth absent. Suricata eve does not
        # currently expose a pre-auth flag, so this stays dormant until it does
        # (see docs/suricata-config.md); it fires the moment the field appears.
        if _asrep_preauthless(k) and k.get("cname"):
            _ew_add("asrep:", part, src, k.get("cname"))
    elif et == "smb":
        s = e.get("smb", {}) or {}
        src = e.get("src_ip")
        cmd = str(s.get("command", "")).upper()
        status = str(s.get("status", "")).upper()
        # password spraying via SMB session-setup logon failures
        if "SESSION_SETUP" in cmd and ("LOGON_FAILURE" in status or "ACCESS_DENIED" in status):
            acct = (s.get("ntlmssp") or {}).get("user") or s.get("user")
            if acct:
                _ew_add("spray:", part, src, acct)
        # ransomware: write/rename vs read ops across distinct files (T1486)
        fname = s.get("filename")
        if fname:
            if any(x in cmd for x in ("WRITE", "SET_INFO", "RENAME")):
                _ew_add("rw:", part, src, f"w|{fname}")
            elif "READ" in cmd:
                _ew_add("rw:", part, src, f"r|{fname}")
        # lateral exec via known SMB named pipe (PsExec/schtasks/registry). WinRM
        # fan-out (5985/6) is already covered by lateral_fanout via ADMIN_PORTS.
        pipe = s.get("named_pipe") or (fname if fname and "pipe" in str(fname).lower() else None)
        if pipe:
            hit, matched = ew.lateral_exec_score([pipe], [], [])
            if hit:
                _ew_add("lex:", part, src, matched[0])
    elif et == "dcerpc":
        d = e.get("dcerpc", {}) or {}
        hit, desc = ew.dcerpc_lateral(d.get("interface_uuid") or d.get("interface"))
        if hit:
            ent = json.dumps([{"type": "ip", "role": "src", "value": e.get("src_ip")},
                              {"type": "ip", "role": "dst", "value": e.get("dest_ip")},
                              {"type": "dcerpc", "op": desc}])
            c = _cand("dcerpc_lateral", "lateral", 7, 0.75, ent)
            if c:
                producer.send(CAND, c); log.info("DCERPC_LATERAL %s->%s %s", e.get("src_ip"), e.get("dest_ip"), desc)


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    producer = ndr_runtime.make_producer()
    consumer = ndr_runtime.make_consumer("suricata.flow.v1", "suricata.raw.v1", group_id=GROUP_ID, auto_offset_reset="latest")
    m = ndr_runtime.metrics
    m.start(int(os.environ.get("NDR_METRICS_PORT", "9108")))
    m.set_ready("store", False)
    m.set_ready("consumer")
    log.info("east-west-detectors up (state=%s, lateral/rdp/kerberoast/dcerpc)", STATE_BACKEND)
    last = time.time()
    while _running:
        if not m.is_ready():
            try:
                _store.dedup_seen("readyprobe", 1); m.set_ready("store")
            except Exception:
                pass
        for _tp, records in consumer.poll(timeout_ms=1000, max_records=1000).items():
            for rec in records:
                try:
                    _handle(rec.value, producer, _tp.partition)
                except Exception as ex:
                    m.dropped("handler"); log.debug("skip record: %s", ex)
        if time.time() - last >= EVAL_EVERY:
            try:
                fp = ndr_runtime.assigned_partitions(consumer, "suricata.flow.v1")
                rp = ndr_runtime.assigned_partitions(consumer, "suricata.raw.v1")
                evaluate(producer, fp, rp); producer.flush()
            except Exception as ex:
                m.dropped("evaluate"); log.warning("evaluate failed: %s", ex)
            last = time.time()
    consumer.close()
    producer.close()


if __name__ == "__main__":
    main()
