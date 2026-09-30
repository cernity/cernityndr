"""U2 unit tests for the carved-file artifact store. Mock object store + fetch, NOT a
live e2e proof. Runs under `PYTHONPATH=shared` (object_keys) like the gate."""
import hashlib
import importlib.util
import io
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import object_keys
import store


def _load_app():
    """Path-load app.py for the process_one loop tests. NOT `import app`: several services
    ship an app.py, so a plain import (and a test_app.py here) would collide under the
    shared `pytest services/...` gate."""
    spec = importlib.util.spec_from_file_location(
        "file_artifact_app", Path(__file__).with_name("app.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


app = _load_app()


class _Producer:
    """Fake Kafka producer: records sends and ACKs immediately (send().get())."""

    def __init__(self, *, fail=False):
        self.sent = []
        self._fail = fail

    def send(self, topic, value):
        self.sent.append((topic, value))
        producer = self

        class _Future:
            def get(self, timeout=None):
                if producer._fail:
                    raise TimeoutError("publish not acked")
                return None
        return _Future()


class Store:
    """Minimal MinIO stand-in: bucket/key -> put kwargs. Stamps a realistic LastModified
    on write (MinIO does) so retrieval's retention check has an object age to bound; the
    stamp is overridable per key to exercise the expiry path."""

    def __init__(self):
        self.objects = {}
        self.reads = 0

    def head_object(self, Bucket, Key):
        if Bucket + "/" + Key not in self.objects:
            raise KeyError("no such object")
        return {}

    def put_object(self, **kw):
        kw.setdefault("LastModified", datetime.now(timezone.utc))
        self.objects[kw["Bucket"] + "/" + kw["Key"]] = kw

    def get_object(self, Bucket, Key):
        self.reads += 1
        obj = self.objects[Bucket + "/" + Key]
        return {"Body": io.BytesIO(obj["Body"]), "ContentLength": len(obj["Body"]),
                "LastModified": obj["LastModified"], "Metadata": obj["Metadata"]}


def _src(tenant, sha):
    """The tenant-scoped source key capture-agent now produces (U2 re-key)."""
    return object_keys.file_key(tenant, sha, store.FILES_BUCKET)


def _event(tenant, data, **extra):
    sha = hashlib.sha256(data).hexdigest()
    return {"sensor_id": "s1", "sha256": sha, "size": len(data), "mime": "application/octet-stream",
            "tenant_id": tenant, "state": "bytes_available",
            "object_ref": _src(tenant, sha), **extra}


def _fetch(mapping):
    return lambda ref: mapping[ref]


def _zip(entries, compression=zipfile.ZIP_STORED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, body in entries:
            zf.writestr(name, body)
    return buf.getvalue()


def _prefixed(zip_bytes, prefix=b"MZ" + b"\x00" * 64):
    """A ZIP with bytes prepended (an SFX/`MZ` stub). Its local-file magic is no longer at
    offset 0, but zipfile still reads it via the trailing central directory — the case the
    first-four-bytes is_zip check let skip validation."""
    return prefix + zip_bytes


def _patch_headers(zip_bytes, sig, off, fn):
    """Apply fn(buf, pos) at `off` of every `sig` header in the zip bytes (stdlib zipfile
    cannot WRITE encrypted / bogus-method members, so we set those header fields directly)."""
    b = bytearray(zip_bytes)
    i = 0
    while (i := b.find(sig, i)) >= 0:
        fn(b, i + off)
        i += 4
    return bytes(b)


def _mark_encrypted(zip_bytes):
    """Set general-purpose bit 0 (encryption) in every local + central header — the flag
    that drives both zipfile's read-time RuntimeError and our flag-check rejection."""
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        zip_bytes = _patch_headers(zip_bytes, sig, off, lambda b, p: b.__setitem__(p, b[p] | 0x1))
    return zip_bytes


def _set_compression(zip_bytes, method):
    """Overwrite the compression-method field in every local + central header."""
    for sig, off in ((b"PK\x03\x04", 8), (b"PK\x01\x02", 10)):
        zip_bytes = _patch_headers(
            zip_bytes, sig, off, lambda b, p: b.__setitem__(slice(p, p + 2), method.to_bytes(2, "little")))
    return zip_bytes


# 1. id = SHA-256(bytes); storing same bytes twice is idempotent (one object).
def test_store_id_is_sha256_and_idempotent():
    data = b"carved-payload"
    ev = _event("acme", data)
    s3, audit = Store(), []
    rec = store.store(ev, _fetch({ev["object_ref"]: data}), s3, audit.append)
    assert rec["artifact_id"] == hashlib.sha256(data).hexdigest()
    # Stored under the ACCEPTED namespace (`.../<tseg>/artifacts/<sha>`), not the raw
    # staging key — only accepted keys are servable by retrieval.
    assert rec["object_ref"] == object_keys.accepted_key(
        object_keys.tenant_segment("acme"), rec["artifact_id"], store.FILES_BUCKET)
    assert "/artifacts/" in rec["object_ref"]
    assert len(s3.objects) == 1
    assert audit[-1]["outcome"] == "stored"
    # second store of identical bytes: no new object, and it is not re-put (idempotent)
    rec2 = store.store(ev, _fetch({ev["object_ref"]: data}), s3, audit.append)
    assert rec2 == rec and len(s3.objects) == 1
    assert audit[-1]["outcome"] == "idempotent"


# 2. Two tenants with identical bytes get DISTINCT tenant-scoped keys (U1a regression).
def test_two_tenants_identical_bytes_distinct_keys():
    data = b"identical-bytes-across-tenants"
    ea, eb = _event("acme", data), _event("globex", data)
    s3 = Store()
    ra = store.store(ea, _fetch({ea["object_ref"]: data}), s3, lambda _: None)
    rb = store.store(eb, _fetch({eb["object_ref"]: data}), s3, lambda _: None)
    assert ra["artifact_id"] == rb["artifact_id"]          # same content -> same id
    assert ra["object_ref"] != rb["object_ref"]            # but distinct tenant keys
    assert len(s3.objects) == 2
    assert "None" not in ra["object_ref"].split("/")


def test_non_tenant_scoped_source_rejected():
    # a legacy ndr-files/<sha> (no tenant segment) is refused: no object, audited.
    data = b"legacy"
    sha = hashlib.sha256(data).hexdigest()
    ev = {"object_ref": f"{store.FILES_BUCKET}/{sha}", "state": "bytes_available", "sha256": sha}
    s3, audit = Store(), []
    with pytest.raises(ValueError, match="tenant-scoped"):
        store.store(ev, _fetch({ev["object_ref"]: data}), s3, audit.append)
    assert not s3.objects and audit[-1]["outcome"] == "rejected"


# 3. tenant-A caller retrieving a tenant-B key is DENIED and audited.
def test_cross_tenant_retrieval_denied_and_audited():
    data = b"tenant-b-secret"
    eb = _event("globex", data)
    s3, audit = Store(), []
    rec = store.store(eb, _fetch({eb["object_ref"]: data}), s3, lambda _: None)
    tokens = {"a": {"actor": "analyst-a", "tenant_id": "acme", "file_read": True, "reason": "case-1"}}
    with pytest.raises(PermissionError):
        store.retrieve(rec["object_ref"], "Bearer a", tokens, s3, audit.append)
    assert audit[-1]["outcome"] == "denied" and audit[-1]["actor"] == "analyst-a"
    assert s3.reads == 0                                    # denied before touching the store


# 4. no-auth denied+audited; authorized returns bytes + audit(who/what/why/result).
def test_unauth_denied_and_authorized_returns_bytes_with_full_audit():
    data = b"tenant-a-file"
    ea = _event("acme", data)
    s3, audit = Store(), []
    rec = store.store(ea, _fetch({ea["object_ref"]: data}), s3, lambda _: None)
    tokens = {"a": {"actor": "analyst-a", "tenant_id": "acme", "file_read": True, "reason": "IR-42"},
              "meta": {"actor": "reader", "tenant_id": "acme", "file_read": False}}
    for bad in ("", "Bearer nope", "Bearer meta"):
        with pytest.raises(PermissionError):
            store.retrieve(rec["object_ref"], bad, tokens, s3, audit.append)
        assert audit[-1]["outcome"] == "denied"
    assert s3.reads == 0
    body = store.retrieve(rec["object_ref"], "Bearer a", tokens, s3, audit.append)
    assert body == data
    line = audit[-1]
    # who / what / why / result all present on the success line
    assert line["actor"] == "analyst-a"                    # who
    assert line["action"] == "file.artifact.download" and line["resource_id"] == rec["object_ref"]  # what
    assert line["why"] == "IR-42"                           # why
    assert line["outcome"] == "success"                    # result


def test_retrieval_detects_object_corruption():
    data = b"trustworthy-bytes"
    ea = _event("acme", data)
    s3, audit = Store(), []
    rec = store.store(ea, _fetch({ea["object_ref"]: data}), s3, lambda _: None)
    s3.objects[rec["object_ref"]]["Body"] += b"tampered"
    tokens = {"a": {"actor": "a", "tenant_id": "acme", "file_read": True}}
    with pytest.raises(ValueError, match="digest"):
        store.retrieve(rec["object_ref"], "Bearer a", tokens, s3, audit.append)
    assert audit[-1]["outcome"] == "failed"


# 5a. Artifact over max_file_size rejected BEFORE storage.
def test_oversize_rejected_before_storage():
    data = b"x" * 2048
    ev = _event("acme", data)
    s3, audit = Store(), []
    with pytest.raises(ValueError, match="max_file_size"):
        store.store(ev, _fetch({ev["object_ref"]: data}), s3, audit.append, max_file_size=1024)
    assert not s3.objects and audit[-1]["outcome"] == "failed"


# 5b. Archive over max_archive_depth rejected BEFORE expansion/storage.
def test_deep_archive_rejected_before_storage():
    inner = _zip([("leaf.txt", b"hi")])
    mid = _zip([("inner.zip", inner)])
    outer = _zip([("mid.zip", mid)])                       # depth 3
    ev = _event("acme", outer)
    s3 = Store()
    with pytest.raises(ValueError, match="max_archive_depth"):
        store.store(ev, _fetch({ev["object_ref"]: outer}), s3, lambda _: None, max_archive_depth=2)
    assert not s3.objects
    # within the limit: stored
    ok = store.store(_event("acme", outer), _fetch({ev["object_ref"]: outer}), s3, lambda _: None,
                     max_archive_depth=3)
    assert ok and len(s3.objects) == 1


# 5c. Archive whose entry path escapes the extraction root (zip-slip) rejected.
def test_zip_slip_rejected_before_storage():
    for evil in ("../evil", "../../etc/passwd", "/abs/evil", "a/../../evil", "..\\win"):
        bomb = _zip([(evil, b"pwn")])
        ev = _event("acme", bomb)
        s3 = Store()
        with pytest.raises(ValueError, match="zip-slip"):
            store.store(ev, _fetch({ev["object_ref"]: bomb}), s3, lambda _: None)
        assert not s3.objects
    # a safe nested-but-in-root path is fine
    safe = _zip([("sub/dir/ok.txt", b"ok")])
    s3 = Store()
    assert store.store(_event("acme", safe), _fetch({_event('acme', safe)['object_ref']: safe}),
                       s3, lambda _: None)
    assert len(s3.objects) == 1


def test_archive_member_over_max_size_rejected():
    # Highly compressible so the OUTER archive stays under max_file_size while the
    # member's UNCOMPRESSED size (a decompression bomb) exceeds it — the member-size
    # guard must reject it from the header, before reading.
    big = _zip([("big.bin", b"y" * 100_000)], compression=zipfile.ZIP_DEFLATED)
    assert len(big) < 5000
    ev = _event("acme", big)
    s3 = Store()
    with pytest.raises(ValueError, match="member exceeds"):
        store.store(ev, _fetch({ev["object_ref"]: big}), s3, lambda _: None, max_file_size=5000)
    assert not s3.objects


# 5d. A ZIP with PREPENDED bytes (SFX/`MZ` stub) must still be validated — the first-four-
# bytes is_zip check let a prefixed archive skip traversal + nesting checks and be promoted.
def test_prefixed_zip_is_validated_not_bypassed():
    # is_zip now recognizes the prefixed archive...
    escaping = _prefixed(_zip([("../escape", b"pwn")]))
    assert store.is_zip(escaping)
    ev = _event("acme", escaping)
    s3 = Store()
    with pytest.raises(store.PolicyError, match="zip-slip"):
        store.store(ev, _fetch({ev["object_ref"]: escaping}), s3, lambda _: None)
    assert not s3.objects                                  # never promoted
    # ...including a prefixed archive NESTED inside an outer archive (recurse over the member).
    nested = _zip([("inner", _prefixed(_zip([("../escape", b"pwn")])))])
    ev2 = _event("acme", nested)
    s3 = Store()
    with pytest.raises(store.PolicyError, match="zip-slip"):
        store.store(ev2, _fetch({ev2["object_ref"]: nested}), s3, lambda _: None)
    assert not s3.objects
    # a prefixed but SAFE archive still stores (the prefix itself is not a rejection reason).
    safe = _prefixed(_zip([("sub/ok.txt", b"ok")]))
    ev3 = _event("acme", safe)
    s3 = Store()
    assert store.store(ev3, _fetch({ev3["object_ref"]: safe}), s3, lambda _: None)
    assert len(s3.objects) == 1


# 5e. Encrypted / unsupported archive members are PERMANENT policy failures, not a
# crash-loop: the consumer must reject them and keep making progress on later records.
def test_encrypted_and_unsupported_members_are_permanent_and_progress():
    for bad in (_mark_encrypted(_zip([("secret.txt", b"classified")])),
                _set_compression(_zip([("odd.bin", b"data")]), 42)):
        ev = _event("acme", bad)
        # store() raises PolicyError (NOT a bare RuntimeError/NotImplementedError)...
        s3 = Store()
        with pytest.raises(store.PolicyError):
            store.store(ev, _fetch({ev["object_ref"]: bad}), s3, lambda _: None)
        assert not s3.objects
        # ...so process_one swallows it and a following valid record still stores: no stall.
        s3, prod = Store(), _Producer()
        assert app.process_one(ev, _fetch({ev["object_ref"]: bad}), s3, prod, lambda _: None) is None
        assert not s3.objects and not prod.sent
        good = b"clean-after-poison"
        eg = _event("acme", good)
        rec = app.process_one(eg, _fetch({eg["object_ref"]: good}), s3, prod, lambda _: None)
        assert rec and len(s3.objects) == 1 and len(prod.sent) == 1


# 6. metadata_only / hashes_only create NO object.
def test_metadata_only_and_hashes_only_create_no_object():
    s3, audit = Store(), []
    for state in ("metadata_only", "hashes_only"):
        ev = _event("acme", b"whatever", state=state)
        rec = store.store(ev, _fetch({ev["object_ref"]: b"whatever"}), s3, audit.append)
        assert rec is None and not s3.objects
        assert audit[-1]["outcome"] == "skipped"
    # also: an event with no object_ref creates nothing
    assert store.store({"state": "bytes_available"}, _fetch({}), s3, audit.append) is None
    assert not s3.objects


def test_zip_slip_and_escape_helper():
    assert store._escapes_root("../x")
    assert store._escapes_root("/abs")
    assert store._escapes_root("a/../../b")
    assert not store._escapes_root("ok.txt")
    assert not store._escapes_root("sub/ok.txt")


# ── permanent violations are PolicyError (skippable), infra faults are not ──────

def test_permanent_violations_raise_policyerror_not_bare_valueerror():
    # Every PERMANENT input violation must be a store.PolicyError so the consumer can
    # commit past it instead of crash-looping. PolicyError subclasses ValueError, so the
    # ValueError-matching scenario tests above still hold.
    def _reject(ev, data, **kw):
        s3 = Store()
        with pytest.raises(store.PolicyError):
            store.store(ev, _fetch({ev["object_ref"]: data}), s3, lambda _: None, **kw)
        assert not s3.objects

    _reject(_event("acme", b"x" * 2048), b"x" * 2048, max_file_size=1024)          # oversize
    deep = _zip([("m.zip", _zip([("i.zip", _zip([("leaf", b"hi")]))]))])
    _reject(_event("acme", deep), deep, max_archive_depth=2)                        # too deep
    slip = _zip([("../evil", b"pwn")])
    _reject(_event("acme", slip), slip)                                            # zip-slip
    bad = b"PK\x03\x04" + b"not a real zip"                                        # malformed archive
    _reject(_event("acme", bad), bad)
    # non-tenant-scoped legacy key
    legacy = {"object_ref": f"{store.FILES_BUCKET}/{'a' * 64}", "state": "bytes_available"}
    with pytest.raises(store.PolicyError):
        store.store(legacy, _fetch({legacy["object_ref"]: b"x"}), Store(), lambda _: None)


def test_transient_fetch_error_is_not_policyerror():
    # An infra fault (fetch/S3) must NOT be swallowed as a permanent rejection — it has to
    # propagate as itself so the consumer leaves the offset uncommitted and replays.
    ev = _event("acme", b"bytes")

    def boom(_ref):
        raise ConnectionError("minio unreachable")

    with pytest.raises(ConnectionError):
        store.store(ev, boom, Store(), lambda _: None)


# ── verify_retention: the lifecycle must actually COVER the artifact objects ────

class _LifecycleStore:
    def __init__(self, rules, *, error=None):
        self._rules, self._error = rules, error

    def get_bucket_lifecycle_configuration(self, Bucket):
        if self._error:
            raise self._error
        return {"Rules": self._rules}


def _rule(days, **flt):
    r = {"Status": "Enabled", "Expiration": {"Days": days}}
    r.update(flt)
    return r


def test_verify_retention_accepts_a_covering_rule():
    # No filter (or an empty prefix) applies to every object -> covers all tenants' artifacts.
    assert store.verify_retention(_LifecycleStore([_rule(7)]), retention_days=7) == 7
    assert store.verify_retention(_LifecycleStore([_rule(3, Filter={"Prefix": ""})]), retention_days=7) == 7


def test_verify_retention_rejects_unrelated_prefix_or_tag_filter():
    # A rule scoped to some OTHER prefix/tag does not cover the stored artifacts, so it
    # cannot stand in for the retention promise (the exact hole codex reproduced).
    for flt in ({"Filter": {"Prefix": "unrelated/"}},
                {"Prefix": "unrelated/"},                                   # legacy top-level prefix
                {"Filter": {"Tag": {"Key": "k", "Value": "v"}}},
                {"Filter": {"And": {"Prefix": "", "Tags": [{"Key": "k", "Value": "v"}]}}}):
        with pytest.raises(store.PolicyError, match="cover"):
            store.verify_retention(_LifecycleStore([_rule(7, **flt)]), retention_days=7)


def test_verify_retention_rejects_missing_disabled_or_too_long():
    with pytest.raises(store.PolicyError):                                  # no lifecycle at all
        store.verify_retention(_LifecycleStore([], error=RuntimeError("none")), retention_days=7)
    with pytest.raises(store.PolicyError):                                  # window too long
        store.verify_retention(_LifecycleStore([_rule(30)]), retention_days=7)
    disabled = {"Status": "Disabled", "Expiration": {"Days": 7}}
    with pytest.raises(store.PolicyError):
        store.verify_retention(_LifecycleStore([disabled]), retention_days=7)


def test_retrieve_refuses_object_past_retention_window():
    data = b"aged-out-bytes"
    ea = _event("acme", data)
    s3, audit = Store(), []
    rec = store.store(ea, _fetch({ea["object_ref"]: data}), s3, lambda _: None)
    # Age the stored object beyond the window: retrieval must refuse it even pre-sweep.
    s3.objects[rec["object_ref"]]["LastModified"] = datetime.now(timezone.utc) - timedelta(days=30)
    tokens = {"a": {"actor": "a", "tenant_id": "acme", "file_read": True}}
    with pytest.raises(ValueError, match="retention"):
        store.retrieve(rec["object_ref"], "Bearer a", tokens, s3, audit.append, retention_days=7)
    assert audit[-1]["outcome"] == "failed"


# ── process_one: permanent rejections let the consumer make progress ───────────

def test_process_one_stores_and_publishes_linkage():
    data = b"carved"
    ev = _event("acme", data)
    s3, prod, audit = Store(), _Producer(), []
    rec = app.process_one(ev, _fetch({ev["object_ref"]: data}), s3, prod, audit.append)
    assert rec and len(s3.objects) == 1
    assert len(prod.sent) == 1
    topic, link = prod.sent[0]
    assert topic == app.OUT_TOPIC
    assert link["state"] == "bytes_available"
    assert link["file_artifact_id"] == rec["artifact_id"]
    assert link["tenant_segment"] == object_keys.tenant_segment("acme")


def test_process_one_swallows_permanent_rejection_then_progresses():
    # A malformed archive (PolicyError) must NOT crash the loop: process_one returns None,
    # publishes nothing, and a following good record still stores — proving the consumer
    # can commit past the poison instead of replaying it forever (codex's crash-loop bug).
    bad = b"PK\x03\x04malformed"
    ev_bad = _event("acme", bad)
    s3, prod = Store(), _Producer()
    assert app.process_one(ev_bad, _fetch({ev_bad["object_ref"]: bad}), s3, prod, lambda _: None) is None
    assert not s3.objects and not prod.sent          # nothing stored, nothing published
    good = b"clean-bytes"
    ev_good = _event("acme", good)
    rec = app.process_one(ev_good, _fetch({ev_good["object_ref"]: good}), s3, prod, lambda _: None)
    assert rec and len(s3.objects) == 1 and len(prod.sent) == 1   # progress after the reject


def test_process_one_reraises_transient_fetch_error():
    # A transient fetch fault propagates so the offset stays uncommitted and replays.
    ev = _event("acme", b"bytes")

    def boom(_ref):
        raise ConnectionError("minio down")

    with pytest.raises(ConnectionError):
        app.process_one(ev, boom, Store(), _Producer(), lambda _: None)


def test_process_one_uncommittable_when_linkage_publish_unacked():
    # A stored artifact whose linkage publish is not ACKed must NOT be committed: the
    # unacked publish propagates so the event replays (store is idempotent).
    data = b"carved"
    ev = _event("acme", data)
    with pytest.raises(TimeoutError):
        app.process_one(ev, _fetch({ev["object_ref"]: data}), Store(),
                        _Producer(fail=True), lambda _: None, publish_timeout=0.01)


def test_process_one_metadata_only_no_store_no_publish():
    ev = _event("acme", b"whatever", state="metadata_only")
    s3, prod = Store(), _Producer()
    assert app.process_one(ev, _fetch({ev["object_ref"]: b"whatever"}), s3, prod, lambda _: None) is None
    assert not s3.objects and not prod.sent


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} file-artifact store tests passed")


def test_announced_sha256_mismatch_rejected():
    """Content-address integrity: a producer whose announced sha256 disagrees with the actual bytes
    can't be trusted for linkage — reject permanently (PolicyError), never store bytes under a lie."""
    data = b"honest-artifact-bytes"
    ev = _event("t1", data, sha256="0" * 64)   # object_ref keeps the real sha; only the claim lies
    s3, audit = Store(), []
    with pytest.raises(store.PolicyError):
        store.store(ev, _fetch({ev["object_ref"]: data}), s3, audit.append)


def test_record_sha256_is_computed_not_announced():
    """The stored record's sha256 is the hash of the bytes (== artifact_id), never the announced value."""
    data = b"honest-artifact-bytes"
    ev = _event("t1", data)                      # honest announcement
    rec = store.store(ev, _fetch({ev["object_ref"]: data}), Store(), lambda _: None)
    assert rec["sha256"] == rec["artifact_id"] == hashlib.sha256(data).hexdigest()


def test_corrupt_deflate_member_rejected_not_crashloop():
    """A corrupt DEFLATE member (zlib.error / bad CRC at read time) is a permanent violation -> PolicyError,
    so a poison-pill archive is rejected once instead of crash-looping the consumer forever."""
    z = _zip([("a.bin", b"A" * 4096)], compression=zipfile.ZIP_DEFLATED)  # compressible -> real deflate stream
    b = bytearray(z)
    start = 30 + len("a.bin") + 4                # into the compressed payload, past the local header+name
    for i in range(start, min(start + 16, len(b))):
        b[i] ^= 0xFF                             # mangle the deflate stream
    with pytest.raises(store.PolicyError):
        store.validate_archive(bytes(b))
