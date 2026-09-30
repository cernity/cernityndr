"""Unit U3 YARA ruleset registry tests: AUTHZ-gated lifecycle, poisoned-rule
guard (unauthorized promotion denied + audited), scan-worker visibility, sha256
integrity on load, MIME filtering, and registry-backed rule refresh.

Covers the five UNIT_U3.md test scenarios plus rules_refresh.refresh_to_registry.
"""
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from datetime import datetime

import registry as reg_mod
import rules_refresh as rr
from registry import RulesetRegistry, IllegalTransition, Unauthorized, IntegrityError, allow_actors

_SCHEMA = json.loads(
    (Path(__file__).resolve().parents[2] / "contracts" / "yara_ruleset.schema.json").read_text())
_FORMATS = FormatChecker()


@_FORMATS.checks("date-time", raises=ValueError)
def _valid_ts(value):
    return not isinstance(value, str) or datetime.fromisoformat(
        value.upper().replace("Z", "+00:00")).tzinfo is not None


_VALIDATOR = Draft202012Validator(_SCHEMA, format_checker=_FORMATS)
ADMIN = allow_actors("secops-admin")


def _reg():
    return RulesetRegistry()


def _draft(reg, name="baseline", data=b"rule r { condition: true }", **kw):
    return reg.register_draft(name, "1", data, "unit-test", **kw)


# --- scenario 1: lifecycle progresses; illegal transition rejected --------------
def test_lifecycle_progression():
    reg = _reg()
    rid = _draft(reg)["id"]
    assert reg.get(rid)["status"] == "draft"
    assert reg.promote(rid, "shadow", "secops-admin", ADMIN)["status"] == "shadow"
    assert reg.promote(rid, "active", "secops-admin", ADMIN)["status"] == "active"
    assert reg.promote(rid, "retired", "secops-admin", ADMIN)["status"] == "retired"


def test_illegal_transition_rejected():
    reg = _reg()
    rid = _draft(reg)["id"]
    reg.promote(rid, "shadow", "secops-admin", ADMIN)
    reg.promote(rid, "active", "secops-admin", ADMIN)
    reg.promote(rid, "retired", "secops-admin", ADMIN)
    with pytest.raises(IllegalTransition):
        reg.promote(rid, "active", "secops-admin", ADMIN)          # retired -> active
    assert reg.get(rid)["status"] == "retired"                     # unchanged


# --- scenario 2: unauthorized promotion denied + audited; authorized attributed --
def test_unauthorized_promotion_denied_and_audited():
    reg = _reg()
    rid = _draft(reg, name="evil")["id"]
    reg.promote(rid, "shadow", "secops-admin", ADMIN)
    with pytest.raises(Unauthorized):
        reg.promote(rid, "active", "attacker", ADMIN)              # not an allowed actor
    assert reg.get(rid)["status"] == "shadow"                      # NOT promoted
    denials = [a for a in reg.audit(rid) if a["event"] == "promotion_denied"]
    assert len(denials) == 1
    assert denials[0]["actor"] == "attacker" and denials[0]["to_status"] == "active"


def test_authorized_promotion_records_attribution():
    reg = _reg()
    rid = _draft(reg)["id"]
    reg.promote(rid, "shadow", "secops-admin", ADMIN)
    row = reg.promote(rid, "active", "secops-admin", ADMIN, ts="2026-09-29T12:00:00Z")
    assert row["promoted_by"] == "secops-admin"
    assert row["promoted_at"] == "2026-09-29T12:00:00Z"
    assert any(a["event"] == "promoted" and a["actor"] == "secops-admin"
               for a in reg.audit(rid))


# --- scenario 3: only active/shadow served to a scan worker ---------------------
def test_only_active_and_shadow_served():
    reg = _reg()
    d_draft = _draft(reg, name="draft-only")["id"]
    d_shadow = _draft(reg, name="shadow-one")["id"]
    d_active = _draft(reg, name="active-one")["id"]
    d_retired = _draft(reg, name="retired-one")["id"]
    reg.promote(d_shadow, "shadow", "secops-admin", ADMIN)
    reg.promote(d_active, "shadow", "secops-admin", ADMIN)
    reg.promote(d_active, "active", "secops-admin", ADMIN)
    reg.promote(d_retired, "retired", "secops-admin", ADMIN)
    served = {r["id"] for r in reg.active_for_scan()}
    assert served == {d_shadow, d_active}
    assert d_draft not in served and d_retired not in served


# --- scenario 4: sha256 integrity check on load ---------------------------------
def test_load_bytes_verifies_sha256():
    reg = _reg()
    data = b"rule good { strings: $a = \"x\" condition: $a }"
    rid = _draft(reg, name="ok", data=data)["id"]
    assert reg.load_bytes(rid) == data
    # a compromised object store swaps the bytes under the same address
    reg._db.execute("UPDATE ruleset_bytes SET data=? WHERE sha256=?",
                    (b"defanged { condition: false }", reg.get(rid)["sha256"]))
    reg._db.commit()
    with pytest.raises(IntegrityError):
        reg.load_bytes(rid)


# --- scenario 5: target_mime_types filter; row validates against the schema -----
def test_mime_filter():
    reg = _reg()
    pe = _draft(reg, name="pe-rules", target_mime_types=["application/x-dosexec"])["id"]
    anymime = _draft(reg, name="any-rules", target_mime_types=[])["id"]
    for rid in (pe, anymime):
        reg.promote(rid, "shadow", "secops-admin", ADMIN)
        reg.promote(rid, "active", "secops-admin", ADMIN)
    dos = {r["id"] for r in reg.active_for_scan(mime="application/x-dosexec")}
    assert dos == {pe, anymime}                                    # empty-list ruleset applies to all
    pdf = {r["id"] for r in reg.active_for_scan(mime="application/pdf")}
    assert pdf == {anymime}                                        # pe-only ruleset excluded


def test_row_validates_against_schema():
    reg = _reg()
    rid = _draft(reg, target_mime_types=["application/x-dosexec"])["id"]
    _VALIDATOR.validate(reg.get(rid))                              # draft row (null promotion)
    reg.promote(rid, "shadow", "secops-admin", ADMIN)
    reg.promote(rid, "active", "secops-admin", ADMIN)
    _VALIDATOR.validate(reg.get(rid))                              # promoted row


# --- registration input validation (trust boundary; reviewer regression) --------
def _stored(reg):
    """(#ruleset rows, #byte blobs) — used to assert a rejected write is atomic."""
    n_rows = reg._db.execute("SELECT COUNT(*) FROM rulesets").fetchone()[0]
    n_bytes = reg._db.execute("SELECT COUNT(*) FROM ruleset_bytes").fetchone()[0]
    return n_rows, n_bytes


@pytest.mark.parametrize("kw", [
    {"name": ""},                                                  # blank name (schema minLength 1)
    {"name": "   "},                                               # whitespace-only (schema \S)
    {"version": ""},
    {"max_file_size": -1},                                         # schema minimum 1
    {"max_file_size": 0},
    {"max_file_size": 4294967297},                                 # schema maximum
    {"max_file_size": True},                                       # bool must not pass as a size
    {"max_file_size": "big"},
    {"target_mime_types": "text/plain"},                           # a str is not a MIME array
    {"target_mime_types": [123]},                                  # items must be strings
    {"target_mime_types": [""]},                                   # blank MIME item
    {"test_corpus_ref": ""},                                       # schema minLength 1 when present
])
def test_register_rejects_malformed_input_atomically(kw):
    reg = _reg()
    with pytest.raises((ValueError, TypeError)):
        _draft(reg, **kw)
    assert _stored(reg) == (0, 0)                                  # no partial row, no orphan bytes


def test_register_string_mime_is_not_char_list():
    # regression: passing a bare string once stored list('text/plain') and never
    # matched the real MIME type. It must now be refused outright.
    reg = _reg()
    with pytest.raises(ValueError):
        _draft(reg, target_mime_types="text/plain")
    assert reg.list_rulesets() == []


def test_valid_mime_list_still_matches():
    reg = _reg()
    rid = _draft(reg, target_mime_types=["text/plain"])["id"]
    reg.promote(rid, "shadow", "secops-admin", ADMIN)
    assert [r["id"] for r in reg.active_for_scan(mime="text/plain")] == [rid]


@pytest.mark.parametrize("actor", [None, "", "   ", 123])
def test_promote_rejects_bad_actor_attribution(actor):
    reg = _reg()
    rid = _draft(reg)["id"]
    with pytest.raises(ValueError):
        reg.promote(rid, "shadow", actor, ADMIN)
    assert reg.get(rid)["status"] == "draft"                       # not moved
    # rejected before any write: no denial/transition audit, only 'registered'
    assert [a["event"] for a in reg.audit(rid)] == ["registered"]


# --- reviewer regression: supplied id/timestamp must satisfy the wire contract ----
@pytest.mark.parametrize("kw", [
    {"ruleset_id": "   "},                                         # blank id (schema pattern \S)
    {"ruleset_id": ""},                                            # empty id (schema minLength 1)
    {"ruleset_id": "x" * 257},                                     # over maxLength
    {"ruleset_id": 123},                                           # not a string
    {"ts": "not-a-date"},                                          # created_at not RFC3339
    {"ts": "2026-09-29"},                                          # date without time -> fails pattern
    {"ts": 1727600000},                                            # not a string
])
def test_register_rejects_bad_id_or_timestamp_atomically(kw):
    reg = _reg()
    with pytest.raises((ValueError, TypeError)):
        _draft(reg, **kw)
    assert _stored(reg) == (0, 0)                                  # no row, no orphan bytes


def test_promote_rejects_bad_timestamp():
    reg = _reg()
    rid = _draft(reg)["id"]
    with pytest.raises(ValueError):
        reg.promote(rid, "shadow", "secops-admin", ADMIN, ts="not-a-date")
    assert reg.get(rid)["status"] == "draft"                       # not moved
    assert [a["event"] for a in reg.audit(rid)] == ["registered"]  # no half-applied write


def test_register_valid_supplied_id_and_timestamp():
    reg = _reg()
    row = _draft(reg, ruleset_id="ruleset-2026-001", ts="2026-09-29T00:00:00Z")
    assert row["id"] == "ruleset-2026-001" and row["created_at"] == "2026-09-29T00:00:00Z"
    _VALIDATOR.validate(row)


def test_duplicate_id_failure_is_atomic_then_recovers():
    # Reviewer regression: a duplicate id with DIFFERENT bytes raised IntegrityError
    # after the blob was inserted, leaving an open transaction and an orphan blob that
    # a later successful write then committed. Registration must roll back cleanly and
    # a subsequent operation must not inherit the orphan.
    reg = _reg()
    reg.register_draft("dup", "1", b"first bytes", "op", ruleset_id="dup-id")
    before = _stored(reg)
    with pytest.raises(sqlite3.IntegrityError):                     # PK clash
        reg.register_draft("dup2", "1", b"different bytes", "op", ruleset_id="dup-id")
    assert reg._db.in_transaction is False                         # rolled back, no dangling txn
    assert _stored(reg) == before                                  # no orphan blob or partial row

    # a subsequent successful registration commits only its own row/blob
    reg.register_draft("next", "1", b"third bytes", "op", ruleset_id="next-id")
    assert _stored(reg) == (before[0] + 1, before[1] + 1)
    # the failed attempt left no audit trail on the target id
    assert [a["event"] for a in reg.audit("dup-id")] == ["registered"]


# --- reviewer finding 3: concurrency-safe status (no retired->active race) --------
def test_concurrent_connections_cannot_reactivate_retired(tmp_path):
    # Two SEPARATE registry connections (own conn + own lock) must not lose an
    # update on status: a retire racing an activate must NEVER leave the ruleset
    # active (no retired->active TOCTOU / lost update). Under a per-instance lock
    # with a deferred transaction, connection B could read 'shadow', connection A
    # could retire, then B's stale write would reactivate it. BEGIN IMMEDIATE makes
    # the read-check-write one serialized cross-connection write transaction.
    import threading
    from concurrent.futures import ThreadPoolExecutor

    db = str(tmp_path / "reg.db")
    seed = RulesetRegistry(db)
    for i in range(30):
        rid = seed.register_draft("r", "1", b"rule x { condition: true }", "t")["id"]
        seed.promote(rid, "shadow", "secops-admin", ADMIN)

        a, b = RulesetRegistry(db), RulesetRegistry(db)        # two connections
        barrier = threading.Barrier(2)

        def retire():
            barrier.wait()
            try:
                a.promote(rid, "retired", "secops-admin", ADMIN)
            except (IllegalTransition, Unauthorized):
                pass                                            # lost the race, fine
        def activate():
            barrier.wait()
            try:
                b.promote(rid, "active", "secops-admin", ADMIN)
            except (IllegalTransition, Unauthorized):
                pass

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(retire), pool.submit(activate)]
            for future in futures:
                future.result(timeout=10)  # unexpected worker errors must fail the test
        a._db.close()
        b._db.close()

        # Whichever won: retire-first -> activate rejected; activate-first ->
        # active then retired. Either way the row ends retired, never active.
        assert seed.get(rid)["status"] == "retired", \
            f"round {i}: status left {seed.get(rid)['status']!r} (retired->active race)"


# --- reviewer finding 5: ruleset ids are NOT filesystem paths (traversal guard) ---
@pytest.mark.parametrize("bad_id", [
    "../evil",                                                  # parent-dir escape
    "..",
    "a/b",                                                      # path separator
    "a\\b",                                                     # windows separator
    "foo/../../etc/passwd",
    "served_../x",
    ".hidden",                                                  # leading dot (dotfile)
    "-flag",                                                    # leading dash
    "x\x00y",                                                   # NUL byte
    "with space",
    "safe\n",                                                 # trailing newline is not a safe token
])
def test_register_rejects_unsafe_ids_atomically(bad_id):
    reg = _reg()
    with pytest.raises((ValueError, TypeError)):
        _draft(reg, ruleset_id=bad_id)
    assert _stored(reg) == (0, 0)                               # no row, no orphan bytes


def test_served_ruleset_path_stays_inside_cache_dir(tmp_path):
    # The id reaches os.path.join(cache_dir, f"served_{id}.yar") in ensure_rules.
    # A validated id can never place that materialised file outside cache_dir.
    reg = _reg()
    rid = _draft(reg, ruleset_id="ruleset-2026-042")["id"]
    reg.promote(rid, "shadow", "secops-admin", ADMIN)
    reg.promote(rid, "active", "secops-admin", ADMIN)
    cache = tmp_path / "cache"
    empty_bundle = tmp_path / "none"
    paths = rr.ensure_rules(reg, bundled_dir=str(empty_bundle), cache_dir=str(cache))
    assert len(paths) == 1
    resolved = Path(paths[0]).resolve()
    assert resolved.parent == cache.resolve()                  # never escapes the cache dir


# --- registry-backed refresh: stages REMOTE rules as DRAFT rows, sha256 matches --
def test_refresh_to_registry_writes_drafts(monkeypatch):
    # a reachable remote ruleset is staged as a DRAFT (never auto-served)
    body = b"rule refreshed { condition: true }"
    monkeypatch.setenv("YARA_RULES_URLS", "https://mirror.example/refreshed.yar")
    monkeypatch.setattr(rr, "_fetch_remote", lambda url: body)     # no real network
    reg = _reg()
    ids = rr.refresh_to_registry(reg, source="rules-refresh")
    assert len(ids) == 1
    row = reg.get(ids[0])
    assert row["status"] == "draft" and row["promoted_by"] is None
    assert row["sha256"] == hashlib.sha256(body).hexdigest()
    assert reg.load_bytes(ids[0]) == body                          # bytes stored + verify
    _VALIDATOR.validate(row)


def test_refresh_skips_non_https(monkeypatch):
    monkeypatch.setenv("YARA_RULES_URLS", "http://insecure.example/evil.yar")
    reg = _reg()
    ids = rr.refresh_to_registry(reg)
    assert ids == []                                               # non-https refused


def test_refresh_to_registry_is_idempotent(monkeypatch):
    # repeated refresh of identical content must NOT accumulate duplicate drafts
    body = b"rule r { condition: true }"
    monkeypatch.setenv("YARA_RULES_URLS", "https://mirror.example/r.yar")
    monkeypatch.setattr(rr, "_fetch_remote", lambda url: body)
    reg = _reg()
    first = rr.refresh_to_registry(reg)
    second = rr.refresh_to_registry(reg)
    assert len(first) == 1 and second == []                        # identical bytes not re-staged
    assert len(reg.list_rulesets()) == 1


# --- regression: unpromoted remote rules must NOT reach the compile path --------
def test_ensure_rules_never_compiles_unpromoted_remote(tmp_path, monkeypatch):
    remote_body = b"rule remote_evil { condition: true }"
    monkeypatch.setenv("YARA_RULES_URLS", "https://mirror.example/remote.yar")
    monkeypatch.setattr(rr, "_fetch_remote", lambda url: remote_body)  # no real network
    bundled = tmp_path / "rules"
    bundled.mkdir()
    (bundled / "baseline.yar").write_bytes(b"rule base { condition: true }")
    cache = tmp_path / "cache"
    reg = _reg()

    # refresh STAGES only the remote ruleset as a draft — never compiles it. The
    # bundled baseline is served from disk and is not staged.
    ids = rr.refresh_to_registry(reg)
    assert len(ids) == 1 and reg.get(ids[0])["status"] == "draft"
    assert reg.get(ids[0])["sha256"] == hashlib.sha256(remote_body).hexdigest()

    # compile path yields bundled baseline only; the remote bytes appear nowhere
    paths = rr.ensure_rules(reg, bundled_dir=str(bundled), cache_dir=str(cache))
    blobs = b"".join(Path(p).read_bytes() for p in paths)
    assert b"rule base" in blobs
    assert remote_body not in blobs

    # only after an AUTHORIZED promotion does the remote ruleset reach compile
    reg.promote(ids[0], "shadow", "secops-admin", ADMIN)
    blobs2 = b"".join(Path(p).read_bytes()
                      for p in rr.ensure_rules(reg, bundled_dir=str(bundled), cache_dir=str(cache)))
    assert remote_body in blobs2                                   # promoted -> now served


def test_ensure_rules_purges_previously_cached_remote(tmp_path):
    # a remote_*.yar left by an older build must be purged, not compiled
    bundled = tmp_path / "rules"
    bundled.mkdir()
    (bundled / "baseline.yar").write_bytes(b"rule base { condition: true }")
    cache = tmp_path / "cache"
    cache.mkdir()
    stale = cache / "remote_0.yar"
    stale.write_bytes(b"rule stale_remote { condition: true }")
    reg = _reg()
    paths = rr.ensure_rules(reg, bundled_dir=str(bundled), cache_dir=str(cache))
    assert not stale.exists()                                       # purged from the compile cache
    assert str(stale) not in paths
    assert all("remote_0" not in p for p in paths)


def test_ensure_rules_serves_promoted_and_verifies_bytes(tmp_path):
    reg = _reg()
    body = b"rule promoted { condition: true }"
    rid = _draft(reg, name="promoted", data=body)["id"]
    cache = tmp_path / "cache"
    empty_bundle = tmp_path / "none"
    # draft is not served
    assert rr.ensure_rules(reg, bundled_dir=str(empty_bundle), cache_dir=str(cache)) == []
    reg.promote(rid, "shadow", "secops-admin", ADMIN)
    reg.promote(rid, "active", "secops-admin", ADMIN)
    paths = rr.ensure_rules(reg, bundled_dir=str(empty_bundle), cache_dir=str(cache))
    assert len(paths) == 1 and Path(paths[0]).read_bytes() == body
    # tampered bytes are refused on materialisation (sha256 integrity check)
    reg._db.execute("UPDATE ruleset_bytes SET data=? WHERE sha256=?",
                    (b"defanged", reg.get(rid)["sha256"]))
    reg._db.commit()
    with pytest.raises(IntegrityError):
        rr.ensure_rules(reg, bundled_dir=str(empty_bundle), cache_dir=str(cache))


# --- regression: bundled rules follow the lifecycle only under AUTHORIZED control --
def test_ensure_rules_bundled_lifecycle(tmp_path):
    # A bundled ruleset stays the always-available baseline until an AUTHORIZED
    # transition brings it under registry control: served while active/shadow,
    # excluded once retired. An anonymous draft must NOT suppress it (see the
    # dedicated regression below). Retired-still-compiled was the earlier finding.
    bundled = tmp_path / "rules"
    bundled.mkdir()
    body = b"rule eicar_like { condition: true }"
    (bundled / "eicar.yar").write_bytes(body)
    cache = tmp_path / "cache"
    reg = _reg()

    def served():
        return b"".join(Path(p).read_bytes()
                        for p in rr.ensure_rules(reg, bundled_dir=str(bundled), cache_dir=str(cache)))

    assert body in served()                                        # no row: always-available baseline

    rid = reg.register_draft("eicar", "1", body, "operator")["id"]
    assert reg.get(rid)["status"] == "draft"
    assert body in served()                                        # anonymous draft does NOT suppress

    reg.promote(rid, "shadow", "secops-admin", ADMIN)
    reg.promote(rid, "active", "secops-admin", ADMIN)
    assert body in served()                                        # active -> served (from object store)

    reg.promote(rid, "retired", "secops-admin", ADMIN)
    assert reg.active_for_scan() == []
    assert body not in served()                                    # retired bundled rule excluded


def test_remote_draft_of_bundled_rule_does_not_suppress_baseline(tmp_path, monkeypatch):
    # Reviewer regression: a REMOTE copy of a bundled rule, staged as a draft by the
    # unauthenticated refresh path, must not disable the bundled baseline. Only an
    # AUTHORIZED promotion transfers those bytes into registry lifecycle control.
    bundled = tmp_path / "rules"
    bundled.mkdir()
    body = b"rule baseline_pe { condition: true }"
    (bundled / "baseline.yar").write_bytes(body)
    cache = tmp_path / "cache"
    reg = _reg()

    def served():
        return b"".join(Path(p).read_bytes()
                        for p in rr.ensure_rules(reg, bundled_dir=str(bundled), cache_dir=str(cache)))

    # refresh stages a remote ruleset whose bytes are IDENTICAL to the bundled rule
    monkeypatch.setenv("YARA_RULES_URLS", "https://mirror.example/baseline.yar")
    monkeypatch.setattr(rr, "_fetch_remote", lambda url: body)
    ids = rr.refresh_to_registry(reg)
    assert len(ids) == 1 and reg.get(ids[0])["status"] == "draft"
    assert body in served()                                        # baseline still detects -- not suppressed

    # an authorized promotion is what moves those bytes under lifecycle control;
    # retiring them then removes coverage (now an on-record authorized decision)
    reg.promote(ids[0], "shadow", "secops-admin", ADMIN)
    reg.promote(ids[0], "active", "secops-admin", ADMIN)
    assert body in served()
    reg.promote(ids[0], "retired", "secops-admin", ADMIN)
    assert body not in served()                                    # authorized retire -> baseline gone


# --- regression: refresh loop drops a retired final ruleset from later scans -------
def test_refresh_once_clears_snapshot_when_all_rules_retired(tmp_path, monkeypatch):
    import app
    reg = RulesetRegistry()
    monkeypatch.setattr(app, "_registry", reg)
    # fake compile so the test needs no native yara lib; an empty source list is
    # guarded before compile is reached, a non-empty one yields a sentinel snapshot.
    monkeypatch.setattr(app.sc, "compile_rules", lambda srcs: ("compiled", tuple(srcs)))
    cache = tmp_path / "cache"
    empty_bundle = tmp_path / "none"
    _ensure = rr.ensure_rules                                      # app.rr IS rr; capture before patch
    monkeypatch.setattr(app.rr, "ensure_rules", lambda registry: _ensure(
        registry, bundled_dir=str(empty_bundle), cache_dir=str(cache)))

    rid = reg.register_draft("only", "1", b"rule only { condition: true }", "operator")["id"]
    reg.promote(rid, "shadow", "secops-admin", ADMIN)
    reg.promote(rid, "active", "secops-admin", ADMIN)
    app._compiled[0] = None
    assert app._refresh_once() == 1                                # one eligible ruleset compiled
    assert app._compiled[0] is not None

    reg.promote(rid, "retired", "secops-admin", ADMIN)             # retire the last ruleset
    assert app._refresh_once() == 0
    assert app._compiled[0] is None                                # retired rule no longer live


# --- regression: periodic refresh re-stages remote rules (reviewer blocking) -----
def _patch_refresh_env(app, reg, monkeypatch, tmp_path):
    """Wire app._refresh_once to a real registry + isolated dirs, with a fake
    compile so no native yara lib is needed. Returns nothing; caller sets _fetch."""
    monkeypatch.setattr(app, "_registry", reg)
    monkeypatch.setattr(app.sc, "compile_rules", lambda srcs: ("compiled", tuple(srcs)))
    cache = tmp_path / "cache"
    empty_bundle = tmp_path / "none"
    _ensure = rr.ensure_rules
    monkeypatch.setattr(app.rr, "ensure_rules", lambda registry: _ensure(
        registry, bundled_dir=str(empty_bundle), cache_dir=str(cache)))


def test_refresh_once_stages_changed_remote_content(tmp_path, monkeypatch):
    # A remote ruleset whose content CHANGES between refreshes must be discovered
    # and staged as a new draft — startup-only staging missed this (reviewer).
    import app
    reg = RulesetRegistry()
    _patch_refresh_env(app, reg, monkeypatch, tmp_path)
    monkeypatch.setenv("YARA_RULES_URLS", "https://mirror.example/rules.yar")

    body = {"v": b"rule v1 { condition: true }"}
    monkeypatch.setattr(rr, "_fetch_remote", lambda url: body["v"])
    app._compiled[0] = None
    app._refresh_once()
    drafts = reg.list_rulesets(status="draft")
    assert len(drafts) == 1
    assert drafts[0]["sha256"] == hashlib.sha256(body["v"]).hexdigest()

    body["v"] = b"rule v2 { condition: true }"                     # upstream changed
    app._refresh_once()
    drafts = reg.list_rulesets(status="draft")
    assert len(drafts) == 2                                         # new content -> new draft
    assert {d["sha256"] for d in drafts} == {
        hashlib.sha256(b"rule v1 { condition: true }").hexdigest(),
        hashlib.sha256(b"rule v2 { condition: true }").hexdigest()}
    # unchanged content on a later refresh is a no-op (content dedup preserved)
    app._refresh_once()
    assert len(reg.list_rulesets(status="draft")) == 2


def test_refresh_once_recovers_from_initial_fetch_failure(tmp_path, monkeypatch):
    # An initial remote fetch that FAILS (returns None) must not abort the refresh,
    # and a later successful fetch must still stage the draft (retry on recovery).
    import app
    reg = RulesetRegistry()
    _patch_refresh_env(app, reg, monkeypatch, tmp_path)
    monkeypatch.setenv("YARA_RULES_URLS", "https://mirror.example/rules.yar")

    state = {"ok": False}
    body = b"rule recovered { condition: true }"
    monkeypatch.setattr(rr, "_fetch_remote", lambda url: body if state["ok"] else None)

    app._compiled[0] = None
    app._refresh_once()                                            # fetch fails -> no draft, no crash
    assert reg.list_rulesets(status="draft") == []

    state["ok"] = True
    app._refresh_once()                                            # remote recovered -> staged now
    drafts = reg.list_rulesets(status="draft")
    assert len(drafts) == 1 and drafts[0]["sha256"] == hashlib.sha256(body).hexdigest()
    assert drafts[0]["promoted_by"] is None                        # staged as draft, never auto-served


def test_module_self_check():
    reg_mod.demo()                                                 # ponytail self-check runs clean


@pytest.mark.parametrize("mime", [
    "not-a-mime", "text/", "/plain", "text/plain/extra", "text /plain",
    "text/plain; charset=utf-8", "text/*", "*/*", "text/plain\n",
])
def test_malformed_mime_syntax_rejected_atomically(mime):
    reg = _reg()
    with pytest.raises(ValueError):
        _draft(reg, target_mime_types=[mime])
    assert _stored(reg) == (0, 0)
    assert reg._db.execute("SELECT COUNT(*) FROM ruleset_audit").fetchone()[0] == 0
    assert not reg._db.in_transaction


@pytest.mark.parametrize("ts", [
    "2026-13-01T00:00:00Z", "2026-02-29T00:00:00Z",
    "2026-04-31T00:00:00Z", "0000-01-01T00:00:00Z",
    "2026-09-29T24:00:00Z", "2026-09-29T00:60:00Z",
    "2026-09-29T00:00:61Z", "2026-09-29T00:00:00+24:00",
    "2026-09-29T00:00:00+00:60", "2026-09-29T00:00:00Z\n",
])
def test_invalid_calendar_timestamp_rejected_atomically(ts):
    reg = _reg()
    with pytest.raises(ValueError):
        _draft(reg, ts=ts)
    assert _stored(reg) == (0, 0)
    assert not reg._db.in_transaction
    rid = _draft(reg)["id"]
    before = reg.get(rid), reg.audit(rid)
    with pytest.raises(ValueError):
        reg.promote(rid, "shadow", "secops-admin", ADMIN, ts=ts)
    assert (reg.get(rid), reg.audit(rid)) == before
    assert not reg._db.in_transaction


@pytest.mark.parametrize("ts", [
    "2024-02-29T23:59:59Z", "2026-09-29t00:00:00.123z",
    "2026-09-29T00:00:00+05:30", "2026-09-29T00:00:00-07:00",
])
def test_valid_calendar_timestamp_matches_wire_contract(ts):
    reg = _reg()
    row = _draft(reg, ts=ts)
    _VALIDATOR.validate(row)
    _VALIDATOR.validate(reg.promote(row["id"], "shadow", "secops-admin", ADMIN, ts=ts))


def test_audit_persist_failure_rolls_back_registration(monkeypatch):
    reg = _reg()
    original = reg._audit

    def fail_after_audit(*args, **kwargs):
        original(*args, **kwargs)
        raise sqlite3.OperationalError("injected persistence failure")

    monkeypatch.setattr(reg, "_audit", fail_after_audit)
    with pytest.raises(sqlite3.OperationalError, match="injected persistence failure"):
        _draft(reg)
    assert _stored(reg) == (0, 0)
    assert reg._db.execute("SELECT COUNT(*) FROM ruleset_audit").fetchone()[0] == 0
    assert not reg._db.in_transaction
    monkeypatch.setattr(reg, "_audit", original)
    _draft(reg)
    assert _stored(reg) == (1, 1)


def test_retire_transaction_blocks_concurrent_activation(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    import threading

    path = str(tmp_path / "serialized.db")
    retiring, activating = RulesetRegistry(path), RulesetRegistry(path)
    rid = _draft(retiring)["id"]
    retiring.promote(rid, "shadow", "secops-admin", ADMIN)
    retire_checked = threading.Event()
    activate_started = threading.Event()
    release_retire = threading.Event()

    def authorize_retirement(*args):
        retire_checked.set()  # retirement has read shadow while holding its write lock
        assert release_retire.wait(5)
        return True

    def trace(statement):
        if statement == "BEGIN IMMEDIATE":
            activate_started.set()

    activating._db.set_trace_callback(trace)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            retire = pool.submit(retiring.promote, rid, "retired", "secops-admin", authorize_retirement)
            try:
                assert retire_checked.wait(5)
                activate = pool.submit(activating.promote, rid, "active", "secops-admin", ADMIN)
                assert activate_started.wait(5)
            finally:
                release_retire.set()
            retire.result(timeout=5)
            with pytest.raises(IllegalTransition, match="retired"):
                activate.result(timeout=5)
        assert activating.get(rid)["status"] == "retired"
        assert [a["to_status"] for a in activating.audit(rid)] == ["draft", "shadow", "retired"]
        assert not retiring._db.in_transaction and not activating._db.in_transaction
    finally:
        retiring._db.close()
        activating._db.close()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    import inspect
    for fn in fns:
        if inspect.signature(fn).parameters:
            continue                                               # skip pytest-fixture tests in bare run
        fn()
        print("ok ", fn.__name__)
    reg_mod.demo()
    print("\nregistry self-checks passed")
