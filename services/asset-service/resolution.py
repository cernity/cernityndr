"""Asset / identity resolution (plan U17 + U7; design §13.4, §13.5). Pure logic —
app.py wires it to the topics + ClickHouse. The entity spine: resolve every
observation to a stable asset_key within a tenant so the SAME host seen by
different sensors (same MAC) folds into one entity, even as its IP changes.

U7 adds temporal, evidence-backed FACTS: each attribution carries a value, a
validity interval [valid_from, valid_to), a confidence and an evidence-backed
source (§13.4). A changed value NEVER overwrites — the open interval is closed and
a new one opens. Conflicts at the same normalized ts resolve deterministically
(§13.5). Identity bindings (IP<->MAC) are TIME-BOUNDED by MAC evidence and DHCP
lease windows (§13.5): a reused address after a lease expires is NOT attributed to
the previous holder; IP-only attribution is explicitly uncertain.

Time handling is instant-based: timestamps are parsed to UTC datetimes for
ordering/interval math and re-emitted in one canonical millisecond ISO form, so
mixed fractional precision and offsets sort correctly.
"""
from __future__ import annotations

import hashlib
import json
import re as _re
from datetime import datetime, timedelta, timezone


# ── canonical time ────────────────────────────────────────────────────────────

def _instant(v) -> datetime:
    """Parse a ts (ISO string or datetime) to a UTC-aware datetime for ordering
    and interval math. Naive datetimes are assumed UTC. This is the ONLY ordering
    key — never compare timestamp STRINGS (fractional precision / offset differ)."""
    if isinstance(v, datetime):
        dt = v
    else:
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso(v) -> str | None:
    """Canonical representation: UTC, millisecond precision, 'Z'. None passes
    through. 12:00:00Z and 12:00:00.000+00:00 both -> '...T12:00:00.000Z'."""
    if v is None:
        return None
    return _instant(v).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ── canonical observation identity (mirrors normalizer.models.observation) ─────
# The asset-service consumes RAW EVE off the bus and must pin each fact to a
# DURABLE, retrievable observation identity using the SAME contract the normalizer
# uses, so source.observation_id is canonical + deterministic across replay (and
# equals the normalizer's obs_id for the same bus occurrence). Parity with the
# normalizer is pinned by test_obs_id_matches_normalizer.
# ponytail: contract mirrored (3 lines) rather than a cross-service runtime import;
# move to shared/ if a third consumer needs it. Drift is caught by the parity test.

def canonical_obs_id(tenant: str, sensor: str, topic: str, partition: int, offset: int) -> str:
    identity = json.dumps([tenant, sensor, topic, partition, offset],
                          sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "obs:" + hashlib.sha256(identity.encode()).hexdigest()


# ── evidence extraction ────────────────────────────────────────────────────────

def extract_evidence(eve: dict) -> list[dict]:
    """Pull (ip, mac, hostname, lease) observations from a raw Suricata EVE record.
    Different event types carry different identity strength. DHCP carries a lease
    interval (§13.5) — lease_secs is preserved so bindings can expire."""
    et = eve.get("event_type")
    out: list[dict] = []
    if et == "flow":
        # flows give IP activity only (no L2 on most sensors).
        for ip in (eve.get("src_ip"), eve.get("dest_ip")):
            if ip:
                out.append({"ip": ip, "mac": None, "hostname": None,
                            "lease_secs": None, "src": "flow"})
    elif et == "arp":
        a = eve.get("arp", {}) or {}
        if a.get("src_ip"):
            out.append({"ip": a.get("src_ip"), "mac": a.get("src_mac"),
                        "hostname": None, "lease_secs": None, "src": "arp"})
    elif et == "dhcp":
        d = eve.get("dhcp", {}) or {}
        ip = d.get("assigned_ip") or d.get("client_ip")
        if ip:
            lease = d.get("lease_time")
            out.append({"ip": ip, "mac": d.get("client_mac"),
                        "hostname": d.get("hostname"),
                        "lease_secs": int(lease) if lease else None, "src": "dhcp"})
    elif et == "tls":
        # U3c additive (observed-only): a TLS handshake carries two distinct
        # fingerprints and a presented cert. The CLIENT (src) fingerprint (ja4)
        # describes the client; the SERVER (dst) fingerprint (ja4s) and the
        # presented certificate describe the server. Each value attaches ONLY to
        # the entity it attests — never the client's ja4 onto the server, nor the
        # server's cert onto the client (that would fabricate identity the packet
        # does not carry). A field the record lacks yields no attribute (ADR 010).
        t = eve.get("tls", {}) or {}
        src, dst = eve.get("src_ip"), eve.get("dest_ip")
        client_ja4 = [t["ja4"]] if t.get("ja4") else []
        server_ja4 = [t["ja4s"]] if t.get("ja4s") else []
        certs = [c for c in (t.get("subject"), t.get("issuerdn"), t.get("fingerprint")) if c]
        if src and client_ja4:
            out.append(_attr_obs(src, "tls", ja4=client_ja4))
        if dst and (server_ja4 or certs):
            out.append(_attr_obs(dst, "tls", ja4=server_ja4, certificates=certs))
    elif et == "http":
        # U3c additive (observed-only): the user-agent is the CLIENT's software
        # (src applications); the Host header names the SERVER the client reached
        # (dst hostname) — NOT the client's own name, so it attaches to dst.
        h = eve.get("http", {}) or {}
        src, dst = eve.get("src_ip"), eve.get("dest_ip")
        ua = h.get("http_user_agent")
        host = h.get("hostname")
        if src and ua:
            out.append(_attr_obs(src, "http", applications=[ua]))
        if dst and host:
            out.append(_attr_obs(dst, "http", hostname=host))
    # dns + flow DO NOT set attributes — they produce relationship edges
    # (relationships.build_edges). flow still emits its ip-only identity rows above.
    return out


def _attr_obs(ip: str, src: str, hostname=None, **attrs) -> dict:
    """An observation row carrying additive U3c attributes, in the SAME shape as the
    shipped identity rows (ip/mac/hostname/lease_secs/src) so merge() folds it
    identically — plus only the observed attribute keys (never a default)."""
    obs = {"ip": ip, "mac": None, "hostname": hostname, "lease_secs": None, "src": src}
    obs.update({k: v for k, v in attrs.items() if v})
    return obs


# ── time-bounded identity bindings (§13.5) ─────────────────────────────────────
# bindings: ip -> [ {mac, valid_from, expires} ... ].  A binding is valid from
# valid_from until the EARLIER of (a) the next binding of the same ip and (b) its
# DHCP lease expiry. Outside every binding window an IP resolves to NOTHING —
# reused addresses are never attributed to the previous holder.

def lease_expiry(ts, lease_secs) -> str | None:
    if not lease_secs:
        return None
    return _iso(_instant(ts) + timedelta(seconds=lease_secs))


def record_binding(bindings: dict, ip: str, mac: str, valid_from, expires,
                   obs_id: str = "", src: str = "") -> None:
    """Record ONE lease/ARP binding record, preserving its evidence identity (obs_id +
    src) so point-attribution can select among same-start records with the SAME rule
    the persisted-ownership rebuild uses (§13.5) — the two can never diverge.

    A record is keyed by (mac, valid_from, obs_id): an IDENTICAL record replayed is a
    no-op (replay-safe), but two DISTINCT records that share a MAC and start — e.g. a
    60s and a 3600s lease observed at the same instant — are BOTH kept. owner_at then
    drops the loser deterministically by the same lease id (_lease_id) both paths use,
    rather than one path taking the longest expiry while the other takes the smallest
    obs_id (the reviewer's 12:01-vs-13:00 divergence)."""
    lst = bindings.setdefault(ip, [])
    b = {"mac": mac.lower(), "valid_from": _iso(valid_from), "expires": _iso(expires),
         "obs_id": obs_id or "", "src": src or ""}
    for x in lst:
        if (x["mac"], x["valid_from"], x["obs_id"]) == (b["mac"], b["valid_from"], b["obs_id"]):
            return                                    # identical record — replay no-op
    lst.append(b)


def _lease_id(c: dict) -> tuple:
    """A lease's STABLE identity — the same-start tie-break the task fixes (§13.5). The
    lease id IS its source observation id (obs_id): deterministic and reproduced
    byte-for-byte across replay, so live attribution (owner_at) and the persisted-interval
    rebuild pick the identical lease and can never diverge. mac is a total-order fallback
    only when obs_id is absent (pure-logic bindings). Source strength/confidence are
    deliberately NOT part of it — a same-start conflict is broken by lease id, period, not
    by which evidence type happens to be stronger."""
    return (str(c.get("obs_id", "")), c["mac"])


def _winning_by_start(leases: list[dict]) -> dict:
    """The one winning lease per distinct start instant, ties broken by lease id
    (_lease_id). A claim that loses its start is DROPPED — it never re-wins later, even
    against a shorter winning lease, so both attribution and the cache agree no one owns
    the tail (§13.5)."""
    by_start: dict = {}
    for c in leases:
        s = _instant(c["valid_from"])
        prev = by_start.get(s)
        if prev is None or _lease_id(c) < _lease_id(prev):
            by_start[s] = c
    return by_start


def _lease_end(c: dict, starts: list, i: int):
    """A winning claim ends at the EARLIER of the next distinct start (reassignment or the
    same MAC's renewal) and its OWN lease expiry — a shorter replacement lease caps
    ownership at the new expiry; an expiry before the next start leaves a genuine gap."""
    ends = []
    if i + 1 < len(starts):
        ends.append(starts[i + 1])
    if c.get("expires"):
        ends.append(_instant(c["expires"]))
    return min(ends) if ends else None


def owner_at(leases: list[dict], t) -> str | None:
    """THE ownership oracle (§13.5): the MAC that owns an address at instant `t` among the
    FULL raw candidate-lease set for that ip, or None (uncertain / lease gap). Each lease is
    a raw record {mac, valid_from, [expires], [obs_id], [src]}. Deterministic and
    order-independent (winner chosen per-start, not by arrival). This is the SINGLE ownership
    function — BOTH live point-attribution (resolve_mac) and the persisted-interval rebuild
    (ownership_intervals -> rebuild_ip_ownership) call it on the SAME leases, so a stored
    interval can NEVER disagree with what attribution resolves."""
    t = _instant(t)
    win = _winning_by_start(leases)
    starts = sorted(win)
    for i, s in enumerate(starts):
        end = _lease_end(win[s], starts, i)
        if s <= t and (end is None or t < end):
            return win[s]["mac"]
    return None


def ownership_intervals(ip: str, leases: list[dict]) -> list[dict]:
    """The DERIVED interval cache for one ip — the piecewise-constant plot of owner_at over
    every lease boundary (each start + each expiry). Because every point comes from owner_at
    there is NO parallel ownership logic; the cache is exactly what attribution sees.
    Order-independent. Adjacent segments with the same owner coalesce (a renewal, or a lease
    that outlives an unrelated expiry boundary); a None (gap) segment drops. Each interval
    carries its winning lease's evidence (source/confidence/obs_id) for the caller to key on.

    ponytail: recomputes from the raw leases each change — correctness (restart/late-event)
    over row count; the raw leases are the durable source, so coalescing here is safe."""
    win = _winning_by_start(leases)
    bounds = sorted(set(win) | {_instant(c["expires"]) for c in leases if c.get("expires")})
    intervals: list[dict] = []
    for i, b in enumerate(bounds):
        mac = owner_at(leases, b)
        if mac is None:
            continue
        nb = bounds[i + 1] if i + 1 < len(bounds) else None
        last = intervals[-1] if intervals else None
        if last is not None and last["mac"] == mac and last["valid_to"] == _iso(b):
            last["valid_to"] = _iso(nb) if nb else None      # coalesce adjacent same owner
            continue
        c = win[b]                                           # opens at a winning start
        intervals.append({
            "mac": mac, "value": ip, "valid_from": _iso(b),
            "valid_to": _iso(nb) if nb else None,
            "confidence": SOURCE_CONFIDENCE.get(c.get("src", ""), 0.0),
            "source": {"type": c.get("src", ""), "observation_id": c.get("obs_id", "")},
            "method": c.get("src"), "classifier_version": CLASSIFIER_VERSION,
        })
    return intervals


def resolve_mac(bindings: dict, ip: str, ts) -> str | None:
    """MAC that OWNS `ip` at instant `ts`, or None (uncertain / lease gap). A thin call to
    the owner_at oracle over the SAME raw leases the persisted cache rebuilds from, so
    attribution and stored facts agree in every case — reassignment, a shorter replacement
    lease, an equal-start conflict (lex-min MAC), lease gaps (§13.5) — never by arrival order."""
    return owner_at(bindings.get(ip) or [], ts)


def asset_key(obs: dict, bindings: dict, ts) -> str:
    """Resolve an observation to a stable asset_key at instant ts. MAC-first; else a
    MAC bound to this IP *at ts* (time-bounded, §13.5); else an IP-only key (weak)."""
    mac = obs.get("mac")
    if mac:
        return "mac:" + mac.lower()
    ip = obs.get("ip")
    bound = resolve_mac(bindings, ip, ts) if ip else None
    if bound:
        return "mac:" + bound
    return "ip:" + ip if ip else "ip:unknown"


# U3a additive entity attributes (model only — NO ingestion wiring here; extract_evidence
# does not yet populate these, so they are carried only when a caller supplies them on the
# obs row). Scalars set-when-observed; lists accumulate like the shipped *_set fields. An
# attribute is recorded ONLY when the observation actually carries it — role/os/listening-
# service etc. are NEVER inferred or asserted when unobserved (per-attribute provenance below
# makes "observed" explicit; absent from provenance == never seen).
_ATTR_SCALARS = ("username", "role", "os_hint", "criticality", "owner")
_ATTR_LISTS = ("applications", "listening_services", "certificates", "ja4")


def _note_provenance(a: dict, attr: str, obs: dict, ts: str) -> None:
    """Record that `attr` was set from an OBSERVED value (source + when). Created lazily so a
    record with no additive attributes carries no provenance key (shipped shape preserved).
    The schema permits attribute_provenance: null (additive + nullable) — a present-but-null
    value is normalized to a fresh mapping here, else recording would raise (setdefault keeps
    the existing None)."""
    prov = a.get("attribute_provenance")
    if prov is None:                               # absent OR explicitly null
        prov = a["attribute_provenance"] = {}
    prov[attr] = {"source": obs.get("src", ""), "observed_at": ts}


def merge(asset: dict | None, obs: dict, ts: str) -> dict:
    """Merge an observation into an asset record (accumulate sets, advance seen).

    U3a (additive): also carry optional entity attributes (_ATTR_SCALARS / _ATTR_LISTS) ONLY
    when the observation actually provides them, recording per-attribute provenance. An
    attribute the obs does not carry stays ABSENT — never fabricated, defaulted, or inferred.
    Signature and the shipped entity shape are unchanged: an obs with none of the new keys
    yields exactly the pre-U3a record (no new keys, no provenance)."""
    a = asset or {"ip_set": [], "mac_set": [], "hostname_set": [],
                  "evidence_sources": [], "first_seen": ts, "confidence": 0.5,
                  "role_if_known": ""}
    for field, val in (("ip_set", obs.get("ip")), ("mac_set", obs.get("mac")),
                       ("hostname_set", obs.get("hostname")),
                       ("evidence_sources", obs.get("src"))):
        v = (val or "").lower() if field == "mac_set" and val else val
        if v and v not in a[field]:
            a[field] = a[field] + [v]
    a["last_seen"] = ts
    # confidence rises with corroborating evidence types.
    a["confidence"] = min(1.0, 0.5 + 0.1 * len(set(a["evidence_sources"])))
    for attr in _ATTR_SCALARS:
        val = obs.get(attr)
        if val is not None:                        # observed -> set + provenance
            a[attr] = val
            _note_provenance(a, attr, obs, ts)
    for attr in _ATTR_LISTS:
        vals = obs.get(attr)
        if vals:                                   # observed non-empty -> accumulate
            existing = a.get(attr) or []
            new = existing + [v for v in vals if v not in existing]
            if attr not in a or new != existing:
                a[attr] = new
                _note_provenance(a, attr, obs, ts)
    return a


# ── U7: temporal, evidence-backed facts (§13.4) + entity timeline (§13.5) ──────

CLASSIFIER_VERSION = "asset-fp-u7"

# §13.5 evidence strength: dhcp carries lease+MAC+hostname, arp a MAC binding,
# flow is IP-only. Ranking is total + deterministic (ties broken further below),
# so conflicting facts always resolve the same way regardless of arrival order.
SOURCE_RANK = {"dhcp": 3, "arp": 2, "flow": 1}
SOURCE_CONFIDENCE = {"dhcp": 0.9, "arp": 0.8, "flow": 0.4}

# Predicates derivable from EXISTING identity evidence only (no new fingerprints).
_FACT_FIELDS = ("hostname", "mac")


def derive_facts(obs: dict, obs_id: str, ts) -> list[dict]:
    """Turn one extract_evidence() row into §13.4 fact candidates. Each candidate is
    evidence-backed (source.observation_id pins it to the row). MAC is normalized
    lower so cross-sensor casing folds. No new passive-fingerprint predicates (U7
    defers those) — only hostname/mac from arp/dhcp identity evidence."""
    src = obs.get("src", "")
    conf = SOURCE_CONFIDENCE.get(src, 0.4)
    ts = _iso(ts)
    out: list[dict] = []
    for pred in _FACT_FIELDS:
        val = obs.get(pred)
        if pred == "mac" and val:
            val = val.lower()
        if not val:
            continue
        out.append({
            "predicate": pred, "value": val, "confidence": conf,
            "valid_from": ts, "valid_to": None, "expires": None,
            "source": {"type": src, "observation_id": obs_id},
            "method": src, "classifier_version": CLASSIFIER_VERSION,
        })
    return out


def identity_observation(obs: dict, obs_id: str, tenant: str, ts) -> dict:
    """Build the evidence-observation row for an identity (arp/dhcp) event, keyed by
    the SAME canonical obs_id the derived facts reference. arp/dhcp are NOT persisted
    by the normalizer (it types only flow/tls/dns/http), so without this the facts'
    source.observation_id would dangle — pointing at no stored row. asset-service
    persists this row (ndr.identity_observation, unioned into ndr.evidence_observations)
    so every fact's obs_id RESOLVES to real, retrievable evidence (§13.4), and the
    MAC's IP appears as a joinable entity value. Row shape mirrors the typed evidence
    tables' evidence columns (tenant_id, obs_id, normalized_time, entity_values,
    observation)."""
    entities = [{"type": "ip", "value": obs["ip"]}] if obs.get("ip") else []
    if obs.get("mac"):
        entities.append({"type": "mac", "value": obs["mac"].lower()})
    if obs.get("hostname"):
        entities.append({"type": "hostname", "value": obs["hostname"]})
    entity_values = [e["value"] for e in entities]
    doc = {"schema": "cernity.observation.v1", "obs_id": obs_id, "tenant": tenant,
           "type": obs.get("src", ""), "ts": {"normalized": _iso(ts)},
           "entities": entities, "capabilities": ["identity"],
           # lease_secs rides in the observation blob (no schema column) so restore_state
           # can replay this evidence and recover the ORIGINAL lease bound — not the
           # derived (capped) valid_to — reproducing intervals byte-identically (§13.4).
           "lease_secs": obs.get("lease_secs"),
           "source_ref": {"kind": "identity", "obs_id": obs_id}}
    return {"tenant_id": tenant, "obs_id": obs_id, "normalized_time": _iso(ts),
            "entity_values": entity_values,
            "observation": json.dumps(doc, sort_keys=True, separators=(",", ":"))}


def reconstruct_obs(doc: dict) -> dict:
    """Rebuild the extract_evidence() obs row from a persisted identity_observation doc
    so restore_state can REPLAY it through the exact fold path observe() uses. Carries
    the full reconstruction evidence: ip/mac/hostname entities, the source type, and the
    original lease_secs (so binding expiry is recomputed, not read back capped)."""
    ents: dict = {}
    for e in doc.get("entities", []):
        ents.setdefault(e.get("type"), e.get("value"))
    return {"ip": ents.get("ip"), "mac": ents.get("mac"),
            "hostname": ents.get("hostname"), "lease_secs": doc.get("lease_secs"),
            "src": doc.get("type", "")}


def resolve_conflict(candidates: list[dict]) -> dict:
    """Deterministically pick ONE value among candidates that conflict at the same
    normalized ts for the same predicate (§13.5): strongest source, then highest
    confidence, then lexicographically smallest value, then source type + the
    evidence obs_id. The last two keys make the order TOTAL — two candidates that
    tie on value/rank/confidence (e.g. two same-value DHCP records at one instant)
    still resolve to the same winner regardless of arrival order, so the recorded
    source/obs_id is reproducible, not whichever arrived first."""
    return min(candidates, key=lambda c: (
        -SOURCE_RANK.get(c["source"]["type"], 0),
        -c["confidence"],
        str(c["value"]),
        str(c["source"].get("type", "")),
        str(c["source"].get("observation_id", "")),
    ))


def _rebuild(by_ts: dict) -> list[dict]:
    """Rebuild a predicate's interval history from its per-instant winners. Walk in
    NORMALIZED-ts order and coalesce runs of equal values into one interval; a value
    change CLOSES the open interval (no overwrite) at the change instant — bounded by
    an earlier lease expiry if the closing interval carried one. A trailing open
    interval is closed at its lease expiry when it has one. Rebuilding from the full
    sorted set makes the result order-independent and late-event / replay safe."""
    items = sorted(by_ts.items(), key=lambda kv: _instant(kv[0]))
    intervals: list[dict] = []
    for ts, c in items:
        ts_i = _instant(ts)
        cur = intervals[-1] if intervals else None
        # Coalesce a run of the SAME value only while still inside the open
        # interval's (possibly lease-bounded) window. A same-value observation AT OR
        # AFTER the prior lease expiry is a re-acquisition across a lease GAP, not a
        # renewal — it must open a fresh interval so the gap is preserved and the MAC
        # is not attributed to the address during the lease it did not hold (§13.5).
        within = cur is not None and (cur["_expires"] is None or ts_i < _instant(cur["_expires"]))
        if cur is not None and cur["value"] == c["value"] and cur["valid_to"] is None and within:
            cur["confidence"] = max(cur["confidence"], c["confidence"])
            # renewal extends the lease-bounded end
            if c.get("expires") and (cur["_expires"] is None or _instant(c["expires"]) > _instant(cur["_expires"])):
                cur["_expires"] = c["expires"]
            continue
        if cur is not None and cur["valid_to"] is None:
            close = ts_i
            if cur["_expires"] and _instant(cur["_expires"]) < close:
                close = _instant(cur["_expires"])   # lease expired before the change / gap
            cur["valid_to"] = _iso(close)
        intervals.append({
            "value": c["value"], "valid_from": _iso(ts), "valid_to": None,
            "confidence": c["confidence"], "source": c["source"],
            "method": c.get("method"), "classifier_version": c.get("classifier_version"),
            "_expires": c.get("expires"),
        })
    if intervals and intervals[-1]["valid_to"] is None and intervals[-1]["_expires"]:
        intervals[-1]["valid_to"] = intervals[-1]["_expires"]   # trailing lease expiry
    for iv in intervals:
        iv.pop("_expires", None)
    return intervals


def fold_facts(state: dict, subject: str, cands: list[dict]) -> dict:
    """Fold fact candidates into `state` (subject -> predicate -> {ts -> winner}).
    Candidates competing at the SAME normalized ts for a predicate resolve
    deterministically (§13.5) before folding, so exactly one value wins per instant
    regardless of arrival order. Returns {predicate: [intervals]} for every predicate
    touched, so the caller re-emits its authoritative interval set (ReplacingMergeTree
    collapses re-emits). Never overwrites: a changed value opens a new interval."""
    facts = state.setdefault(subject, {})
    touched: dict[str, list[dict]] = {}
    by_pred: dict[str, list[dict]] = {}
    for c in cands:
        by_pred.setdefault(c["predicate"], []).append(c)
    for pred, group in by_pred.items():
        by_ts = facts.setdefault(pred, {})
        for c in group:
            ts = _iso(c["valid_from"])
            existing = by_ts.get(ts)
            by_ts[ts] = c if existing is None else resolve_conflict([existing, c])
        touched[pred] = _rebuild(by_ts)
    return touched


def rebuild_ip_ownership(bindings: dict) -> dict:
    """Rebuild the `ip` interval cache for EVERY MAC subject from the RAW leases — the SAME
    `bindings` resolve_mac()/owner_at attribute from — via ownership_intervals, so the cache
    and attribution can never disagree and the result is INDEPENDENT of arrival order (§13.5).
    Rebuilding from the FULL raw-lease set (not patching only the subject that just changed)
    is what makes it order-independent: chronological, reversed, and equal-time arrivals all
    converge to the same windows; a late reassignment inserted between two renewals splits
    ownership exactly as a restart-then-late-event replay does — because both feed owner_at
    the identical raw leases.

    Returns {subject: [ip intervals]} for every MAC subject that has ever claimed an IP; an
    empty list means it now owns none at any instant, so the caller tombstones its stale rows.

    ponytail: recomputes all IP owners on each binding change — fine at lab fact volumes;
    scope to the changed IP's claimant closure if a profile flags it."""
    owned: dict[str, list[dict]] = {
        "mac:" + c["mac"]: [] for leases in bindings.values() for c in leases}
    for ip, leases in bindings.items():
        for iv in ownership_intervals(ip, leases):
            owned.setdefault("mac:" + iv["mac"], []).append(
                {k: v for k, v in iv.items() if k != "mac"})
    for ivs in owned.values():
        ivs.sort(key=lambda iv: _instant(iv["valid_from"]))
    return owned


def build_timeline(observations: list[dict], fact_changes: list[dict],
                   entity: str | None = None, attribution: str | None = None) -> dict:
    """Merge an entity's observation stream and its fact-change history into one
    timeline ORDERED BY NORMALIZED ts (parsed to instants, not string-compared).
    At equal instants an observation precedes the fact it produced. Returns
    {entity, attribution, events, facts}; `attribution` flags IP-only (uncertain)
    resolution vs a MAC-bound entity (§13.5)."""
    events: list[dict] = []
    for o in observations:
        events.append({"kind": "observation", "ts": _iso(o["ts_normalized"]),
                       "obs_id": o.get("obs_id"), "type": o.get("type")})
    for f in fact_changes:
        events.append({"kind": "fact_change", "ts": _iso(f["valid_from"]),
                       "predicate": f["predicate"], "value": f["value"],
                       "valid_from": _iso(f["valid_from"]),
                       "valid_to": _iso(f.get("valid_to")),
                       "confidence": f["confidence"], "source": f["source"]})
    events.sort(key=lambda e: (_instant(e["ts"]),
                               0 if e["kind"] == "observation" else 1,
                               e.get("predicate", ""), e.get("obs_id") or ""))
    facts: dict[str, list[dict]] = {}
    for f in sorted(fact_changes, key=lambda x: _instant(x["valid_from"])):
        facts.setdefault(f["predicate"], []).append({
            "value": f["value"], "valid_from": _iso(f["valid_from"]),
            "valid_to": _iso(f.get("valid_to")),
            "confidence": f["confidence"], "source": f["source"]})
    return {"entity": entity, "attribution": attribution, "events": events, "facts": facts}


# ── read API ───────────────────────────────────────────────────────────────────
# entity id shape guard — bound the value so a malformed id is a clean 400, not a
# surprise scan. Covers ip / ipv6 (colons) / mac:… / ip:… keys.
_ENTITY_RE = _re.compile(r"^[A-Za-z0-9_.:%\-\[\]]{1,255}$")
_TIMELINE_LIMIT = 5000                          # bound both streams per entity read


def grants_for_token(tokens: dict, auth_header: str):
    """Caller's granted tenants, derived server-side from the bearer token (§21).
    None => unauthenticated. Tenant is NEVER a query/path param."""
    token = auth_header[7:] if (auth_header or "").startswith("Bearer ") else None
    return tokens.get(token) if token else None


def validate_entity(entity: str) -> str:
    if not entity or not _ENTITY_RE.match(entity):
        raise ValueError("entity is required and must be a valid identifier")
    return entity


def _authoritative(rows: list[dict]) -> list[dict]:
    """Select the authoritative version of each interval regardless of background
    merges: dedup ReplacingMergeTree rows by (tenant_id, subject, predicate, value,
    valid_from, observation_id) keeping the max updated_at; at equal updated_at a CLOSED
    interval (valid_to set) or a tombstone (is_deleted) wins over an open one. TENANT is
    part of the key so the SAME subject in two tenants is NEVER collapsed into one row
    (§21). VALUE is part of the key so a subject holding several values at one instant
    — a MAC that owns two IPs at the same lease start — keeps a distinct interval per
    value. OBSERVATION_ID (the lease/interval id) is part of the key so two SAME-START
    intervals for ONE ip (distinct leases at one instant) also stay distinct instead of
    collapsing to whichever version sorted last — this mirrors the table's ORDER BY
    exactly. A key whose winning version is a tombstone (is_deleted) is dropped — that
    interval was removed by an idempotent rebuild and must not resurface (§13.4); its
    tombstone therefore carries the same value AND observation_id so it lands on the same key."""
    best: dict = {}
    for r in rows:
        key = (r.get("tenant_id"), r.get("subject"), r["predicate"],
               r.get("value"), _iso(r["valid_from"]), r.get("observation_id"))
        cur = best.get(key)
        if cur is None:
            best[key] = r
            continue
        ru, cu = r.get("updated_at"), cur.get("updated_at")
        # a row supersedes when it is newer, or ties on updated_at but is more
        # "final" (closed/deleted beats open) — deterministic tie-break.
        r_final = bool(r.get("valid_to")) or bool(r.get("is_deleted"))
        cur_final = bool(cur.get("valid_to")) or bool(cur.get("is_deleted"))
        if ru is not None and cu is not None:
            if _instant(ru) > _instant(cu) or (_instant(ru) == _instant(cu) and r_final and not cur_final):
                best[key] = r
        elif r_final and not cur_final:
            best[key] = r
    return [r for r in best.values() if not r.get("is_deleted")]


def _ip_windows(entity: str, facts: list[dict]) -> tuple[list[tuple], str]:
    """The (ip, valid_from, valid_to) windows to join this entity's observations to,
    plus an attribution flag. A MAC entity joins only within its temporal IP-binding
    windows (§13.5 — no cross-time address reuse); an IP entity joins that IP over
    all time but is flagged uncertain."""
    if entity.startswith("mac:"):
        wins = [(f["value"], f["valid_from"], f.get("valid_to"))
                for f in facts if f["predicate"] == "ip"]
        return wins, "mac-bound"
    if entity.startswith("ip:"):
        return [(entity[3:], None, None)], "ip-only"
    return [(entity, None, None)], "ip-only"


def _in_window(obs: dict, windows: list[tuple]) -> bool:
    ts = _instant(obs["ts_normalized"])
    for ip, vf, vt in windows:
        if ip in obs.get("entity_values", []):
            if (vf is None or _instant(vf) <= ts) and (vt is None or ts < _instant(vt)):
                return True
    return False


def fetch_timeline(client, grants, entity: str) -> dict:
    """Read one entity's timeline from ClickHouse, scoped STRICTLY PER TENANT.

    A caller granted several tenants gets a separate timeline per tenant under
    `tenants[<tenant>]`; facts and observations are NEVER merged across tenants —
    the same subject / IP in two tenants is two independent entities (§21). Each
    tenant is queried on its own so no cross-tenant row can enter another tenant's
    result. Facts are read with authoritative versioning (closed/tombstoned rows
    supersede open ones); observations are joined via the entity's temporal
    IP-binding windows (§13.5), never by raw asset-key equality. entity/ips are
    bound parameters, never interpolated. The live SQL is verified in the real env;
    the merge/window/version logic here is unit-tested against a fake client."""
    return {"entity": entity,
            "tenants": {t: _timeline_for_tenant(client, t, entity) for t in grants}}


def _timeline_for_tenant(client, tenant: str, entity: str) -> dict:
    fact_sql = (
        "SELECT tenant_id, subject, predicate, value, valid_from, valid_to, "
        "confidence, source_type, observation_id, is_deleted, updated_at "
        "FROM ndr.asset_fact FINAL "
        "WHERE tenant_id = {tenant:String} AND subject = {entity:String} "
        "AND is_deleted = 0 ORDER BY predicate, valid_from LIMIT {limit:UInt32}")
    fp = {"tenant": tenant, "entity": entity, "limit": _TIMELINE_LIMIT}
    fact_rows = _authoritative(_rows(client.query(fact_sql, parameters=fp)))
    fact_changes = [{"predicate": r["predicate"], "value": r["value"],
                     "valid_from": r["valid_from"], "valid_to": r.get("valid_to"),
                     "confidence": r["confidence"],
                     "source": {"type": r.get("source_type", ""),
                                "observation_id": r.get("observation_id", "")}}
                    for r in fact_rows]

    windows, attribution = _ip_windows(entity, fact_changes)
    ips = sorted({ip for ip, _vf, _vt in windows})
    observations: list[dict] = []
    if ips:
        obs_sql = (
            "SELECT obs_id, normalized_time, type, entity_values "
            "FROM ndr.evidence_observations "
            "WHERE tenant_id = {tenant:String} "
            "AND hasAny(entity_values, {ips:Array(String)}) "
            "ORDER BY normalized_time, obs_id LIMIT {limit:UInt32}")
        op = {"tenant": tenant, "ips": ips, "limit": _TIMELINE_LIMIT}
        for r in _rows(client.query(obs_sql, parameters=op)):
            obs = {"obs_id": r["obs_id"], "ts_normalized": r["normalized_time"],
                   "type": r["type"], "entity_values": list(r.get("entity_values") or [])}
            if _in_window(obs, windows):     # exclude activity outside the binding window
                observations.append(obs)
    return build_timeline(observations, fact_changes, entity=entity, attribution=attribution)


def fetch_relationships(client, grants, entity: str) -> dict:
    """Read one entity's observed relationship edges from ClickHouse, scoped STRICTLY
    PER TENANT (§21), mirroring fetch_timeline. An edge is returned whether the entity
    is the src OR the dst endpoint. Each edge's evidence JSON is decoded back to an
    object for the caller. entity is a bound parameter, never interpolated; the live
    SQL is verified in the real env, the per-tenant scoping is unit-tested with a fake
    client."""
    return {"entity": entity,
            "tenants": {t: _relationships_for_tenant(client, t, entity) for t in grants}}


def _relationships_for_tenant(client, tenant: str, entity: str) -> list[dict]:
    sql = (
        "SELECT tenant_id, src_entity, dst_entity, kind, first_seen, last_seen, evidence "
        "FROM ndr.entity_relationship FINAL "
        "WHERE tenant_id = {tenant:String} "
        "AND (src_entity = {entity:String} OR dst_entity = {entity:String}) "
        "ORDER BY src_entity, dst_entity, kind LIMIT {limit:UInt32}")
    fp = {"tenant": tenant, "entity": entity, "limit": _TIMELINE_LIMIT}
    edges: list[dict] = []
    for r in _rows(client.query(sql, parameters=fp)):
        ev = r.get("evidence")
        if isinstance(ev, str) and ev:
            try:
                ev = json.loads(ev)
            except ValueError:
                pass                                   # keep the raw string if not JSON
        edges.append({"src_entity": r["src_entity"], "dst_entity": r["dst_entity"],
                      "kind": r["kind"], "first_seen": _iso(r["first_seen"]),
                      "last_seen": _iso(r["last_seen"]), "evidence": ev})
    return edges


def _rows(result) -> list[dict]:
    return [dict(zip(result.column_names, r)) for r in result.result_rows]
