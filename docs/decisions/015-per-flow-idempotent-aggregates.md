# 015: per-flow idempotent aggregates — stop accumulating cumulative flow counters

Status: implemented, pending independent review.

`behavioral-detectors` buffered four accumulating increments per `flow` record —
exfil bytes, exfil connection count, cumulative long-connection seconds, connection
count — which resolved to Redis `HINCRBYFLOAT`. That is not idempotent, and two
things make the same record arrive twice:

- **Redelivery.** `shared/ndr_runtime.py` sets `enable_auto_commit=True`, so offsets
  commit on a poll timer independently of processing. A crash, restart or
  consumer-group rebalance re-delivers already-processed records.
- **Cumulative interim records.** `flow.bytes_toserver` and `flow.age` are CUMULATIVE
  per flow. Where a deployment emits more than one flow record for the same flow, each
  record's FULL cumulative value was added again.

The consequence was not a duplicate finding — the emit dedup in `_candidate` collapses
those. It was worse: inflated counters push BENIGN traffic over the exfil byte
threshold and the cumulative long-connection threshold, so a FALSE finding is
manufactured and then faithfully delivered once. The same flaw in a different shape
affected `exb:`, the per-flow bytes evidence behind `low_slow_exfil`'s `material_flows`:
as a ZSET of `(event time, bytes)` members, two interim records for one flow became two
"material flows".

## Decision

Stop accumulating. Store each flow's LATEST CUMULATIVE value as one hash field keyed by
flow identity, written blind (last-write-wins), and DERIVE the aggregate at read time in
`evaluate()`, where the threshold checks already live:

| aggregate | derivation |
|---|---|
| exfil bytes | `SUM` of the `exf:` field values |
| connection count | `COUNT` of the `exf:` fields |
| cumulative long-conn seconds | `SUM` of the `lcf:` field values |
| material flows (§49.4) | `COUNT` of `exf:` fields `>= exfil_material_flow_bytes` |

A blind set is idempotent under redelivery, correct for interim records (a later record
overwrites with the higher cumulative value), and handles a counter RESET for free — a
lower value is simply the current truth for that flow. `exb:` is deleted: its evidence
IS the `exf:` field values, and reading it there also aligns the evidence with the total
it qualifies instead of keeping two differently-windowed structures.

### Rolling upgrade: a new keyspace, not a new meaning for an old one

The hash SHAPE is unchanged but the SCHEMA is not — a field used to be a counter name
(`ex:` `b`/`c`, `lc:` `s`/`n`) and is now a flow identity. Redis holds live window state
across a deploy, so reading the old keys with the new code would see `b` = 30 MB as one
"flow" and `c` = 1 as another and could re-manufacture the very finding this fixes. So
the derived state lives under its OWN prefixes, `exf:` / `lcf:` (and their own `idx:`
index keys): the two schemas never share a key, in either direction, so a ROLLBACK also
reads only its own keys. The pre-upgrade `ex:` / `lc:` / `exb:` keys are never read again
and expire within one WINDOW on the TTL they already carry. Cost of the rename, accepted:
aggregates in flight at the moment of the deploy restart from zero for one window.

**This preserves plan 007's write-only property.** `_handle` issues zero synchronous
Redis round-trips in steady state; the new write is a buffered `fset` op flushed in the
same single pipelined round-trip per poll-batch. The rejected alternatives both break
something: reading per-flow state synchronously per record destroys plan 007, and an
in-process last-seen map is empty exactly when it is needed most (a restart).

**What this guarantees:** the derived aggregates are unchanged by replay and by repeated
interim records. **What it does not:** it is NOT exactly-once delivery. Consumer
semantics are untouched on purpose — the fix makes the aggregate idempotent rather than
chasing exactly-once.

`counter_add` / `counter_get` are kept intact: the ssh/icmp rate counters in
`protocol-detectors` legitimately want accumulation.

## Flow identity

`flow_id` is a Suricata-INSTANCE-local correlation key, not globally unique, so it is
never used alone. `app._flow_identity` resolves, most to least specific:

1. **`(sensor, flow_id)`** — sensor from `host` / `sensor_id`, the fields the normalizer
   already trusts, because two sensors can mint the same `flow_id` for unrelated flows.
   Used ONLY when BOTH are present: a record with a `flow_id` but no sensor falls
   through to 2/3 rather than merging every sensor's `flow_id` 5 into one field.
2. **`(sensor, community_id, flow.start, flow_id)`** — `community_id` hashes the 5-TUPLE,
   so a pair that reconnects on the same ports REUSES it; the flow's own start time
   separates those genuinely distinct flows, while interim records of one flow share all
   four and collapse. `flow_id` is included when the record carries one but no sensor: it
   can only split an identity further, never merge two. The sensor is carried here too
   even though it alone was not enough to reach 1 — two sensors taping either side of a
   hop see the same 5-tuple and the same start, so dropping it would merge their records
   into one field and the second would overwrite the first, an UNDER-count (review fix).
3. **A synthetic digest** over what the record does carry (sensor, 5-tuple, proto,
   flow start, flow_id).

The fallback is deliberately conservative in the OVER-counting direction: including the
start time means the worst case is treating one flow as two (today's behavior), never
merging two flows into one — which would make the detector blind, the dangerous failure.
Nothing is fabricated; a record with no identifier lands on a digest of its own fields.
Known ceiling: with neither `flow_id` nor `flow.start` the digest falls back to the EVE
emit timestamp, so interim records of such a record shape can still split (Suricata does
not emit that shape).

## Cardinality, bounded explicitly

An accumulating counter was O(1) per (src,dst) pair; per-flow fields are O(flows per
pair per window), so a chatty pair grows the hash. `NDR_FLOW_IDENTITY_CAP` (default
**2048**) bounds it: 2048 flows in a 600s window is ~3.4 flows/s sustained to ONE
destination — a pair that chatty is already strobe/beacon territory — and holds a pair's
hash to roughly 100 KB.

Once the cap binds, the derived aggregate is a **FLOOR**, and that is stated rather than
hidden — but stated for exactly what is counted. `store.field_set` counts refused
**WRITES** in a reserved `#refused` field (inside the hash, so it survives a restart and
is read back with the aggregate). It cannot count distinct omitted flows: the write path
takes no read, by design, so it cannot tell a new identity from one it already refused,
and a redelivered refused record is refused and counted again. So the number is an upper
bound on refusals and means only "at least one flow is missing from this total". It is
therefore reported as what it is: `evaluate()` logs "N per-flow writes refused (>=1 flow
omitted)", exports `ndr_flow_cap_refused_updates{prefix}` (a gauge: the stored count is
cumulative within a tumbling window, so re-adding it each cycle would over-count), and
attaches `flow_updates_refused_at_cap` to the finding — never a flow count. Nothing is
dropped silently. Bounded distinct-overflow accounting was rejected: it needs a second
bounded structure per pair to earn a number no decision depends on, since the finding
already says "floor".

The cap is enforced server-side in Redis by a small Lua script inside the existing
pipeline, because enforcing it in the client would mean a read turnaround per record —
the exact cost plan 007 removed. The script is invoked as a queued `SCRIPT LOAD` +
`EVALSHA` pair, NOT via redis-py's `register_script`: a registered `Script` queued on a
pipeline makes `Pipeline.execute` issue an immediate `SCRIPT EXISTS` first (redis-py 8.1
`client.py` `load_scripts`), which is a second synchronous round-trip per poll-batch —
the cost plan 007 exists to avoid. Queueing the load ahead of the `EVALSHA`s in the same
pipeline keeps it at one round-trip and also rules out `NOSCRIPT` after a Redis restart
or `SCRIPT FLUSH`, at the cost of the ~200-byte script body once per batch.
`InMemoryStore` implements identical semantics, `shared/test_store.py` asserts the two
backends agree (including the cap and the batched `fset` op), and a command-level test
there pins the one-execute/no-preflight behavior rather than trusting inspection.

Refusals are reported before any early exit in `evaluate()`, and a key is pruned from its
partition index only when its state is ABSENT — not when its sum is zero. A zero-byte
flow can be the one the cap admits, after which every real flow is refused; the aggregate
is then 0 and there is no finding to carry the evidence, so the gauge and the log are the
only report of the loss and must still fire. Pruning on a zero sum would additionally
unindex live state, hiding the overflow for the rest of the window (review fix).

TTL/window semantics are unchanged: the per-flow hash tumbles on the first write exactly
as the counter did (F05).
