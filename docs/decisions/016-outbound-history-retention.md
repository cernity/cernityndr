# 016: outbound history is a retained archive, not disposable window state

Status: implemented behind a disabled flag; pending independent review and live
Redis/build gates.

U0 retains one compact row per `(tenant, cohort, entity, window_start)` for 28
days in the shared store seam. The schema has its own `ob:v1:` namespace. The
key hashes JSON identity components so delimiters, IPv6, and tenant glob
characters cannot collide. Historical scoring needs only tenant, cohort, entity,
start, end, and bytes_out; per-flow evidence remains on the current row.

`kv_set_once` uses first-writer-wins and a millisecond TTL in both backends.
Replay cannot replace a row or refresh its deadline. The model derives TTL from
window end plus retention, not arrival time; already expired replay is ignored.
This synchronous primitive returns whether it won, and is not part of the
fire-and-forget `pipeline_ops` flush. Existing store operations are unchanged.

The 288-window scoring lookback, feature window width, median/MAD, thresholds,
and explanations are unchanged. Keeping four weeks does NOT start scoring four
weeks: U1 must deliberately select its seasonal samples from the retained rows.
This distinction is necessary to make U0 parity measurable. All same-window rows
remain ineligible (`end <= scored.start`), including rows another replica has
already learned. Two replicas cannot create two samples for the same identity.
This does not merge partial feature aggregates: upstream routing must give each
entity window to one owner. First writer wins assumes a complete, closed row.

## Capacity evidence and the durability decision

The plain-assert volume test actually inserts 29 days of synthetic entity-window
rows into InMemoryStore, advances its clock, and prunes daily. It observes
**806,400 live keys** after the extra day, never more at daily boundaries.
The workload is a stated sizing scenario, not captured production traffic:
100 continuously active entities at one conn/s/entity = 100 events/s, or
241,920,000 input events over four weeks. Aggregation yields
100 × (86,400 / 300) × 28 = **806,400 rows**. The ceiling is a workload bound,
not an admission cap: a larger deployment needs separate sizing, never silent
sample dropping. Expired InMemoryStore entries are lazy; tests explicitly call
kv_prune, whereas Redis removes expired keys itself.

A serialization measurement of the fixture with ten-digit epoch timestamps is
146 key bytes plus 182 JSON bytes = 328 bytes/row, or
806,400 × 328 = **264,499,200 bytes (~252.2 MiB)** of raw key/value payload.
The key includes a ten-digit window timestamp. This measures JSON and key bytes, not Redis resident memory.
Redis allocator, dictionary, expiry and replication/AOF overhead are additional;
there is no measured Redis RSS figure in this environment. The synthetic count
also does not establish scan latency or production throughput.

**Decision: the existing ephemeral deployment is insufficient for material
history.** Row count is tractable for a dedicated Redis instance, but a TTL does
not provide durability. U1/U4/U5 require a persistent, backed-up backend before
relying on this archive. A dedicated Redis with AOF on persistent storage,
noeviction, monitored capacity, backup/restore drills and a documented recovery
point is the deployment prerequisite; alternatively implement a durable database
behind the same seam. Never apply the store module's old “flush ephemeral DB on
upgrade” advice to this namespace. U0 does not change other services or deploy
infrastructure. Data loss/recovery guarantees have not been demonstrated here.

The current lookup uses cohort-scoped SCAN plus row GETs. It is intentionally a
small initial seam, not a fleet-scale throughput claim: it scans the Redis DB
once per cohort/window. The timestamp in each key limits GETs to the unchanged
scoring lookback; every entity in the batch uses one cohort snapshot. Measure
this at target cardinality before enabling; an indexed/batched range lookup is
required if it misses the five-minute processing budget. The capacity test is
not a latency benchmark.

## Rollout and verification

`OUTBOUND_HISTORY_STORE=0` (default/unset) keeps the old in-process path.
`OUTBOUND_HISTORY_STORE=1` requires `OUTBOUND_HISTORY_REDIS_URL` pointing at the
persistent instance. There is no silent memory fallback: connection/read/write
errors propagate. Retention is 28 days; history_windows remains 288. Changing
the default requires parity, restart, TTL, concurrent-write and live backend
contract gates, a persistent-backend recovery drill, and target-load timing.

Run `PYTHONPATH=shared python services/anomaly-detector/test_anomaly.py` and
`PYTHONPATH=shared python shared/test_store.py`. Set `NDR_TEST_REDIS_URL` to a
**disposable database** to exercise the real Redis assertions (tests flush it).
The new contract fails, rather than skips, when an explicitly configured Redis
cannot be reached. The anomaly image now runs all tests, including those that
previously appeared below its premature main block; jsonschema is installed
only into a temporary build-test directory, not added as a runtime dependency.
