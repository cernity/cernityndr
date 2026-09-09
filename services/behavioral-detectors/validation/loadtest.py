#!/usr/bin/env python3
"""Single-server load / ceiling harness (plan 003 U7; extends the U-plan load
test). Drives synthetic src-keyed flows, simulates P Kafka partitions across R
co-located replicas, and reports:

  - per-core ingest rate (records/sec through one _handle loop)
  - per-partition record distribution + skew ratio (a hot src => a hot partition
    => one replica saturates while others idle; do NOT read aggregate rate as the
    ceiling without checking this -- plan 003 U2 doc-review finding)
  - per-replica scoped evaluate() cost vs the old scan-all cost (the U4 win)
  - a bottleneck verdict (cpu / bus / redis / headroom)

  python loadtest.py --n 50000 --partitions 32 --replicas 8
  python loadtest.py --backend redis --redis unix:///sock/redis.sock?db=0 ...
  python loadtest.py --selfcheck        # tiny run + classifier assertions (CI)

A full multi-process run is `docker compose up -d --scale behavioral-detectors=R`
against one Redis + a 32-partition topic; this harness measures the per-core and
per-replica shape in one process so the ceiling is knowable without the full stack.
"""
import argparse
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _part(src: str, partitions: int) -> int:
    """Stable partition for a src key (stands in for the broker's key hash; the
    real bus uses murmur2, but any stable hash exercises skew + scoping here)."""
    return int(hashlib.sha1(src.encode()).hexdigest(), 16) % partitions


def classify_ceiling(cpu_saturated: bool, lag_growing: bool, redis_saturated: bool) -> str:
    """What caps this single box. redis first (shared dependency), then a starved
    bus (replicas idle yet lag grows), then CPU (workers maxed => add replicas/
    cores), else headroom (load can grow)."""
    if redis_saturated:
        return "redis-bound"
    if lag_growing and not cpu_saturated:
        return "bus-bound"
    if cpu_saturated:
        return "cpu-bound"
    return "headroom"


def _run(n, partitions, replicas, backend, redis_url):
    os.environ["NDR_STATE_BACKEND"] = backend
    os.environ["NDR_REDIS_URL"] = redis_url
    os.environ.setdefault("NDR_CONFIG_TOPIC_DISABLE", "1")
    import app, store
    app._store = store.make_store(backend, redis_url)
    p = type("P", (), {"send": lambda s, t, v: None, "flush": lambda s: None})()
    now = time.time()

    per_part = [0] * partitions
    t0 = time.time()
    for i in range(n):
        src = f"10.0.{i % 250}.{i % 200}"
        part = _part(src, partitions)
        per_part[part] += 1
        app._handle({"event_type": "flow", "src_ip": src,
                     "dest_ip": f"203.0.113.{i % 250}", "timestamp": None,
                     "flow": {"bytes_toserver": 200, "bytes_toclient": 300, "age": 1}},
                    p, now, part)
    ingest = time.time() - t0
    rps = n / ingest if ingest else 0

    # assign partitions round-robin to replicas; time each replica's SCOPED
    # evaluate vs the old scan-all, to show per-replica cost is bounded by its share
    assign = {r: {q for q in range(partitions) if q % replicas == r} for r in range(replicas)}
    # Time the per-replica SCOPED passes FIRST, on the freshly-planted store, so
    # they are not advantaged by scan-all having already populated dedup/pruned
    # (plan 003 U4 review). Replicas own disjoint partitions, so no cross-dedup
    # between them. Single-sample, directional -- for exact numbers run several.
    per_replica = []
    for r in range(replicas):
        tr = time.time(); app.evaluate(p, flow_parts=assign[r], dns_parts=set())
        per_replica.append(time.time() - tr)
    te = time.time(); app.evaluate(p); scan_all = time.time() - te      # unscoped (old behavior)

    # enumeration cost: index (SMEMBERS assigned partitions) vs scan (whole
    # prefix) for one replica (plan 004 U4). On Redis the scan grows with the
    # keyspace while the index stays bounded by the replica's share; on memory
    # both are cheap dict ops, so the win only shows on --backend redis.
    r0 = assign[0]
    _si = app.ENUM_INDEX
    app.ENUM_INDEX = True                               # measure the index path explicitly
    ti = time.time()
    for pfx in ("bc:", "bf:", "dn:"):
        app._scoped_keys(pfx, r0)                       # index (ENUM_INDEX default on)
    enum_index = time.time() - ti
    _saved = app.ENUM_INDEX
    app.ENUM_INDEX = False
    try:
        tsc = time.time()
        for pfx in ("bc:", "bf:", "dn:"):
            app._scoped_keys(pfx, r0)                   # scan whole prefix + filter
        enum_scan = time.time() - tsc
    finally:
        app.ENUM_INDEX = _si

    hi, lo = max(per_part), min(per_part)
    skew = (hi / (sum(per_part) / partitions)) if sum(per_part) else 0
    return {"rps": rps, "ingest": ingest, "scan_all_s": scan_all,
            "per_replica_s": per_replica, "per_part_hi": hi, "per_part_lo": lo,
            "skew_ratio": skew, "enum_index_s": enum_index, "enum_scan_s": enum_scan,
            "keys": (app._store._r.dbsize() if backend == "redis" else None)}


def _report(n, partitions, replicas, backend, m):
    print(f"backend={backend}  records={n:,}  partitions={partitions}  replicas={replicas}")
    print(f"  per-core ingest : {m['ingest']:.2f}s  ->  {m['rps']:,.0f} records/sec")
    print(f"  partition skew  : hi={m['per_part_hi']} lo={m['per_part_lo']} "
          f"ratio={m['skew_ratio']:.2f}x  (>~1.5x => a hot src caps a replica; not cpu headroom)")
    avg_r = sum(m["per_replica_s"]) / len(m["per_replica_s"])
    print(f"  evaluate()      : scan-all={m['scan_all_s']*1000:.1f}ms  "
          f"per-replica-scoped avg={avg_r*1000:.1f}ms  (scoped ~ scan-all / replicas -- the U4 win)")
    print(f"  enumeration     : index={m['enum_index_s']*1000:.2f}ms  scan={m['enum_scan_s']*1000:.2f}ms  "
          f"(index bounded by the replica's share; scan grows with the keyspace -- the win shows on redis)")
    if m["keys"] is not None:
        print(f"  redis keys      : {m['keys']:,}")


def demo():
    # classifier truth table
    assert classify_ceiling(False, False, True) == "redis-bound"
    assert classify_ceiling(False, True, False) == "bus-bound"
    assert classify_ceiling(True, True, False) == "cpu-bound"
    assert classify_ceiling(True, False, False) == "cpu-bound"
    assert classify_ceiling(False, False, False) == "headroom"
    # partitioning spreads srcs and is stable
    assert _part("10.0.0.1", 32) == _part("10.0.0.1", 32)
    assert len({_part(f"10.0.0.{i}", 32) for i in range(64)}) > 1
    # a tiny end-to-end run completes and reports a well-formed shape
    m = _run(200, partitions=8, replicas=2, backend="memory", redis_url="redis://localhost:6379/0")
    assert m["rps"] > 0 and len(m["per_replica_s"]) == 2 and m["skew_ratio"] > 0
    print("loadtest selfcheck passed")


def _writer(worker, n, partitions, backend, redis_url, redis_urls):
    # one writer process: its own store connection, n window_add_indexed writes.
    os.environ["NDR_STATE_BACKEND"] = backend
    os.environ["NDR_REDIS_URL"] = redis_url
    if redis_urls:
        os.environ["NDR_REDIS_URLS"] = redis_urls
    import store, time as _t
    st = store.make_store(backend, redis_url)
    t0 = _t.time()
    for i in range(n):
        src = f"10.{worker}.{i % 250}.{i % 200}"
        part = _part(src, partitions)
        st.window_add_indexed(f"bc:{part}:t:{src}|d", f"idx:bc:{part}", _t.time(), 1, 600)
    return n / (_t.time() - t0)


def concurrent_bench(writers, n_each, partitions, backend, redis_url, redis_urls):
    # aggregate throughput of `writers` CONCURRENT writer processes. This is what
    # sharding helps: N clients on one single-threaded Redis serialize; N shards
    # let N Redis processes run in parallel (plan 005).
    import multiprocessing as mp
    t0 = time.time()
    with mp.Pool(writers) as pool:
        pool.starmap(_writer, [(w, n_each, partitions, backend, redis_url, redis_urls)
                               for w in range(writers)])
    wall = time.time() - t0
    total = writers * n_each
    print(f"backend={backend}  concurrent writers={writers} x {n_each:,} = {total:,} writes")
    print(f"  aggregate: {total / wall:,.0f} writes/sec  (wall {wall:.2f}s)  "
          f"[{'N shards parallelize' if backend == 'sharded' else '1 Redis serializes'}]")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20000)
    ap.add_argument("--partitions", type=int, default=32)
    ap.add_argument("--replicas", type=int, default=8)
    ap.add_argument("--backend", default="memory")
    ap.add_argument("--redis", default="redis://localhost:6379/0")
    ap.add_argument("--selfcheck", action="store_true")
    ap.add_argument("--writers", type=int, default=0, help="concurrent multi-writer bench (plan 005 sharding proof)")
    a = ap.parse_args()
    if a.selfcheck:
        demo()
        return
    if a.writers:
        concurrent_bench(a.writers, a.n, a.partitions, a.backend, a.redis,
                         os.environ.get('NDR_REDIS_URLS', ''))
        return
    m = _run(a.n, a.partitions, a.replicas, a.backend, a.redis)
    _report(a.n, a.partitions, a.replicas, a.backend, m)


if __name__ == "__main__":
    main()
