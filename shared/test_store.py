"""WindowStore contract tests (plan U1). The SAME assertions run against
InMemoryStore and (when a Redis is reachable) RedisStore, proving the Redis
backend is equivalent to the in-memory one before app.py is switched over.
"""
import os
import time

import store as st


def _backends():
    """Yield (name, store) for each available backend. Redis is included only
    when NDR_TEST_REDIS_URL is set and reachable, so the build gate stays offline."""
    yield "memory", st.InMemoryStore()
    url = os.environ.get("NDR_TEST_REDIS_URL")
    if url:
        try:
            r = st.RedisStore(url)
            r._r.ping()
            r._r.flushdb()
            yield "redis", r
        except Exception as e:
            print(f"  (redis backend skipped: {e})")


def _check(s, name):
    # window: time-ordered, prunes below min_score
    for i in range(5):
        s.window_add("w:a", float(i * 60), i, ttl=600)
    rng = s.window_range("w:a", min_score=0)
    assert [v for _, v in rng] == [0, 1, 2, 3, 4], f"{name}: window order"
    rng2 = s.window_range("w:a", min_score=180)     # prune older than score 180
    assert [sc for sc, _ in rng2] == [180.0, 240.0], f"{name}: window prune"

    # counter: accumulate + read back + clear
    assert s.counter_add("c:x", "bytes", 100, ttl=600) == 100
    assert s.counter_add("c:x", "bytes", 50, ttl=600) == 150
    assert s.counter_get("c:x", "bytes") == 150, f"{name}: counter"
    s.counter_clear("c:x")
    assert s.counter_get("c:x", "bytes") == 0, f"{name}: counter clear"

    # capped set: never exceeds cap+1, membership + len
    for i in range(20):
        s.set_add("s:d", f"src{i}", ttl=600, cap=5)
    assert s.set_len("s:d") <= 6, f"{name}: set cap"
    s.set_add("s:known", "1.2.3.4", ttl=600)
    assert s.set_contains("s:known", "1.2.3.4") and not s.set_contains("s:known", "9.9.9.9"), f"{name}: set contains"

    # kv
    s.kv_set("kv:ip", ["evil.com", 123.0], ttl=600)
    assert s.kv_get("kv:ip") == ["evil.com", 123.0], f"{name}: kv"
    assert s.kv_get("kv:missing") is None, f"{name}: kv miss"

    # dedup: true once, false within ttl
    assert s.dedup_seen("dd:k", ttl=600) is True, f"{name}: dedup first"
    assert s.dedup_seen("dd:k", ttl=600) is False, f"{name}: dedup repeat"


def test_contract_both_backends():
    ran = 0
    for name, s in _backends():
        _check(s, name)
        print(f"ok  contract [{name}]")
        ran += 1
    assert ran >= 1


def test_inmemory_ttl_expiry():
    # a stale window key expires (lazy) rather than persisting forever (the leak fix)
    clk = [1000.0]
    s = st.InMemoryStore(clock=lambda: clk[0])
    s.window_add("w:t", 1000.0, "x", ttl=60)
    s.counter_add("c:t", "b", 5, ttl=60)
    clk[0] = 1200.0                                  # advance past ttl
    assert s.window_range("w:t", 0) == [], "expired window cleared"
    assert s.counter_get("c:t", "b") == 0, "expired counter cleared"


def test_inmemory_restart_survival_is_backend_property():
    # the in-memory store does NOT survive a handle drop (that is why redis exists);
    # this documents the contract: a fresh InMemoryStore starts empty.
    s1 = st.InMemoryStore(); s1.window_add("w:r", 1.0, "a", ttl=600)
    s2 = st.InMemoryStore()
    assert s2.window_range("w:r", 0) == []


def test_make_store_selects_backend():
    assert isinstance(st.make_store("memory"), st.InMemoryStore)


def test_set_members_and_remove():
    """set_members/set_remove (plan 004 U1) equivalent on both backends."""
    for name, s in _backends():
        s.set_add("t4:idx", "a", 60)
        s.set_add("t4:idx", "b", 60)
        assert set(s.set_members("t4:idx")) == {"a", "b"}, name
        s.set_remove("t4:idx", "a")
        assert set(s.set_members("t4:idx")) == {"b"}, name
        s.set_remove("t4:idx", "missing")                     # absent member: no error
        assert s.set_members("t4:neverwritten") == [], name   # unwritten key: [] (no create)
        s.set_add("t4:idx", "2001:db8::1|2001:db8::2", 60)    # ':' and '|' members
        assert "2001:db8::1|2001:db8::2" in s.set_members("t4:idx"), name
        print(f"  ok set_members/set_remove [{name}]")


def test_window_add_indexed():
    """window_add_indexed (plan 004 review): one call writes the window AND the
    index member, equivalent on both backends."""
    for name, s in _backends():
        s.window_add_indexed("bc:0:t:a|b", "idx:bc:0", 100.0, 1, 60)
        assert s.window_range("bc:0:t:a|b", 0) == [(100.0, 1)], name
        assert s.set_members("idx:bc:0") == ["bc:0:t:a|b"], name
        print(f"  ok window_add_indexed [{name}]")


def test_shard_routing():
    for n in (2, 3, 4):                                        # partition + its index co-locate
        assert st._shard_of("bc:3:homelab:a|b", n) == st._shard_of("idx:bc:3", n), n
        assert st._shard_of("nx:5:homelab:c", n) == st._shard_of("idx:nx:5", n), n
        assert st._shard_of("pv:homelab:1.2.3.4", n) == st._shard_of("pv:homelab:1.2.3.4", n)
    assert st._shard_of("bc:7:homelab:2001:db8::1|2001:db8::2", 4) == 7 % 4   # IPv6 routes by partition
    print("  ok shard routing")


def test_sharded_contract():
    sh = st.ShardedRedisStore([st.InMemoryStore() for _ in range(3)])
    sh.window_add_indexed("bc:2:t:a|b", "idx:bc:2", 100.0, 5, 60)
    assert sh.window_range("bc:2:t:a|b", 0) == [(100.0, 5)]
    assert sh.set_members("idx:bc:2") == ["bc:2:t:a|b"]       # index co-located + readable
    assert sh.counter_add("ex:t:x|y", "b", 10, 60) == 10
    assert sh.counter_get("ex:t:x|y", "b") == 10
    assert sh.dedup_seen("emit:t:d:1:9", 60) is True
    assert sh.dedup_seen("emit:t:d:1:9", 60) is False
    sh.window_add("bc:0:t:c|d", 1.0, 1, 60)
    ks = set(sh.keys_matching("bc:"))
    assert "bc:2:t:a|b" in ks and "bc:0:t:c|d" in ks          # union across shards
    print("  ok sharded contract")


def test_window_add_indexed_batch():
    """Batched window writes (plan 006) == individual, on both backends + sharded."""
    stores = [("memory", st.InMemoryStore()),
              ("sharded-mem", st.ShardedRedisStore([st.InMemoryStore() for _ in range(3)]))]
    for name, s in stores:
        items = [(f"bc:{p}:t:e{p}", f"idx:bc:{p}", 100.0 + p, p, 60) for p in range(6)]
        s.window_add_indexed_batch(items)
        for p in range(6):
            assert s.window_range(f"bc:{p}:t:e{p}", 0) == [(100.0 + p, p)], name
            assert f"bc:{p}:t:e{p}" in s.set_members(f"idx:bc:{p}"), name
        s.window_add_indexed_batch([])                       # empty -> no-op
        # idx_key=None -> plain window, no index
        s.window_add_indexed_batch([("bc:9:t:x", None, 1.0, 1, 60)])
        assert s.window_range("bc:9:t:x", 0) == [(1.0, 1)] and s.set_members("idx:bc:9") == [], name
        print(f"  ok window_add_indexed_batch [{name}]")


def test_pipeline_ops():
    """pipeline_ops (plan 007): every op kind lands like its individual equivalent,
    on both memory and sharded-mem, in ONE batch."""
    stores = [("memory", st.InMemoryStore()),
              ("sharded-mem", st.ShardedRedisStore([st.InMemoryStore() for _ in range(3)]))]
    for name, s in stores:
        s.pipeline_ops([
            ("win",  "bc:1:t:a|b", "idx:bc:1", 100.0, 7, 60),
            ("cnt",  "ex:1:t:a|b", "b", 500, 60, "idx:ex:1"),
            ("cnt",  "ex:1:t:a|b", "b", 200, 60, "idx:ex:1"),      # same key/field accumulates
            ("znx",  "kd:1:t:a", "dstX", 10.0, 60, "idx:kd:1"),
            ("znx",  "kd:1:t:a", "dstX", 99.0, 60, "idx:kd:1"),    # NX: keeps earliest 10.0
            ("kv",   "ctx:t:a|b", ["breed", ["r1"]], 60),
            ("sadd", "pv:t:b", "a", 60),
        ])
        assert s.window_range("bc:1:t:a|b", 0) == [(100.0, 7)], name
        assert "bc:1:t:a|b" in s.set_members("idx:bc:1"), name
        assert s.counter_get("ex:1:t:a|b", "b") == 700, name          # 500+200
        assert "ex:1:t:a|b" in s.set_members("idx:ex:1"), name
        assert s.zset_rank("kd:1:t:a", "dstX") == 0, name             # only member -> rank 0
        assert "kd:1:t:a" in s.set_members("idx:kd:1"), name
        assert s.kv_get("ctx:t:a|b") == ["breed", ["r1"]], name
        assert s.set_contains("pv:t:b", "a"), name
        s.pipeline_ops([])                                            # empty -> no-op
        print(f"  ok pipeline_ops [{name}]")


def test_zset_first_seen():
    """First-seen ZSET (plan 007, rare-dest): NX keeps earliest, since = strictly
    newer, rank = count ordered before (score, member)."""
    for name, s in _backends():
        for m, sc in (("d1", 10.0), ("d2", 20.0), ("d3", 30.0)):
            s.pipeline_ops([("znx", "kd:z", m, sc, 600, None)])
        s.pipeline_ops([("znx", "kd:z", "d2", 999.0, 600, None)])     # NX: d2 stays 20.0
        assert s.zset_since("kd:z", 0.0) == ["d1", "d2", "d3"], name  # score-ascending order
        assert s.zset_since("kd:z", 15.0) == ["d2", "d3"], name       # strictly > 15, ordered
        assert s.zset_since("kd:z", 20.0) == ["d3"], name             # boundary excluded
        assert s.zset_rank("kd:z", "d1") == 0, name                   # earliest -> 0 predecessors
        assert s.zset_rank("kd:z", "d3") == 2, name                   # two arrived before
        assert s.zset_rank("kd:z", "missing") is None, name
        print(f"  ok zset_first_seen [{name}]")


if __name__ == "__main__":
    import inspect
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        if inspect.getfullargspec(fn).args:
            continue
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall store contract tests passed")
