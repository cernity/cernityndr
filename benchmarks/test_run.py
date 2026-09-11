"""U12/F10: the benchmark must SUBSTANTIATE what it reports — page past 10k, fail loudly
on a query/engine error (never score a silent empty arm), wait for ingestion to settle,
and hash the real engine outputs. No OpenSearch/Docker: fetch/count/sleep are injected.

  python3 test_run.py
"""
import os
import tempfile

import run


def test_os_search_paginates_past_a_single_page():
    # 25 docs across pages of 10 via search_after — the old size=10000 truncated silently.
    docs = [{"_source": {"i": i}, "sort": [i]} for i in range(25)]

    def fetch(endpoint, index, body):
        after = body.get("search_after")
        start = (after[0] + 1) if after else 0
        return docs[start:start + body["size"]]

    got = run.os_search("http://x", "idx", page=10, fetch=fetch)
    assert [d["i"] for d in got] == list(range(25)), "pagination lost or duplicated docs"


def test_os_search_strict_raises_on_query_error():
    def boom(*_a):
        raise RuntimeError("engine 503")
    try:
        run.os_search("http://x", "idx", fetch=boom, strict=True)
        assert False, "strict os_search must raise, not return an empty arm"
    except RuntimeError as e:
        assert "idx" in str(e)
    # non-strict degrades to partial (used only by the wait poller)
    assert run.os_search("http://x", "idx", fetch=boom, strict=False) == []


def test_wait_for_ingest_settles_then_returns():
    seq = {"a": [0, 3, 3], "b": [1, 2, 2]}          # counts stabilise on the 3rd poll
    calls = {"a": 0, "b": 0}

    def count(idx):
        v = seq[idx][min(calls[idx], len(seq[idx]) - 1)]
        calls[idx] += 1
        return v
    run.wait_for_ingest("http://x", ["a", "b"], min_docs=1, tries=5, count=count, sleep=lambda _s: None)


def test_wait_for_ingest_raises_when_nothing_arrives():
    try:
        run.wait_for_ingest("http://x", ["a"], min_docs=1, tries=3,
                            count=lambda _i: 0, sleep=lambda _s: None)
        assert False, "must fail loudly when ingestion never settles"
    except RuntimeError:
        pass


def test_eve_paths_hashes_real_outputs():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "eve.json"), "w") as f:
            f.write('{"event_type":"alert"}\n')
        os.environ["BENCH_EVE_DIR"] = d
        try:
            assert run._eve_paths(), "real engine outputs not discovered for the determinism hash"
            h1 = run.determinism_hash(*run._eve_paths())
            assert h1 and h1 == run.determinism_hash(*run._eve_paths())   # stable
        finally:
            del os.environ["BENCH_EVE_DIR"]
    assert run._eve_paths() == []                    # unset -> nothing (honest, not a fake hash)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} benchmark run tests passed")
