"""Observability tests (plan U6). Work with or without prometheus_client."""
import urllib.request

import metrics as m


def test_counters_are_safe_to_call():
    # no-op or real, these never raise
    m.finding("beacon", "acme")
    m.record("flow")
    m.dropped("handler")
    m.config_reloaded()
    m.observe_evaluate(0.01)


def test_readiness_gate():
    m.set_ready("consumer", False)
    m.set_ready("store", False)
    assert m.is_ready() is False
    m.set_ready("consumer", True)
    assert m.is_ready() is False          # store still not ready
    m.set_ready("store", True)
    assert m.is_ready() is True


def test_health_endpoints_serve():
    m.set_ready("consumer", False)
    m.set_ready("store", False)
    srv = m.start(port=9209)
    base = "http://127.0.0.1:9209"
    assert urllib.request.urlopen(base + "/healthz", timeout=3).status == 200
    # not ready -> 503
    try:
        urllib.request.urlopen(base + "/readyz", timeout=3)
        assert False, "should be 503"
    except urllib.error.HTTPError as e:
        assert e.code == 503
    # ready -> 200
    m.set_ready("consumer", True); m.set_ready("store", True)
    assert urllib.request.urlopen(base + "/readyz", timeout=3).status == 200
    srv.shutdown()


if __name__ == "__main__":
    import inspect
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        if inspect.getfullargspec(fn).args:
            continue
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall metrics tests passed")
