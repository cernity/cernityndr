from forwarder import handle_batch, build_receipt, sink_receipts


class Spy:
    def __init__(self):
        self.seen = []

    def emit(self, f):
        self.seen.append(f["finding_id"])


class FakeSink:
    def __init__(self, name, delivered=0, dead=0):
        self.name, self.delivered, self.dead_lettered = name, delivered, dead

    def receipt(self):
        return {"name": self.name, "delivered": self.delivered, "dead_lettered": self.dead_lettered}


class FakeMulti:
    def __init__(self, sinks):
        self.adapters = sinks

    def receipt(self):
        return [s.receipt() for s in self.adapters]


def test_handle_batch_forwards_each():
    spy = Spy()
    handle_batch([{"finding_id": "a"}, {"finding_id": "b"}], spy)
    assert spy.seen == ["a", "b"]


def test_handle_batch_empty():
    spy = Spy()
    handle_batch([], spy)
    assert spy.seen == []


def test_build_receipt_accounts_for_every_consumed_finding():
    # Rec-D invariant: consumed == suppressed + delivered + dead_lettered (per sink).
    r = build_receipt(FakeSink("opensearch", delivered=8, dead=0), consumed=10, suppressed=2)
    assert r["consumed"] == 10 and r["suppressed"] == 2 and r["delivered_live"] == 8
    s = r["sinks"][0]
    assert s["delivered"] + s["dead_lettered"] == r["delivered_live"]     # fully accounted, none pending


def test_build_receipt_surfaces_dead_letters_as_a_negative_outcome():
    r = build_receipt(FakeSink("splunk", delivered=5, dead=3), consumed=8, suppressed=0)
    assert r["sinks"][0]["dead_lettered"] == 3 and r["delivered_live"] == 8   # 5 delivered + 3 dead == 8


def test_receipt_covers_every_sink_in_a_fanout():
    r = build_receipt(FakeMulti([FakeSink("a", 4), FakeSink("b", 3, dead=1)]), consumed=4, suppressed=0)
    assert {s["name"] for s in r["sinks"]} == {"a", "b"} and len(sink_receipts(FakeMulti([FakeSink("a")]))) == 1


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok", _n)
    print("ok test_forwarder")
