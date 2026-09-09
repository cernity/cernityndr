from forwarder import handle_batch


class Spy:
    def __init__(self):
        self.seen = []

    def emit(self, f):
        self.seen.append(f["finding_id"])


def test_handle_batch_forwards_each():
    spy = Spy()
    handle_batch([{"finding_id": "a"}, {"finding_id": "b"}], spy)
    assert spy.seen == ["a", "b"]


def test_handle_batch_empty():
    spy = Spy()
    handle_batch([], spy)
    assert spy.seen == []


if __name__ == "__main__":
    test_handle_batch_forwards_each()
    test_handle_batch_empty()
    print("ok test_forwarder")
