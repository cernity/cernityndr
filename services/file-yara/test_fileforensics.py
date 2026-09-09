"""fileforensics tests (pure; entropy is deterministic, PE block is optional)."""
import fileforensics as ff


def test_entropy_bounds():
    assert ff.shannon_entropy(b"") == 0.0
    assert ff.shannon_entropy(b"\x00" * 1024) == 0.0          # uniform => 0 bits
    high = ff.shannon_entropy(bytes(range(256)) * 4)          # every byte equally likely
    assert 7.9 <= high <= 8.0


def test_forensics_flags_packed():
    packed = ff.forensics(bytes(range(256)) * 16)
    assert packed["packed_or_encrypted"] is True
    assert packed["size"] == 4096
    plain = ff.forensics(b"hello world " * 100)
    assert "packed_or_encrypted" not in plain


def test_non_pe_has_no_pe_block():
    out = ff.forensics(b"just some text, not an executable")
    assert "pe" not in out
    assert ff.is_pe(b"MZ\x90\x00") is True
    assert ff.is_pe(b"PK\x03\x04") is False


def test_pe_metadata_graceful_on_stub():
    # An 'MZ' stub with no valid PE structure must degrade to {} (pefile absent or parse fail).
    assert ff.pe_metadata(b"MZ" + b"\x00" * 64) == {}


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print("ok ", fn.__name__)
    print("all %d fileforensics tests passed" % len(fns))
