"""Build gate for parity (run: `python test_parity.py`)."""
import parity as p


def test_core_zeek_logs_present():
    for z in ("conn", "dns", "http", "ssl", "files", "ssh", "smb", "kerberos", "notice"):
        assert z in p.PARITY, z


def test_coverage_values_valid_and_notes_nonempty():
    for z, (eve, cov, note) in p.PARITY.items():
        assert cov in p.COVERAGE, (z, cov)
        assert eve and note, z


def test_render_table_lists_every_row():
    t = p.render_table()
    for z in p.PARITY:
        assert f"`{z}`" in t


def test_coverage_counts_sum_to_total():
    c = p.coverage_counts()
    assert sum(c.values()) == len(p.PARITY)


def test_notice_is_the_cernity_gap():
    _eve, cov, _note = p.PARITY["notice"]
    assert cov == "none"          # the honest gap Cernity's detectors fill


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print(f"ok {name}")
    print("all ok")
