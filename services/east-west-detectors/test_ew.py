"""East-west detector tests (pure)."""
import ew


def test_is_internal():
    assert ew.is_internal("192.168.222.5") and ew.is_internal("10.1.2.3")
    assert not ew.is_internal("8.8.8.8")


def test_lateral_fanout():
    targets = {(f"192.168.1.{i}", 445) for i in range(6)}
    hit, n = ew.lateral_fanout(targets)
    assert hit and n == 6
    assert not ew.lateral_fanout({("192.168.1.1", 445), ("192.168.1.1", 3389)})[0]  # 1 host


def test_rdp_fanout():
    assert ew.rdp_fanout({"192.168.1.1", "192.168.1.2", "192.168.1.3"})[0]
    assert not ew.rdp_fanout({"192.168.1.1"})[0]


def test_kerberoast_many_spns():
    reqs = [{"sname": f"MSSQLSvc/host{i}", "encryption": "18"} for i in range(10)]
    hit, spns, rc4 = ew.kerberoast_score(reqs)
    assert hit and spns == 10 and not rc4


def test_kerberoast_rc4_downgrade():
    reqs = [{"sname": f"svc{i}", "encryption": "23"} for i in range(3)]  # RC4 + 3 SPNs
    hit, _, rc4 = ew.kerberoast_score(reqs)
    assert hit and rc4


def test_kerberoast_normal_is_quiet():
    reqs = [{"sname": "krbtgt", "encryption": "18"}]
    assert not ew.kerberoast_score(reqs)[0]


def test_dcerpc_lateral_svcctl():
    hit, desc = ew.dcerpc_lateral("367abb81-9844-35f1-ad32-98f038001003")
    assert hit and "PsExec" in desc
    assert not ew.dcerpc_lateral("00000000-0000-0000-0000-000000000000")[0]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} east-west tests passed")
