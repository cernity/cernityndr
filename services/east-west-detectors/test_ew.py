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




def test_scan_score():
    import ew
    horiz = {("10.0.0.%d" % i, "445") for i in range(30)}
    hit, kind, n = ew.scan_score(horiz)
    assert hit and kind == "horizontal" and n == 30
    vert = {("10.0.0.5", str(pt)) for pt in range(20)}
    hit, kind, n = ew.scan_score(vert)
    assert hit and kind == "vertical" and n == 20
    assert not ew.scan_score({("10.0.0.5", "445"), ("10.0.0.6", "443")})[0]


# --- credential access / impact / lateral exec (plan T2) -------------------

def test_password_spray_many_accounts_fires():
    accts = {f"user{i}" for i in range(10)}          # 10 distinct accounts, few tries each
    hit, n = ew.spray_score(accts)
    assert hit and n == 10


def test_password_spray_one_account_is_brute_not_spray():
    # many failures against ONE account is brute force, not spraying
    assert not ew.spray_score({"admin"})[0]


def test_asrep_roast_multiple_preauthless_accounts_fires():
    hit, n = ew.asrep_roast_score({"svc_sql", "svc_web", "svc_bak"})
    assert hit and n == 3


def test_asrep_roast_single_account_is_quiet():
    assert not ew.asrep_roast_score({"svc_sql"})[0]  # below threshold, likely a misconfig


def test_ransomware_smb_write_flood_fires():
    hit, writes = ew.ransomware_smb_score(distinct_files=200, writes=200, reads=5)
    assert hit and writes == 200


def test_ransomware_smb_read_only_enumeration_no_fire():
    assert not ew.ransomware_smb_score(distinct_files=300, writes=0, reads=300)[0]


def test_ransomware_smb_normal_fileserver_no_fire():
    # busy but read-mostly and few files: below files/writes/ratio thresholds
    assert not ew.ransomware_smb_score(distinct_files=40, writes=30, reads=400)[0]


def test_lateral_exec_svcctl_pipe_fires():
    hit, matched = ew.lateral_exec_score(["\\PIPE\\svcctl"], [], [])
    assert hit and any("svcctl" in m for m in matched)


def test_lateral_exec_wmi_dcerpc_fires():
    hit, matched = ew.lateral_exec_score([], ["8a885d04-1ceb-11c9-9fe8-08002b104860"], [])
    assert hit and any("WMI" in m for m in matched)


def test_lateral_exec_winrm_fanout_fires():
    hit, matched = ew.lateral_exec_score([], [], ["10.0.0.2", "10.0.0.3"])
    assert hit and any("winrm" in m for m in matched)


def test_lateral_exec_benign_rpc_no_fire():
    hit, matched = ew.lateral_exec_score(["\\PIPE\\spoolss"], ["00000000-0000-0000-0000-000000000000"], [])
    assert not hit and matched == []


def test_llmnr_poison_many_answered_names_fires():
    hit, n = ew.llmnr_poison_score({f"host{i}" for i in range(6)})
    assert hit and n == 6


def test_llmnr_poison_single_name_is_legit_host():
    assert not ew.llmnr_poison_score({"fileserver"})[0]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} east-west tests passed")
