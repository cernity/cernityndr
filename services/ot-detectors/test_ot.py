"""OT/ICS (Modbus) detector tests (pure). Each detection has a positive case and a
benign control, mirroring the fixture contract in modbus-ot-eve.jsonl."""
import ot


def test_mb_fields_spellings():
    # nested function object + access object + unit spelling
    f = ot.mb_fields({"function": {"code": 16, "raw": 16}, "access": {"type": "WRITE_SINGLE"},
                      "unit_id": 3})
    assert f["fc"] == 16 and "WRITE" in f["access"] and f["unit_id"] == 3
    # flat spellings + exception
    f = ot.mb_fields({"function_code": 3, "access_type": "READ", "uid": 1,
                      "exception": "ILLEGAL_FUNCTION"})
    assert f["fc"] == 3 and f["is_error"] and f["unit_id"] == 1
    # absent -> dormant (no guessing)
    f = ot.mb_fields({})
    assert f["fc"] is None and f["access"] == "" and not f["is_error"]
    # a clean read carries no error
    assert not ot.mb_fields({"function": 3, "error_flags": 0})["is_error"]


def test_is_write_control():
    assert ot.is_write_control(6)                       # write single register
    assert ot.is_write_control(16)                      # write multiple registers
    assert ot.is_write_control(None, "WRITE_MULTIPLE")  # by access flag alone
    assert not ot.is_write_control(3)                   # read holding registers
    assert not ot.is_write_control(3, "READ")


def test_unauthorized_write():
    assert ot.unauthorized_write(6, "WRITE", src_is_authorized=False)[0]
    assert not ot.unauthorized_write(6, "WRITE", src_is_authorized=True)[0]   # EWS/HMI allowed
    assert not ot.unauthorized_write(3, "READ", src_is_authorized=False)[0]   # read is fine


def test_program_download():
    assert ot.program_download(90, src_is_authorized=False)[0]     # Schneider Unity program
    assert not ot.program_download(90, src_is_authorized=True)[0]  # from the EWS: expected
    assert not ot.program_download(3, src_is_authorized=False)[0]  # ordinary read


def test_enumeration():
    assert ot.enumeration_hit(6, 1)[0]                  # fc breadth
    assert ot.enumeration_hit(2, 4)[0]                  # unit breadth
    assert not ot.enumeration_hit(2, 2)[0]              # normal poll loop


def test_error_spike():
    assert ot.error_spike_hit(5)[0]
    assert not ot.error_spike_hit(1)[0]


def test_modbus_port_anomaly():
    assert ot.modbus_port_anomaly(1502)[0]              # modbus off the well-known port
    assert not ot.modbus_port_anomaly(502)[0]           # normal
    assert not ot.modbus_port_anomaly(1502, allow_ports={1502})[0]   # allowlisted
    assert not ot.modbus_port_anomaly(None)[0]          # absent port no-fire


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} OT/ICS detector tests passed")
