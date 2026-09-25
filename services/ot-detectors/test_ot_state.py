"""ot-detectors externalized state: learned authorized-masters warmup, novelty,
enumeration/error windows, config override, shared dedup. In-memory backend; no broker."""
import json

import app
import store


class _P:
    def __init__(self):
        self.sent = []

    def send(self, topic, msg):
        self.sent.append(msg)

    def flush(self):
        pass


def _fresh():
    app._store = store.make_store("memory")
    app.AUTHORIZED_MASTERS = set()


def _dets(sent):
    return [m["detector_id"] for m in sent]


def _mb(src, dst, fc, port=502, **kw):
    m = {"function": {"code": fc}}
    m.update(kw)
    return {"event_type": "modbus", "src_ip": src, "dest_ip": dst, "dest_port": port, "modbus": m}


def _warm(p, dst, fc=3):
    """Learn MASTER_WARMUP distinct read-only masters for an outstation (no fire during warmup)."""
    for i in range(app.MASTER_WARMUP):
        app._handle(_mb(f"10.0.0.{10 + i}", dst, fc), p)


def test_no_fire_during_warmup():
    _fresh()
    p = _P()
    for i in range(app.MASTER_WARMUP - 2):               # fewer than warmup -> baseline not judged
        app._handle(_mb(f"10.0.0.{i}", "10.0.1.1", 3), p)
    assert p.sent == []


def test_novelty_after_warmup():
    _fresh()
    p = _P()
    _warm(p, "10.0.1.2")                                 # 5 known masters, silent
    assert "new_master_pairing" not in _dets(p.sent)
    app._handle(_mb("10.0.0.250", "10.0.1.2", 3), p)     # never-seen master, post-warmup
    assert "new_master_pairing" in _dets(p.sent)


def test_unauthorized_write_fires():
    _fresh()
    p = _P()
    _warm(p, "10.0.1.3")
    app._handle(_mb("10.0.0.250", "10.0.1.3", 6), p)     # unknown master, write single register
    dets = _dets(p.sent)
    assert "unauthorized_write" in dets
    uw = next(m for m in p.sent if m["detector_id"] == "unauthorized_write")
    assert uw["mitre"] == ["T0855", "T0831"] and uw["category"] == "ics_control"


def test_authorized_master_write_ok():
    _fresh()
    p = _P()
    _warm(p, "10.0.1.4")                                 # 10.0.0.10..14 learned
    app._handle(_mb("10.0.0.10", "10.0.1.4", 6), p)      # a LEARNED master writing -> allowed
    assert "unauthorized_write" not in _dets(p.sent)


def test_config_override_authorizes():
    _fresh()
    app.AUTHORIZED_MASTERS = {"10.0.0.50"}               # R4: pin corrects/overrides the baseline
    p = _P()
    _warm(p, "10.0.1.5")
    app._handle(_mb("10.0.0.50", "10.0.1.5", 6), p)      # pinned EWS write, post-warmup
    assert "unauthorized_write" not in _dets(p.sent) and "new_master_pairing" not in _dets(p.sent)


def test_program_download_fires():
    _fresh()
    p = _P()
    _warm(p, "10.0.1.6")
    app._handle(_mb("10.0.0.250", "10.0.1.6", 90), p)    # vendor program/mode code from unknown src
    pd = next(m for m in p.sent if m["detector_id"] == "program_download")
    assert pd["mitre"] == ["T0858", "T0843"]


def test_fc_enumeration_fires():
    _fresh()
    p = _P()
    for fc in (1, 2, 3, 4, 7, 11):                        # 6 distinct fc from one src -> recon
        app._handle(_mb("10.0.0.9", "10.0.1.7", fc), p)
    en = next(m for m in p.sent if m["detector_id"] == "fc_enumeration")
    assert en["mitre"] == ["T0846"]


def test_error_spike_fires():
    _fresh()
    p = _P()
    for _ in range(app.ERROR_SPIKE_MIN):                 # burst of modbus exceptions
        app._handle(_mb("10.0.0.9", "10.0.1.8", 3, exception="ILLEGAL_FUNCTION"), p)
    assert "error_flag_spike" in _dets(p.sent)


def test_port_anomaly_fires():
    _fresh()
    p = _P()
    app._handle(_mb("10.0.0.9", "10.0.1.9", 3, port=1502), p)   # modbus off :502
    pa = next(m for m in p.sent if m["detector_id"] == "modbus_port_anomaly")
    assert pa["mitre"] == ["T0885"]


def test_dedup_no_double_emit():
    _fresh()
    p = _P()
    for fc in (1, 2, 3, 4, 7, 11):
        app._handle(_mb("10.0.0.9", "10.0.1.10", fc), p)
    app._handle(_mb("10.0.0.9", "10.0.1.10", 1), p)      # already-counted fc: same signal, same bucket
    assert sum(1 for m in p.sent if m["detector_id"] == "fc_enumeration") == 1


def test_stable_hash_deterministic():
    assert app._stable("x") == app._stable("x")


def test_source_events_provenance_attached():
    # U3: the candidate carries the originating Modbus EVE; verdict fields unchanged (R6).
    _fresh()
    p = _P()
    _warm(p, "10.0.1.20")
    app._handle(_mb("10.0.0.250", "10.0.1.20", 6), p)   # unknown master, write single register
    f = next(m for m in p.sent if m["detector_id"] == "unauthorized_write")
    se = f["source_events"][0]
    assert se["record"]["modbus"]["function"]["code"] == 6      # native EVE preserved verbatim
    assert f["detector_id"] == "unauthorized_write" and f["severity"] == 8   # R6: verdict unchanged


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} ot-state tests passed")
