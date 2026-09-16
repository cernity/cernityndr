"""Tests for the baseline provenance helper (pure)."""
import json
import os

import provenance as p

# A real .16 QUIC EVE record (ndpi + ja3 + ja4), abbreviated but structurally faithful.
QUIC = {
    "timestamp": "2026-09-16T20:19:21.668890+0000",
    "flow_id": 338184613427258, "event_type": "quic",
    "src_ip": "2603:8000::1", "dest_ip": "2606:4700::6812:efc2", "dest_port": 443,
    "community_id": "1:7uPREPibQnCr/ndhsscK+t1/kaI=",
    "quic": {"sni": "static-pub.highwebmedia.com",
             "ja3": {"hash": "78d14b5e6e68de179a8d1b616dd0bedb"},
             "ja4": "q13d0314h3_55b375c5d22e_79cc91d6b50c"},
    "ndpi": {"proto": "QUIC", "category": "Web", "confidence": {"6": "DPI"}},
}


def test_preserves_native_record_and_pivots():
    e = p.source_event(QUIC)
    assert e["event_type"] == "quic"
    assert e["community_id"] == "1:7uPREPibQnCr/ndhsscK+t1/kaI="
    assert e["flow_id"] == 338184613427258
    assert e["timestamp"].startswith("2026-09-16T20:19:21")
    # native EVE preserved verbatim — ndpi + ja3 + ja4 intact
    assert e["record"]["ndpi"]["proto"] == "QUIC"
    assert e["record"]["quic"]["ja4"] == "q13d0314h3_55b375c5d22e_79cc91d6b50c"
    assert e["record"]["quic"]["ja3"]["hash"] == "78d14b5e6e68de179a8d1b616dd0bedb"


def test_missing_identifiers_omitted_never_faked():
    e = p.source_event({"event_type": "stats", "stats": {}})  # no community_id/flow_id/tx_id
    assert "community_id" not in e and "flow_id" not in e and "tx_id" not in e
    assert e["record"]["event_type"] == "stats"


def test_over_cap_record_becomes_bounded_preview():
    os.environ["NDR_SOURCE_EVENTS_MAX_BYTES"] = "200"
    import importlib
    importlib.reload(p)
    big = dict(QUIC, blob="x" * 5000)
    e = p.source_event(big)
    assert e.get("truncated") is True and "record" not in e
    assert len(e["record_preview"]) <= 200
    os.environ["NDR_SOURCE_EVENTS_MAX_BYTES"] = "16384"
    importlib.reload(p)


def test_representative_flag():
    assert p.source_event(QUIC, representative=True)["representative"] is True


def test_non_dict_returns_none():
    assert p.source_event("not a dict") is None


def test_contributors_dedups_and_counts():
    evs = [dict(QUIC), dict(QUIC, flow_id=999, community_id="1:other="),
           {"event_type": "flow"}]  # third has no pivots
    c = p.contributors(evs)
    assert c["count"] == 3
    assert c["community_ids"] == ["1:7uPREPibQnCr/ndhsscK+t1/kaI=", "1:other="]
    assert c["flow_ids"] == [338184613427258, 999]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} provenance tests passed")
