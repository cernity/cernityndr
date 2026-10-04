"""U3c observed entity-to-entity relationship edges (relationships.build_edges).

Edges come ONLY from observed telemetry: dns answers (querier --resolves--> the
answered IP, carrying the queried name) and flows (src --communicates-with--> dst).
Endpoints resolve through the SAME asset_key spine as the rest of the service, so
edges reference real entity UIDs (mac:… when bound, ip:… otherwise), never raw IPs.
Pure, deterministic, provenance-carrying.
"""
import resolution as r
import relationships as rel

TS = "2026-09-28T12:00:00Z"

DNS = {"event_type": "dns", "src_ip": "10.0.0.5", "dest_ip": "1.1.1.1",
       "dns": {"queries": [{"rrname": "example.com", "rrtype": "A"}],
               "answers": [{"rrname": "example.com", "rrtype": "A", "rdata": "93.184.216.34"},
                           {"rrname": "example.com", "rrtype": "CNAME", "rdata": "cdn.example.net"}]}}
FLOW = {"event_type": "flow", "src_ip": "10.0.0.5", "dest_ip": "93.184.216.34",
        "proto": "TCP", "app_proto": "tls", "flow": {}}


# ── (6) dns -> resolves edge querier->answer with the queried name + provenance ─

def test_dns_yields_resolves_edge_with_queried_name_and_provenance():
    edges = rel.build_edges(DNS, {}, TS)
    assert len(edges) == 1                                     # only the A answer is an IP entity
    e = edges[0]
    assert e["kind"] == "resolves"
    assert e["src_entity"] == "ip:10.0.0.5" and e["dst_entity"] == "ip:93.184.216.34"
    assert e["evidence"] == {"event_type": "dns", "observed_at": r._iso(TS),
                             "detail": "example.com"}


# ── (7) flow -> communicates-with edge src->dst ────────────────────────────────

def test_flow_yields_communicates_with_edge_src_to_dst():
    e = rel.build_edges(FLOW, {}, TS)[0]
    assert e["kind"] == "communicates-with"
    assert e["src_entity"] == "ip:10.0.0.5" and e["dst_entity"] == "ip:93.184.216.34"
    assert e["evidence"]["event_type"] == "flow" and e["evidence"]["observed_at"] == r._iso(TS)
    assert e["evidence"]["detail"] == "tls"                    # observed app_proto, not fabricated


# ── (8) edges reference entity UIDs via the shared resolver, not raw IPs ────────

def test_edges_reference_entity_uids_via_shared_resolver():
    b: dict = {}
    r.record_binding(b, "10.0.0.5", "AA:BB:CC:00:11:22", TS, None)   # 10.0.0.5 is MAC-bound
    e = rel.build_edges(FLOW, b, TS)[0]
    assert e["src_entity"] == "mac:aa:bb:cc:00:11:22"          # resolved to the MAC UID
    assert e["dst_entity"] == "ip:93.184.216.34"               # unbound -> ip UID


# ── (9) deterministic: same input -> same edges ────────────────────────────────

def test_build_edges_is_deterministic():
    assert rel.build_edges(DNS, {}, TS) == rel.build_edges(DNS, {}, TS)
    assert rel.build_edges(FLOW, {}, TS) == rel.build_edges(FLOW, {}, TS)


def test_dns_without_ip_answer_yields_no_edge():
    # A query with only a CNAME answer resolves to no IP entity -> honest gap, no edge.
    eve = {"event_type": "dns", "src_ip": "10.0.0.5", "dest_ip": "1.1.1.1",
           "dns": {"queries": [{"rrname": "x.example"}],
                   "answers": [{"rrname": "x.example", "rrtype": "CNAME", "rdata": "y.example"}]}}
    assert rel.build_edges(eve, {}, TS) == []
