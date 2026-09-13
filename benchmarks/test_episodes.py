"""§7 scorer battery for episode/role-aware matching (run: python test_episodes.py).

Post-R3 semantics: a detection surfaces an episode only when it implicates ALL of the episode's
entities (the discriminating relationship), in compatible roles, with compatible behaviour and
tenant — so a shared source no longer cross-credits sibling episodes (§20.1)."""
import episodes as ep


def _det(entities, **kw):
    d = {"entities": [{"value": v, "role": r} for v, r in entities]}
    d.update(kw)
    return d


BEACON = {"id": "beacon-1", "label": "malicious", "behavior": "c2",
          "entities": [{"value": "10.0.0.5", "role": "initiator"},
                       {"value": "203.0.113.66", "role": "target"}]}
EP_A = {"id": "A", "label": "malicious", "behavior": "c2",
        "entities": [{"value": "10.0.0.5", "role": "initiator"}, {"value": "203.0.113.66", "role": "target"}]}
EP_B = {"id": "B", "label": "malicious", "behavior": "c2",
        "entities": [{"value": "10.0.0.5", "role": "initiator"}, {"value": "198.51.100.77", "role": "target"}]}


def test_full_relationship_surfaces_and_target_is_not_a_separate_fp():
    d = _det([("10.0.0.5", "src"), ("203.0.113.66", "dst")], behavior="c2")
    r = ep.score([d], [BEACON])
    assert r["episode_recall"] == 1.0 and r["false_items"] == 0 and r["relevant_items"] == 1


def test_shared_source_credits_only_the_supported_episode():
    # THE §20.1 probe: a detection naming the shared source + destination A must credit ONLY A.
    d = _det([("10.0.0.5", "src"), ("203.0.113.66", "dst")], behavior="c2")
    r = ep.score([d], [EP_A, EP_B])
    assert r["surfaced_ids"] == ["A"] and r["episodes_surfaced"] == 1 and r["episodes_missed"] == 1


def test_both_incidents_need_their_own_detection():
    dA = _det([("10.0.0.5", "src"), ("203.0.113.66", "dst")], behavior="c2")
    dB = _det([("10.0.0.5", "src"), ("198.51.100.77", "dst")], behavior="c2")
    assert ep.score([dA, dB], [EP_A, EP_B])["episode_recall"] == 1.0     # 2/2 only with both
    assert ep.score([dA], [EP_A, EP_B])["episodes_surfaced"] == 1        # one detection -> one


def test_initiator_only_does_not_surface_a_peer_specific_episode():
    d = _det([("10.0.0.5", "src")], behavior="c2")                       # no destination
    assert ep.score([d], [BEACON])["episode_recall"] == 0.0


def test_reversed_direction_role_mismatch_does_not_match():
    d = _det([("203.0.113.66", "src"), ("10.0.0.5", "dst")], behavior="c2")   # roles swapped
    assert ep.score([d], [BEACON])["episode_recall"] == 0.0


def test_benign_host_detection_is_a_false_item():
    d = _det([("10.0.0.10", "src"), ("8.8.8.8", "dst")], behavior="c2")
    r = ep.score([d], [BEACON])
    assert r["episode_recall"] == 0.0 and r["false_items"] == 1


def test_extra_benign_endpoint_in_a_matched_finding_is_not_a_separate_fp():
    # names the real relationship (10.0.0.5 -> 203.0.113.66) plus an extra benign peer
    d = _det([("10.0.0.5", "src"), ("203.0.113.66", "dst"), ("10.0.0.99", "dst")], behavior="c2")
    r = ep.score([d], [BEACON])
    assert r["relevant_items"] == 1 and r["false_items"] == 0 and r["episode_recall"] == 1.0


def test_duplicates_count_episode_once():
    d = _det([("10.0.0.5", "src"), ("203.0.113.66", "dst")], behavior="c2")
    r = ep.score([d, dict(d)], [BEACON])
    assert r["episodes_surfaced"] == 1 and r["relevant_items"] == 2


def test_revisions_dedup_by_tenant_scoped_finding_id():
    d1 = _det([("10.0.0.5", "src"), ("203.0.113.66", "dst")], behavior="c2", finding_id="f1")
    d2 = _det([("10.0.0.5", "src"), ("203.0.113.66", "dst")], behavior="c2", finding_id="f1")
    assert ep.score([d1, d2], [BEACON])["analyst_items"] == 1
    # same finding_id in a different tenant is a different item
    d3 = _det([("10.0.0.5", "src"), ("203.0.113.66", "dst")], behavior="c2", finding_id="f1", tenant="t2")
    assert ep.score([d1, d3], [BEACON, dict(BEACON, tenant="t2")])["analyst_items"] == 2


def test_multiple_episodes_per_host_scored_separately_by_behavior():
    e1 = {"id": "a", "label": "malicious", "behavior": "c2", "entities": [{"value": "10.0.0.5", "role": "initiator"}]}
    e2 = {"id": "b", "label": "malicious", "behavior": "recon", "entities": [{"value": "10.0.0.5", "role": "initiator"}]}
    c2 = _det([("10.0.0.5", "src")], behavior="c2")
    assert ep.score([c2], [e1, e2])["episodes_surfaced"] == 1            # only the c2 one
    scan = _det([("10.0.0.5", "src")], behavior="recon")
    assert ep.score([c2, scan], [e1, e2])["episode_recall"] == 1.0


def test_same_ip_different_tenants_do_not_cross_match():
    d = _det([("10.0.0.5", "src"), ("203.0.113.66", "dst")], behavior="c2", tenant="B")
    assert ep.score([d], [dict(BEACON, tenant="A")])["episode_recall"] == 0.0


def test_ipv6_entities():
    e6 = {"id": "v6", "label": "malicious", "behavior": "c2", "entities": [{"value": "2001:db8::5", "role": "initiator"}]}
    d = _det([("2001:db8::5", "src")], behavior="c2")
    assert ep.score([d], [e6])["episode_recall"] == 1.0


def test_zero_detections_is_full_miss_not_a_crash():
    r = ep.score([], [BEACON])
    assert r["episode_recall"] == 0.0 and r["analyst_precision"] == 0.0 and r["episodes_missed"] == 1


def test_interval_excludes_out_of_window_detection():
    ep_t = dict(BEACON, interval={"start": 100.0, "end": 200.0})
    inside = _det([("10.0.0.5", "src"), ("203.0.113.66", "dst")], behavior="c2", interval={"start": 150.0, "end": 160.0})
    outside = _det([("10.0.0.5", "src"), ("203.0.113.66", "dst")], behavior="c2", interval={"start": 900.0, "end": 910.0})
    assert ep.score([inside], [ep_t])["episode_recall"] == 1.0
    assert ep.score([outside], [ep_t])["episode_recall"] == 0.0


# §24.3: a time-bounded episode must not be credited by a detection that carries no time — that is
# temporally UNVERIFIABLE (ambiguous), not an in-window match and not a plain miss.
def test_timeless_detection_does_not_credit_a_time_bounded_episode():
    ep_t = dict(BEACON, interval={"start": 0.0, "end": 10.0})
    d = _det([("10.0.0.5", "src"), ("203.0.113.66", "dst")], behavior="c2")   # right identity, no interval
    r = ep.score([d], [ep_t])
    assert r["episode_recall"] == 0.0                       # NOT the prior soft over-credit
    assert r["episodes_ambiguous"] == 1 and r["ambiguous_ids"] == ["beacon-1"]
    assert r["episodes_missed"] == 0                        # ambiguous is separate from a true miss
    assert r["ambiguous_items"] == 1 and r["false_items"] == 0 and r["relevant_items"] == 0


def test_out_of_window_detection_is_a_true_miss_and_a_false_item():
    ep_t = dict(BEACON, interval={"start": 100.0, "end": 200.0})
    d = _det([("10.0.0.5", "src"), ("203.0.113.66", "dst")], behavior="c2", interval={"start": 900.0, "end": 910.0})
    r = ep.score([d], [ep_t])
    assert r["episode_recall"] == 0.0 and r["episodes_missed"] == 1 and r["episodes_ambiguous"] == 0
    assert r["false_items"] == 1                            # provably out of window -> unrelated


def test_disjoint_windows_do_not_cross_credit_same_entities():
    # same host/peer, two non-overlapping episodes; each detection credits ONLY its own window.
    e1 = dict(BEACON, id="w1", interval={"start": 0.0, "end": 10.0})
    e2 = dict(BEACON, id="w2", interval={"start": 100.0, "end": 110.0})
    d1 = _det([("10.0.0.5", "src"), ("203.0.113.66", "dst")], behavior="c2", interval={"start": 2.0, "end": 3.0})
    r = ep.score([d1], [e1, e2])
    assert r["surfaced_ids"] == ["w1"] and r["episodes_missed"] == 1     # w2 not credited by a w1 detection


def test_untimed_episode_still_matches_on_identity_alone():
    # regression: an episode with no interval is not time-bounded; identity match still surfaces it.
    d = _det([("10.0.0.5", "src"), ("203.0.113.66", "dst")], behavior="c2")
    assert ep.score([d], [BEACON])["episode_recall"] == 1.0


def test_unknown_episode_match_is_unscored_not_false():
    unk = {"id": "u", "label": "unknown", "behavior": "c2", "entities": [{"value": "10.9.9.9", "role": "initiator"}]}
    d = _det([("10.9.9.9", "src")], behavior="c2")
    r = ep.score([d], [BEACON, unk])
    assert r["unscored_items"] == 1 and r["false_items"] == 0 and r["relevant_items"] == 0


def test_behavior_class_subsumes_detector_technique():
    exfil_ep = {"id": "x", "label": "malicious", "behavior": "exfil", "entities": [{"value": "10.0.0.9", "role": "initiator"}]}
    d = _det([("10.0.0.9", "src")], behavior="dns_tunnel")
    assert ep.score([d], [exfil_ep])["episode_recall"] == 1.0


def test_behavior_incompatible_detection_does_not_surface():
    d = _det([("10.0.0.5", "src"), ("203.0.113.66", "dst")], behavior="recon")
    assert ep.score([d], [BEACON])["episode_recall"] == 0.0


def test_match_requires_narrows_the_discriminator():
    # a scan family may key on the initiator alone (target set is evidence, not a fixed entity)
    scan = {"id": "s", "label": "malicious", "behavior": "recon",
            "entities": [{"value": "10.0.0.8", "role": "initiator"}], "match_requires": ["10.0.0.8"]}
    d = _det([("10.0.0.8", "src"), ("10.0.0.20", "dst")], behavior="recon")
    assert ep.score([d], [scan])["episode_recall"] == 1.0


def test_incomplete_detection_is_graceful():
    assert ep.score([{"entities": []}, {}], [BEACON])["episode_recall"] == 0.0


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok", _n)
    print("all episode-scorer tests passed")
