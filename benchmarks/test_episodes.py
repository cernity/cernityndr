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


# §25.3: revision selection must be deterministic (never by file order) and deadline-aware.
def _rev(fid, t, **kw):
    # instant interval at t: t is both the recency key and the observation time
    d = {"entities": [{"value": "10.0.0.5", "role": "src"}, {"value": "203.0.113.66", "role": "dst"}],
         "behavior": "c2", "finding_id": fid, "interval": {"start": t, "end": t}}
    d.update(kw)
    return d


def test_latest_revision_selected_regardless_of_input_order():
    lo = _rev("f1", 100.0, severity=4)          # earlier evidence
    hi = _rev("f1", 500.0, severity=8)           # later revision of the SAME finding
    for order in ([lo, hi], [hi, lo]):           # reordering export rows must not change the result
        r = ep.score(order, [BEACON])
        assert r["analyst_items"] == 1 and r["superseded_revisions"] == 1
        assert r["relevant_items"] == 1          # one logical item, latest revision
    # explicit revision counter dominates recency
    assert ep._revision_rank(_rev("f", 0.0, revision=2)) > ep._revision_rank(_rev("f", 999.0))


def test_state_breaks_ties_at_equal_recency():
    interim = _rev("f1", 100.0, state="open")
    final = _rev("f1", 100.0, state="final")
    assert ep._revision_rank(final) > ep._revision_rank(interim)


def test_same_rank_conflicting_payloads_are_flagged_not_picked_by_order():
    # §28-B: two records, same (tenant, finding_id) and identical rank, DIFFERENT behavior. The
    # winner must not depend on input order — it is an unresolved version conflict, scored as neither.
    c2 = _rev("f1", 100.0)                        # behavior c2 (default in _rev)
    recon = _rev("f1", 100.0); recon["behavior"] = "recon"
    for order in ([c2, recon], [recon, c2]):
        r = ep.score(order, [BEACON])
        assert r["version_conflicts"] == 1
        assert r["relevant_items"] == 0 and r["false_items"] == 0   # not adjudicated either way
        assert r["episode_recall"] == 0.0                            # conflict does not credit recall


def test_identical_retransmission_at_same_rank_collapses_without_conflict():
    a = _rev("f1", 100.0)
    b = _rev("f1", 100.0)                         # byte-equal payload + rank -> a duplicate, not a conflict
    r = ep.score([a, b], [BEACON])
    assert r["version_conflicts"] == 0 and r["analyst_items"] == 1 and r["superseded_revisions"] == 1


def test_conflicting_explicit_revisions_at_same_number_are_a_conflict():
    a = _rev("f1", 0.0, revision=3)
    b = _rev("f1", 0.0, revision=3); b["behavior"] = "recon"
    assert ep.score([a, b], [BEACON])["version_conflicts"] == 1
    # a higher explicit revision with a single payload resolves cleanly (no conflict)
    hi = _rev("f1", 0.0, revision=5)
    assert ep.score([a, hi], [BEACON])["version_conflicts"] == 0


def test_late_revision_does_not_improve_deadline_recall():
    ep_t = dict(BEACON, interval={"start": 0.0, "end": 50.0})
    early = _rev("f1", 40.0)                      # within the window, eligible by the deadline
    late = _rev("f1", 900.0)                      # a later revision arriving after the deadline
    # deadline excludes the late revision; the eligible in-window one still surfaces the episode
    r = ep.score([early, late], [ep_t], deadline=100.0)
    assert r["episode_recall"] == 1.0 and r["late_items"] == 1 and r["superseded_revisions"] == 0
    # with NO deadline the late (out-of-window) revision wins the selection -> not in window -> miss
    r2 = ep.score([early, late], [ep_t])
    assert r2["episode_recall"] == 0.0 and r2["superseded_revisions"] == 1


def test_all_revisions_after_deadline_leaves_no_item():
    ep_t = dict(BEACON, interval={"start": 0.0, "end": 50.0})
    r = ep.score([_rev("f1", 900.0), _rev("f1", 950.0)], [ep_t], deadline=100.0)
    assert r["late_items"] == 2 and r["analyst_items"] == 0 and r["episode_recall"] == 0.0


# §28 Major-4: missing availability is UNKNOWN eligibility, never silently on-time; the deadline
# result is observation-basis; finding_id-less records are gated too.
def test_missing_time_under_deadline_is_unknown_not_on_time():
    ep_t = dict(BEACON, interval={"start": 0.0, "end": 50.0})
    d = {"entities": [{"value": "10.0.0.5", "role": "src"}, {"value": "203.0.113.66", "role": "dst"}],
         "behavior": "c2", "finding_id": "f1"}                     # no interval -> no available time
    r = ep.score([d], [ep_t], deadline=100.0)
    assert r["unknown_eligibility_items"] == 1 and r["episode_recall"] == 0.0 and r["analyst_items"] == 0
    assert r["deadline_basis"] and "observation" in r["deadline_basis"]


def test_finding_id_less_record_is_deadline_gated():
    ep_t = dict(BEACON, interval={"start": 0.0, "end": 50.0})
    late = {"entities": [{"value": "10.0.0.5", "role": "src"}, {"value": "203.0.113.66", "role": "dst"}],
            "behavior": "c2", "interval": {"start": 900.0, "end": 900.0}}   # no finding_id, after deadline
    r = ep.score([late], [ep_t], deadline=100.0)
    assert r["late_items"] == 1 and r["analyst_items"] == 0        # not bypassed just because it lacks an id


def test_incomplete_detection_is_graceful():
    assert ep.score([{"entities": []}, {}], [BEACON])["episode_recall"] == 0.0


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok", _n)
    print("all episode-scorer tests passed")
