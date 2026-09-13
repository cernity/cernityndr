"""§7 scorer battery for episode/role-aware matching (run: python test_episodes.py)."""
import episodes as ep


def _e(*vals_roles):
    return {"entities": [{"value": v, "role": r} for v, r in vals_roles]}


def _det(entities, **kw):
    d = {"entities": [{"value": v, "role": r} for v, r in entities]}
    d.update(kw)
    return d


BEACON = {"id": "beacon-1", "label": "malicious", "behavior": "c2",
          "entities": [{"value": "10.0.0.5", "role": "initiator"},
                       {"value": "203.0.113.66", "role": "target"}]}


def test_initiator_detection_surfaces_and_target_is_not_an_unrelated_fp():
    # a finding naming BOTH the malicious initiator and the C2 target surfaces the episode and
    # is a relevant item — the target is part of the episode, not an unrelated false positive.
    d = _det([("10.0.0.5", "src"), ("203.0.113.66", "dst")], behavior="c2")
    r = ep.score([d], [BEACON])
    assert r["episode_recall"] == 1.0 and r["false_items"] == 0 and r["relevant_items"] == 1


def test_benign_host_detection_is_a_false_item():
    d = _det([("10.0.0.10", "src")], behavior="c2")            # unrelated benign host
    r = ep.score([d], [BEACON])
    assert r["episode_recall"] == 0.0 and r["false_items"] == 1 and r["relevant_items"] == 0


def test_benign_endpoint_inside_malicious_flow_not_double_counted():
    # detection implicates the malicious initiator + a benign peer: one relevant item, episode TP,
    # the benign peer does NOT become its own FP.
    d = _det([("10.0.0.5", "src"), ("10.0.0.99", "dst")], behavior="c2")
    r = ep.score([d], [BEACON])
    assert r["relevant_items"] == 1 and r["false_items"] == 0 and r["episode_recall"] == 1.0


def test_duplicates_count_episode_once():
    d1 = _det([("10.0.0.5", "src")], behavior="c2")
    d2 = _det([("10.0.0.5", "src")], behavior="c2")
    r = ep.score([d1, d2], [BEACON])
    assert r["episodes_surfaced"] == 1 and r["relevant_items"] == 2   # one incident, two items


def test_revisions_dedup_by_finding_id():
    d1 = _det([("10.0.0.5", "src")], behavior="c2", finding_id="f1")
    d2 = _det([("10.0.0.5", "src")], behavior="c2", finding_id="f1")   # a revision
    r = ep.score([d1, d2], [BEACON])
    assert r["analyst_items"] == 1 and r["relevant_items"] == 1


def test_multiple_episodes_per_host_scored_separately():
    e1 = {"id": "a", "label": "malicious", "behavior": "c2",
          "entities": [{"value": "10.0.0.5", "role": "initiator"}]}
    e2 = {"id": "b", "label": "malicious", "behavior": "recon",
          "entities": [{"value": "10.0.0.5", "role": "initiator"}]}
    c2 = _det([("10.0.0.5", "src")], behavior="c2")
    r = ep.score([c2], [e1, e2])
    assert r["episodes_surfaced"] == 1 and r["episodes_missed"] == 1     # only the c2 episode

    scan = _det([("10.0.0.5", "src")], behavior="recon")
    assert ep.score([c2, scan], [e1, e2])["episode_recall"] == 1.0       # both now surfaced


def test_same_ip_different_tenants_do_not_cross_match():
    epA = dict(BEACON, tenant="A")
    dB = _det([("10.0.0.5", "src")], behavior="c2", tenant="B")
    assert ep.score([dB], [epA])["episode_recall"] == 0.0


def test_ipv6_entities():
    e6 = {"id": "v6", "label": "malicious", "behavior": "c2",
          "entities": [{"value": "2001:db8::5", "role": "initiator"}]}
    d = _det([("2001:db8::5", "src")], behavior="c2")
    assert ep.score([d], [e6])["episode_recall"] == 1.0


def test_zero_detections_is_full_miss_not_a_crash():
    r = ep.score([], [BEACON])
    assert r["episode_recall"] == 0.0 and r["analyst_precision"] == 0.0 and r["episodes_missed"] == 1


def test_interval_excludes_out_of_window_detection():
    ep_t = dict(BEACON, interval={"start": 100.0, "end": 200.0})
    inside = _det([("10.0.0.5", "src")], behavior="c2", interval={"start": 150.0, "end": 160.0})
    outside = _det([("10.0.0.5", "src")], behavior="c2", interval={"start": 900.0, "end": 910.0})
    assert ep.score([inside], [ep_t])["episode_recall"] == 1.0
    assert ep.score([outside], [ep_t])["episode_recall"] == 0.0


def test_unknown_episode_match_is_unscored_not_false():
    unk = {"id": "u", "label": "unknown", "behavior": "c2",
           "entities": [{"value": "10.9.9.9", "role": "initiator"}]}
    d = _det([("10.9.9.9", "src")], behavior="c2")
    r = ep.score([d], [BEACON, unk])
    assert r["unscored_items"] == 1 and r["false_items"] == 0 and r["relevant_items"] == 0


def test_behavior_class_subsumes_detector_technique():
    # an 'exfil' episode is surfaced by a dns_tunnel detector category (technique -> class)
    exfil_ep = {"id": "x", "label": "malicious", "behavior": "exfil",
                "entities": [{"value": "10.0.0.9", "role": "initiator"}]}
    d = _det([("10.0.0.9", "src")], behavior="dns_tunnel")
    assert ep.score([d], [exfil_ep])["episode_recall"] == 1.0


def test_behavior_incompatible_detection_does_not_surface():
    d = _det([("10.0.0.5", "src")], behavior="recon")          # wrong behaviour for a c2 episode
    assert ep.score([d], [BEACON])["episode_recall"] == 0.0


def test_incomplete_detection_is_graceful():
    assert ep.score([{"entities": []}, {}], [BEACON])["episode_recall"] == 0.0


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f(); print("ok", _n)
    print("all episode-scorer tests passed")
