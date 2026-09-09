"""U8 behavioral detector tests (pure)."""
import detectors as d


def test_beacon_fires_on_regular_interval():
    ts = [i * 60.0 for i in range(12)]          # exactly every 60s
    is_b, score = d.beacon_score(ts)
    assert is_b and score > 0.95


def test_beacon_ignores_jittered_human_traffic():
    ts = [0, 3, 40, 41, 300, 900, 905, 2000, 2001]  # bursty/irregular
    is_b, _ = d.beacon_score(ts)
    assert not is_b


def test_beacon_needs_minimum_connections():
    assert d.beacon_score([0, 60, 120])[0] is False   # only 3 < min


def test_beacon_multisignal_size_consistency():
    # RITA-style: a beacon is regular in BOTH interval and payload size.
    ts = list(range(0, 600, 60))            # 10 conns, perfectly regular interval
    # regular timing + consistent payload -> strong beacon
    is_b, score = d.beacon_score(ts, sizes=[512] * 10)
    assert is_b and score >= 0.9
    # regular timing but wildly varying payload -> combined score drops below the
    # gate, so it is NOT a beacon (the false positive interval-only would flag)
    is_b2, score2 = d.beacon_score(ts, sizes=[10, 5000, 20, 8000, 15, 9000, 30, 7000, 25, 6000])
    assert not is_b2 and score2 < score


def test_beacon_robust_to_jitter_outliers():
    # RITA's Bowley-skew + MADM scoring: a beacon at 60s with a couple of jittered
    # intervals still fires, because the quartile/median measures ignore outliers
    # that would inflate a coefficient-of-variation and let the beacon evade.
    ts = [0, 60, 120, 180, 240, 300, 360, 420, 480, 485, 605]  # 2 jittered gaps
    is_b, score = d.beacon_score(ts)
    assert is_b and score > 0.85


def test_beacon_score_weights_connection_count():
    # More callbacks = stronger evidence (RITA's connection-count factor). Same
    # perfect regularity, more connections -> higher score.
    few = d.beacon_score([i * 60.0 for i in range(6)])[1]     # 6 conns
    many = d.beacon_score([i * 60.0 for i in range(24)])[1]   # 24 conns
    assert many > few and few >= 0.80        # both fire, but many scores higher


def test_madm_and_skew_scores_reward_regularity():
    assert d._madm_score([60] * 10) == 1.0            # zero dispersion
    assert d._bowley_skew_score([60] * 10) == 1.0     # symmetric
    assert d._madm_score([1, 2, 3, 400, 5000]) < 0.4  # high dispersion -> low score


def test_strobe_fires_on_high_connection_count():
    is_s, score = d.strobe_check(150, "203.0.113.5", is_beacon=False)
    assert is_s and score > 0


def test_strobe_not_double_counted_with_beacon():
    assert d.strobe_check(150, "203.0.113.5", is_beacon=True)[0] is False


def test_strobe_ignores_internal_and_low_count():
    assert d.strobe_check(150, "10.0.0.5")[0] is False      # internal dst
    assert d.strobe_check(10, "203.0.113.5")[0] is False    # too few conns


# --- FQDN / SNI beaconing (fast-flux / CDN-fronted C2) -------------------------
def test_fqdn_beacon_fires_on_rotating_domain():
    ts = [i * 60.0 for i in range(12)]                      # regular callbacks
    is_b, score = d.fqdn_beacon(ts, [512] * 12, n_distinct_ips=4)  # 4 rotating IPs
    assert is_b and score > 0.8


def test_fqdn_beacon_defers_single_ip_to_ip_beacon():
    # a domain on ONE stable IP is already covered by beacon_score -> don't fire
    ts = [i * 60.0 for i in range(12)]
    assert d.fqdn_beacon(ts, [512] * 12, n_distinct_ips=1)[0] is False


def test_fqdn_beacon_ignores_irregular_rotation():
    # rotating across many IPs but irregular timing is not a beacon
    ts = [0, 3, 40, 300, 900, 2000, 2001, 5000]
    assert d.fqdn_beacon(ts, None, n_distinct_ips=6)[0] is False


def test_dns_tunnel_fires_on_long_highentropy_queries():
    q = [f"{d.shannon_entropy.__name__}x9f8a7b6c5d4e3f2a1b0-{i}.tunnel.example.com" for i in range(60)]
    is_t, score = d.dns_tunnel_score(q)
    assert is_t and score > 0.4


def test_dns_tunnel_ignores_normal_lookups():
    q = ["google.com", "apple.com", "cloudflare.com"] * 30
    assert d.dns_tunnel_score(q)[0] is False


def test_exfil_fires_on_large_external_transfer():
    is_e, score = d.exfil_check(120_000_000, "8.8.8.8")
    assert is_e and score > 0


def test_exfil_ignores_internal_and_small():
    assert d.exfil_check(120_000_000, "192.168.222.5")[0] is False   # internal dst
    assert d.exfil_check(1_000_000, "8.8.8.8")[0] is False           # small


def test_exfil_allowlist_excludes_trusted_dst(monkeypatch):
    # NDR_EXFIL_ALLOWLIST excludes a trusted external dst from exfil, without
    # marking it internal (so is_external stays True for other detectors).
    monkeypatch.setattr(d, "_EXFIL_ALLOW", ("160.79.104.", "160.79.105."))
    assert d.exfil_check(120_000_000, "160.79.104.10")[0] is False   # Anthropic, allowlisted
    assert d.is_external("160.79.104.10") is True                    # still external elsewhere
    assert d.exfil_check(120_000_000, "8.8.8.8")[0] is True          # non-allowlisted still fires


def test_is_external():
    assert d.is_external("8.8.8.8") and not d.is_external("10.0.0.5")
    assert not d.is_external("192.168.222.9") and not d.is_external("fe80::1")


def test_multicast_and_broadcast_not_external():
    # the big homelab noise sources must not count as external
    for ip in ("239.255.255.250", "224.0.0.251", "233.89.188.1",
               "255.255.255.255", "ff02:0000:0000:0000:0000:0000:0000:00fb"):
        assert d.is_multicast(ip), ip
        assert not d.is_external(ip), ip


def test_beacon_noise_dst_excludes_multicast_and_resolvers():
    assert d.beacon_noise_dst("239.255.255.250")   # SSDP
    assert d.beacon_noise_dst("1.1.1.1")           # resolver
    assert not d.beacon_noise_dst("34.235.4.153")  # real external host


def test_ndpi_risk_hit():
    hit, m = d.ndpi_risk_hit(["Malicious JA3", "Known Proto on Non Std Port"])
    assert hit and len(m) == 2
    assert d.ndpi_risk_hit(["HTTP Numeric IP Address"]) == (False, [])
    assert d.ndpi_risk_hit([]) == (False, [])


def test_ndpi_breed():
    assert d.ndpi_breed_hit("Dangerous") and d.ndpi_breed_hit("Potentially Dangerous")
    assert not d.ndpi_breed_hit("Safe") and not d.ndpi_breed_hit("Acceptable")
    assert not d.ndpi_breed_hit(None)


def test_longconn():
    assert d.longconn_check(7200, "8.8.8.8")[0]        # 2h external
    assert not d.longconn_check(7200, "10.0.0.5")[0]   # internal
    assert not d.longconn_check(60, "8.8.8.8")[0]      # short


def test_rare_dest():
    known = {f"1.1.1.{i}" for i in range(20)}
    assert d.is_rare_dest(known, "203.0.113.9")        # new external, has history
    assert not d.is_rare_dest(known, "1.1.1.5")        # already known
    assert not d.is_rare_dest(known, "10.0.0.9")       # internal
    assert not d.is_rare_dest({"1.1.1.1"}, "203.0.113.9")  # too little history


def test_threat_gate_escalates_and_deprioritizes():
    # dangerous breed / malicious risk / TI hit / DGA -> escalate
    assert d.dst_threat_score("dangerous") == 2
    assert d.dst_threat_score("", ["NDPI_MALICIOUS_JA3"]) == 2
    assert d.dst_threat_score("safe", [], ti_hit=True) == 2
    assert d.dst_threat_score("", [], dga=True) == 2
    # safe app, no risk -> de-prioritize
    assert d.dst_threat_score("safe", []) == -2
    # unknown -> neutral
    assert d.dst_threat_score("", []) == 0


def test_gated_severity_clamps():
    assert d.gated_severity(7, "dangerous") == 9          # beacon to dangerous dst
    assert d.gated_severity(7, "safe") == 5               # beacon to safe app sinks
    assert d.gated_severity(8, "", ["malicious"]) == 10   # exfil to malicious dst
    assert d.gated_severity(1, "safe") == 1               # clamp floor


# --- Per-asset / environment-prevalence baseline (request #4) -----------------
def test_env_prevalence_escalates_rare_and_deprioritizes_common():
    assert d.env_prevalence_delta(1) == 1        # only this asset contacts it -> escalate
    assert d.env_prevalence_delta(2) == 1        # still rare
    assert d.env_prevalence_delta(5) == 0        # in between -> neutral
    assert d.env_prevalence_delta(9) == -1       # fleet-wide common -> de-prioritize
    assert d.env_prevalence_delta(None) == 0     # unknown -> no effect (backward compat)


def test_gated_severity_prevalence_reduces_false_positives():
    # a beacon to a fleet-wide-common destination sinks below the suppression floor
    assert d.gated_severity(7, "", [], env_assets=9) == 6      # common -> 7-1
    # a beacon to a destination almost nobody contacts rises
    assert d.gated_severity(7, "", [], env_assets=1) == 8      # rare -> 7+1
    # prevalence stacks with hostility but stays clamped
    assert d.gated_severity(8, "dangerous", [], env_assets=1) == 10  # +2 +1 clamped
    # backward compatible: no env_assets == old behavior
    assert d.gated_severity(7, "") == 7


# --- RITA cumulative long-connection ------------------------------------------
def test_longconn_cumulative_fires_on_reconnect_pattern():
    # 6 connections of 120s each = 720s total to an external dst
    is_lc, score = d.longconn_cumulative_check(720.0, 6, "203.0.113.9", threshold_secs=600.0)
    assert is_lc and score > 0


def test_longconn_cumulative_ignores_few_connections():
    # one long flow is longconn_check's job, not the cumulative detector
    assert d.longconn_cumulative_check(5000.0, 1, "203.0.113.9", threshold_secs=600.0)[0] is False


def test_longconn_cumulative_ignores_internal_dst():
    assert d.longconn_cumulative_check(9999.0, 50, "10.0.0.5", threshold_secs=600.0)[0] is False


# --- RITA exploded DNS (unique subdomains per registered parent) ---------------
def test_registered_parent_handles_two_level_tld():
    assert d.registered_parent("a.b.tunnel.evil.co.uk") == "evil.co.uk"
    assert d.registered_parent("x.y.z.evil.com") == "evil.com"


def test_dns_exploded_fires_on_many_subdomains():
    qnames = [f"seg{i}.tunnel.evil.com" for i in range(40)]   # 40 unique subdomains, one parent
    is_x, score, parent = d.dns_exploded_score(qnames, min_subdomains=30)
    assert is_x and parent == "evil.com" and score > 0


def test_dns_exploded_ignores_normal_browsing():
    # varied parents, few subdomains each -> no single tunnel parent
    qnames = ["www.google.com", "api.github.com", "cdn.site.net", "mail.proton.me"] * 5
    assert d.dns_exploded_score(qnames, min_subdomains=30)[0] is False


def test_dns_exploded_ignores_repeated_same_query():
    # 100 identical queries = 1 unique subdomain, not a tunnel
    assert d.dns_exploded_score(["host.example.com"] * 100, min_subdomains=30)[0] is False


if __name__ == "__main__":
    import inspect
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    ran = 0
    for fn in fns:
        if inspect.getfullargspec(fn).args:   # skip pytest-fixture tests (e.g. monkeypatch)
            continue
        fn(); print(f"ok  {fn.__name__}"); ran += 1
    print(f"\nall {ran} detector tests passed (fixture tests run under pytest)")
