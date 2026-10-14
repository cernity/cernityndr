"""U8 behavioral detector tests (pure)."""
import random
import time

import detectors as d


# --- helpers for the autocorrelation tests (deterministic: fixed seeds only) ----
def _beats(period=60.0, n=30, drop_every=0, jitter=0.0, seed=1337):
    """A synthetic callback series: `n` scheduled beats at `period`, every
    `drop_every`-th one missed, each surviving beat displaced by up to
    +/-`jitter`*period. The jitter is PHASE jitter (relative to the schedule, not to
    the previous callback), which is what makes successive INTERVALS vary by up to
    +/-2*jitter of the period."""
    rnd = random.Random(seed)
    return [i * period + rnd.uniform(-jitter * period, jitter * period)
            for i in range(n) if not (drop_every and i % drop_every == 0)]


def _poisson(rate_secs=60.0, n=40, seed=7):
    """Memoryless arrivals — the false-positive control that matters most: random
    traffic has no period, so a periodicity detector must stay silent on it."""
    rnd = random.Random(seed)
    out, t = [], 0.0
    for _ in range(n):
        t += rnd.expovariate(1.0 / rate_secs)
        out.append(t)
    return out


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


# --- Autocorrelation periodicity (jitter/gap-tolerant beacon fallback) ---------
def test_autocorr_recovers_clean_fixed_interval_period():
    period, strength, bin_secs = d.autocorr_period(_beats(60.0, n=30))
    assert abs(period - 60.0) <= bin_secs       # within one bin width
    assert strength > 0.9


def test_autocorr_catches_gapped_beacon_the_regularity_scorer_misses():
    # Every 3rd callback missed (host asleep, sensor drop, dropped packet). One interval
    # in three is then 2x the period: dispersion to a quartile measure, a harmonic to an
    # autocorrelation. BOTH halves are asserted -- the robust scorer must fail and the
    # fallback must fire -- because that is what makes the capability new, not redundant.
    ts = _beats(60.0, n=45, drop_every=3)
    assert len(ts) == 30
    is_reg, reg_score = d.beacon_score(ts)
    assert not is_reg and reg_score < 0.70                    # measured ~0.67
    is_ac, ac_score, period = d.beacon_autocorr(ts)
    assert is_ac and ac_score > 0.90
    assert abs(period - 60.0) <= 30.0                          # one bin width (Q1/2)


def test_autocorr_catches_jittered_gapped_beacon():
    # Jitter ON TOP of the gaps: +/-15% of the period in phase, so successive intervals
    # vary by up to +/-30%, plus a 1-in-3 drop rate. The regularity scorer collapses;
    # autocorrelation still detects repetition. With jitter the fundamental can
    # weaken below the harmonic tolerance, leaving the three-beat pattern dominant.
    ts = _beats(60.0, n=90, drop_every=3, jitter=0.15, seed=4242)
    assert not d.beacon_score(ts)[0]
    is_ac, ac_score, period = d.beacon_autocorr(ts)
    assert is_ac and ac_score >= 0.70
    assert abs(period - 180.0) <= 0.25 * 60.0                  # dominant three-beat pattern


def test_compounding_sleep_jitter_stays_with_the_regularity_scorer():
    # The ceiling, asserted rather than claimed: with per-sleep jitter (sleep 60 +/-50%,
    # each sleep independent of the last) the beacon's PHASE random-walks, so the
    # autocorrelation peak decays with it and this fallback does not recover the period.
    # That case is exactly what the outlier-robust interval statistics are good at, and
    # they fire on this realization; other short windows can still be missed.
    rnd = random.Random(99)
    ts, t = [], 0.0
    for _ in range(40):
        ts.append(t)
        t += 60.0 * (1 + rnd.uniform(-0.5, 0.5))
    assert d.beacon_score(ts)[0]                  # primary scorer owns this pattern
    assert not d.beacon_autocorr(ts)[0]           # and the fallback does not pretend to


def test_autocorr_reports_the_fundamental_not_a_harmonic():
    # A true period P also correlates at 2P and 3P, and with a 1-in-3 drop rate the
    # multiple is the STRONGER peak. All three drop phases must still report ~P.
    for phase in (0, 1, 2):
        ts = [i * 60.0 for i in range(46) if i % 3 != phase]
        period, strength, bin_secs = d.autocorr_period(ts)
        assert strength > 0.9 and abs(period - 60.0) <= bin_secs, (phase, period)


def test_autocorr_ignores_random_traffic():
    # The false-positive control that matters more than any positive case.
    for seed in range(20):
        fired, score, _ = d.beacon_autocorr(_poisson(60.0, 40, seed))
        assert not fired, (seed, score)
    for seed in range(8):          # few connections: where the ACF noise floor is highest
        fired, score, _ = d.beacon_autocorr(_poisson(60.0, 12, seed))
        assert not fired, (seed, score)


def test_autocorr_ignores_dense_unstructured_stream():
    # ~1 conn/s with no period at all. (An EXACTLY uniform 1/s stream is genuinely
    # periodic and the regularity scorer fires on it, so the fallback never sees it --
    # the meaningful control for "steady but not periodic" is this one.)
    rnd = random.Random(11)
    ts = sorted(rnd.uniform(0.0, 600.0) for _ in range(600))
    assert not d.beacon_autocorr(ts)[0]


def _constant_size_noise_cases():
    # Match production's constant-size flows, including heavy tails and short windows
    # where selecting the largest ACF lag gives noise the most chances to look periodic.
    for distribution, counts in (("poisson", (12, 40)), ("lognormal", (20, 60, 120))):
        for n in counts:
            for seed in range(200):
                rnd = random.Random(seed)
                ts = [0.0]
                for _ in range(n - 1):
                    interval = (rnd.expovariate(1 / 60.0) if distribution == "poisson"
                                else rnd.lognormvariate(0.0, 2.0))
                    ts.append(ts[-1] + interval)
                # Fit the whole series inside the app's window; scaling preserves ACF.
                ts = [t * 500.0 / ts[-1] for t in ts]
                yield (distribution, n, seed), ts


def test_autocorr_constant_sizes_cannot_rescue_noise():
    eligible = 0
    blocked_by_floor = 0
    for case, ts in _constant_size_noise_cases():
        sizes = [1448] * len(ts)
        if d.beacon_score(ts, sizes)[0]:
            continue                         # only new fallback findings are in scope
        eligible += 1
        hit, score, period = d.beacon_autocorr(ts, sizes)
        assert not hit, (case, score, period)
        blocked_by_floor += d.beacon_autocorr(ts, sizes, min_strength=0.0)[0]
    assert eligible > 100                     # ensure the primary did not mask the sweep
    assert blocked_by_floor > 0               # the old blend really did fire on this corpus


def test_app_constant_size_noise_does_not_emit_beacons():
    import app
    import store
    from unittest.mock import Mock, patch

    memory = store.make_store("memory")
    now = time.time()
    eligible = 0
    for case, ts in _constant_size_noise_cases():
        if d.beacon_score(ts, [1448] * len(ts))[0]:
            continue
        eligible += 1
        tenant = "noise-" + "-".join(map(str, case))
        for t in ts:
            for key in (f"bc:0:{tenant}:10.0.0.3|203.0.113.25",
                        f"bf:0:{tenant}:10.0.0.3|noise.example"):
                memory.window_add(key, now - 550 + t, 1448, 600)
        for ip in ("203.0.113.25", "203.0.113.26"):
            memory.set_add(f"fi:{tenant}:10.0.0.3|noise.example", ip, 600)
    producer = Mock()
    with patch.object(app, "_store", memory), patch.object(app, "AUTOCORR", True), \
         patch.object(app, "AUTOCORR_KW", {}), patch.object(app.time, "time", return_value=now), \
         patch.object(app.log, "info"), \
         patch.object(d, "beacon_autocorr", wraps=d.beacon_autocorr) as fallback:
        app.evaluate(producer)
    assert fallback.call_count == 2 * eligible > 200
    assert all(call.args[1] == [1448] * len(call.args[0]) for call in fallback.call_args_list)
    assert not any(call.args[1]["detector_id"] in ("beacon", "beacon_fqdn")
                   for call in producer.send.call_args_list)


def test_autocorr_degenerate_input_never_fires_or_raises():
    for ts in ([], [5.0], [0.0, 60.0, 120.0], [100.0] * 20, [7.5] * 40):
        assert d.autocorr_period(ts)[:2] == (0.0, 0.0), ts     # no period, no exception
        assert d.beacon_autocorr(ts)[0] is False, ts
    # Duplicates remain counts, but a zero median cannot establish a bin scale.
    dupes = sorted([i * 60.0 for i in range(12)] * 3)
    assert d.autocorr_period(dupes)[:2] == (0.0, 0.0)
    assert not d.beacon_autocorr(dupes)[0]
    for ts in ([float("nan")] * 12, [0.] * 8 + [float("inf")]):
        assert d.autocorr_period(ts)[:2] == (0.0, 0.0)
    for kw in ({"min_cycles": 0}, {"max_bins": 100000}, {"bins_per_period": 0},
               {"max_lag_fraction": 1.0}):
        assert d.autocorr_period(_beats(), **kw)[:2] == (0.0, 0.0)


def test_autocorr_catches_large_sleep_jitter_missed_by_regularity():
    # A fixed short-window realization of independent +/-50% sleep jitter.
    # This demonstrates additional coverage, not reliable recovery for every seed:
    # long random walks lose phase coherence (the ceiling test above).
    rnd = random.Random(144)
    ts = [0.0]
    for _ in range(11):
        ts.append(ts[-1] + rnd.uniform(30.0, 90.0))
    assert not d.beacon_score(ts)[0]
    hit, score, period = d.beacon_autocorr(ts)
    assert hit, score
    assert abs(period - 60.0) < 15.0


def test_autocorr_lag_count_stays_bounded_on_a_long_span():
    # A day of 1s callbacks. Unbounded, this is 86400 bins x ~21600 lags (~1e9
    # multiply-adds) per destination per evaluate cycle; the max_bins cap analyses the
    # most recent bins at full resolution instead, so the cost is bounded and the period
    # is still recovered. Measured ~20ms, so the 2s bound only catches a lost cap.
    ts = [float(i) for i in range(86400)]
    t0 = time.monotonic()
    from unittest.mock import patch
    with patch.object(d, "range", wraps=range, create=True) as ranges:
        period, strength, bin_secs = d.autocorr_period(ts)
    assert max(call.args[-1] for call in ranges.call_args_list) <= 512
    elapsed = time.monotonic() - t0
    assert abs(period - 1.0) <= bin_secs and strength > 0.9
    assert elapsed < 2.0, elapsed
    assert (ts[-1] - ts[0]) / bin_secs > 1000       # span really is far wider than the cap


def test_beacon_autocorr_shares_the_connection_count_confidence():
    # Same (2*regularity + count)/3 shape as beacon_score, with autocorrelation strength
    # standing in for regularity, so the two scores mean the same thing to a consumer.
    few = d.beacon_autocorr(_beats(60.0, n=9))[1]
    many = d.beacon_autocorr(_beats(60.0, n=40))[1]
    assert many > few > 0
    assert d.beacon_autocorr(_beats(60.0, n=6))[0] is False      # below min_conns


def _variable_payload_polling():
    rnd = random.Random(0)
    ts = [i * 25.0 + rnd.uniform(-1.0, 1.0) for i in range(20)]
    return ts, [rnd.lognormvariate(6.0, 4.0) for _ in ts]


def test_autocorr_preserves_payload_size_signal():
    ts, sizes = _variable_payload_polling()
    assert d.beacon_score(ts)[0]
    assert not d.beacon_score(ts, sizes)[0]   # sizes alone suppress the primary
    timing_hit, timing_score, period = d.beacon_autocorr(ts)
    hit, score, sized_period = d.beacon_autocorr(ts, sizes)
    assert timing_hit and not hit
    assert score < timing_score and sized_period == period
    strength = d.autocorr_period(ts)[1]
    expected = round((strength + d._regularity(sizes) + d._count_score(len(ts), 12)) / 3, 3)
    assert score == expected                 # same 50/50 blend as beacon_score
    assert d.beacon_autocorr(ts, [512] * len(ts))[0]
    for insufficient in (None, [], sizes[:7]):
        assert d.beacon_autocorr(ts, insufficient) == d.beacon_autocorr(ts)


def test_app_fallback_preserves_payload_size_signal():
    import app
    import store
    from unittest.mock import Mock, patch

    ts, sizes = _variable_payload_polling()
    memory = store.make_store("memory")
    now = time.time()
    for t, size in zip(ts, sizes):
        for key in ("bc:0:payload:10.0.0.3|203.0.113.25",
                    "bf:0:payload:10.0.0.3|polling.example"):
            memory.window_add(key, now - 550 + t, size, 600)
    for ip in ("203.0.113.25", "203.0.113.26"):
        memory.set_add("fi:payload:10.0.0.3|polling.example", ip, 600)
    producer = Mock()
    with patch.object(app, "_store", memory), patch.object(app, "AUTOCORR", True), \
         patch.object(app, "AUTOCORR_KW", {}), \
         patch.object(d, "beacon_autocorr", wraps=d.beacon_autocorr) as fallback:
        app.evaluate(producer)
    assert fallback.call_count == 2          # both suppressed primaries try fallback
    for call in fallback.call_args_list:
        assert call.args[1] == sizes        # IP and FQDN retain payload evidence
    assert not any(call.args[1]["detector_id"] in ("beacon", "beacon_fqdn")
                   for call in producer.send.call_args_list)


def test_app_beacon_fallback_does_not_double_emit():
    # The no-double-emit rule, at the app level: a destination that fires the regularity
    # scorer must NOT also yield an autocorrelation beacon, and both methods must emit
    # the SAME detector_id (correlate.py caps beacon/beacon_fqdn/strobe as one `temporal`
    # family; a new detector_id would escape that cap).
    import app                         # shared/ must be on the path; never silently skip
    import json
    import store

    class _P:
        def __init__(self):
            self.sent = []

        def send(self, _topic, msg):
            self.sent.append(msg)

        def flush(self):
            pass

    app._store = store.make_store("memory")
    now = time.time()
    regular, gapped = "203.0.113.11", "203.0.113.12"
    sizes = [400, 1200, 800, 2000]      # payload sizes VARY, as a real C2's responses do
    for dst, beats in ((regular, _beats(45.0, n=13)),
                       (gapped, _beats(45.0, n=15, drop_every=3))):
        for i, t in enumerate(beats):
            app._store.window_add(f"bc:0:t1:10.0.0.1|{dst}", now - 590 + t, sizes[i % 4], 600)
    prod = _P()
    from unittest.mock import patch
    with patch.object(d, "beacon_autocorr", wraps=d.beacon_autocorr) as fallback:
        app.evaluate(prod)
    assert fallback.call_count == 1               # primary hit never reaches fallback
    found = {}
    for m in prod.sent:
        if m["detector_id"] != "beacon":
            continue
        ents = json.loads(m["entities"])
        dst = next(e["value"] for e in ents if e.get("role") == "dst")
        found.setdefault(dst, []).append({e["type"]: e["value"] for e in ents if "role" not in e})
    assert len(found.get(regular, [])) == 1, found
    assert found[regular][0]["method"] == "regularity"
    assert found[regular][0]["period_secs"] == 45.0
    assert len(found.get(gapped, [])) == 1, found
    assert found[gapped][0]["method"] == "autocorrelation"
    assert abs(found[gapped][0]["period_secs"] - 45.0) <= 22.5
    assert sum(len(v) for v in found.values()) == 2       # no third beacon from the fallback


def test_app_fqdn_fallback_preserves_rotation_gate():
    import app
    import json
    import store
    from unittest.mock import patch

    class Producer:
        def __init__(self):
            self.sent = []
        def send(self, topic, msg):
            self.sent.append(msg)
        def flush(self):
            pass

    memory = store.make_store("memory")
    now = time.time()
    for domain, gaps, ips in (("regular.example", False, 2),
                              ("gapped.example", True, 2),
                              ("single.example", True, 1)):
        for i, t in enumerate(_beats(30., n=18, drop_every=3 if gaps else 0)):
            memory.window_add(f"bf:0:test:10.0.0.2|{domain}", now - 550 + t,
                              [400, 1200, 800, 2000][i % 4], 600)
        for i in range(ips):
            memory.set_add(f"fi:test:10.0.0.2|{domain}", f"203.0.113.{i}", 600)
    prod = Producer()
    with patch.object(app, "_store", memory), patch.object(app, "AUTOCORR", True), \
         patch.object(app, "AUTOCORR_KW", {}), \
         patch.object(d, "beacon_autocorr", wraps=d.beacon_autocorr) as fallback:
        app.evaluate(prod)
    assert fallback.call_count == 1
    found = {}
    for msg in prod.sent:
        if msg["detector_id"] == "beacon_fqdn":
            entities = json.loads(msg["entities"])
            assert [e["type"] for e in entities[:3]] == ["ip", "domain", "rotating_ips"]
            assert entities[-1]["type"] == "period_secs"
            found.setdefault(entities[1]["value"], []).append(entities[-2]["value"])
    assert found == {"regular.example": ["regularity"],
                     "gapped.example": ["autocorrelation"]}, found


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
    # F06: IPv6 ULA (fc00::/7) is internal; globally-routable v6 is external (parity
    # with the IPv4 private ranges, consistent across behavioral/protocol/east-west).
    assert not d.is_external("fd12:3456::1") and not d.is_external("fc00::1")
    assert d.is_external("2606:4700:4700::1111")


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




def test_low_slow_exfil():
    import detectors as d
    # sustained trickle below the 50MB burst ceiling, over many conns -> fires
    assert d.low_slow_exfil(10_000_000, 20, "8.8.8.8")[0]
    # a real burst is left to exfil_check (no double-fire)
    assert not d.low_slow_exfil(60_000_000, 20, "8.8.8.8")[0]
    # below the floor no-fire; too few conns no-fire; internal no-fire
    assert not d.low_slow_exfil(1_000_000, 20, "8.8.8.8")[0]
    assert not d.low_slow_exfil(10_000_000, 3, "8.8.8.8")[0]
    assert not d.low_slow_exfil(10_000_000, 20, "10.0.0.5")[0]
    # §49.4 distributed requirement: with per-flow evidence, bytes CONCENTRATED in one flow (+ many tiny
    # callbacks) is NOT distributed low-and-slow -> no fire; bytes SPREAD across many material flows fires.
    assert not d.low_slow_exfil(10_000_000, 20, "8.8.8.8", material_flows=1)[0]    # 1 bulk flow + callbacks
    assert d.low_slow_exfil(10_000_000, 20, "8.8.8.8", material_flows=8)[0]        # spread across 8 flows


if __name__ == "__main__":
    import inspect
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    ran = 0
    for fn in fns:
        if inspect.getfullargspec(fn).args:   # skip pytest-fixture tests (e.g. monkeypatch)
            continue
        fn(); print(f"ok  {fn.__name__}"); ran += 1
    print(f"\nall {ran} detector tests passed (fixture tests run under pytest)")
