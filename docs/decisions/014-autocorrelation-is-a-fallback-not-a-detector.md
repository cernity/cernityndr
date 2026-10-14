# 014: autocorrelation is a jitter/gap-tolerant fallback, not a second beacon detector

Status: implemented, pending independent review.

`beacon_score` judges the INTERVAL DISTRIBUTION with outlier-robust statistics
(Bowley skewness + median absolute deviation, weighted by connection count).
That is the right first cut and it is what RITA does. Two real C2 patterns defeat
a distribution measure, both for the same reason:

- **Missed callbacks** — host asleep, sensor drop, network outage. A skipped beat
  turns one interval into 2P or 3P, and a quartile measure reads that as
  dispersion rather than as a harmonic of one period. A 1-in-3 drop rate alone
  pushes `beacon_score` to ~0.67, measured in `test_detectors.py`, which is below
  its 0.80 gate.
- **Jitter stacked on those gaps**, which compounds the same collapse.

Autocorrelating a BINNED EVENT-COUNT series survives both, because a missed beat
is a missing sample rather than a wrong interval: the beats that did arrive still
line up with themselves one period later.

Decision: add `autocorr_period` / `beacon_autocorr` as a **fallback behind**
`beacon_score`, not as a detector of its own.

- **Same `detector_id`.** A destination that fires the regularity scorer is never
  also scored by autocorrelation, and a fallback hit emits `beacon` /
  `beacon_fqdn` exactly as a regular hit does. A new detector_id would have
  escaped the `temporal` family cap that decision 012 put on
  beacon/beacon_fqdn/strobe, so one callback series could have posted two
  independent risk contributions — the precise defect 012 exists to prevent.
  The strobe exclusion also honors a fallback hit, so a periodic destination is
  reported as a beacon, never additionally as a strobe.
- **Same noise gating.** The fallback runs inside the loop that only ever sees
  destinations which already passed `beacon_noise_dst` at write time, and the
  FQDN path keeps its IP-rotation gate. A fallback must not re-open a noise path
  the primary scorer deliberately closed.
- **Same score shape.** `(2*strength + count)/3`, deliberately `beacon_score`'s
  formula with autocorrelation strength standing in for interval regularity, so
  a finding's confidence means the same thing whichever method produced it. The
  gate is 0.70 rather than 0.80 because a gap-ridden series' peak correlation is
  structurally below a clean regularity score.
- **The method is on the finding.** `method` (`regularity` | `autocorrelation`)
  and `period_secs` are carried in the entities payload, so an analyst can tell a
  jitter-tolerant hit from a regular one and see the recovered period. These are
  timing estimates, not evidence the destination is malicious.

Three implementation choices worth recording, each with its ceiling named.

**Bin width comes from the lower quartile of the intervals, not the median.** A
gap-ridden series' intervals are BIMODAL — P and 2P — where the median straddles
the two modes and flips with the drop phase, while Q1 stays on the fundamental.
The cost: an unrelated burst to the same destination shrinks Q1 and can push the
real period off the lag grid. A burst-contaminated series is out of scope; the
robust scorer degrades on it too.

**Two independent lag bounds.** `max_lag_fraction` exists because an ACF estimate
at a lag near the series length is computed from almost no overlapping pairs — it
is noise dressed as a correlation. `min_cycles` exists because a "period" the
window covers only once or twice is not periodicity. Separately, `max_bins` caps
the series length so the O(bins × lags) work is bounded for ANY span; a day-long
window at one-second bins would otherwise be ~1e9 multiply-adds per destination
per evaluate cycle. Over the cap, the most RECENT `max_bins` bins are analysed at
full resolution rather than coarsening bins across the whole span — a dominant
period is better recovered from a shorter slice than smeared across bins wider
than the period itself.

**Raw timing strength must independently clear a floor.** Payload-size
regularity is blended into the strength the way `beacon_score` blends it, because
periodic timing alone also describes benign polling with variable responses. But
with constant flow sizes the size term is 1.0, which alone would reduce the 0.70
gate to an autocorrelation strength of ~0.10 — below the noise floor of a
many-lag ACF peak — and reintroduce false positives on exactly the random traffic
the fallback must stay silent on. So the timing strength is gated separately at
`min_strength` before the blended score is considered. Constant payload sizes
cannot establish a dominant period.

**What is NOT claimed.** Autocorrelation recovers a dominant period; it does not
prove C2 — schedulers, update checks and health probes are periodic too, which is
why this stays a fallback rather than a detector. And it is **not** a general
solution to heavy jitter: per-sleep independent randomisation random-walks the
beacon's phase, so at roughly ±50% per-interval jitter the autocorrelation peak
decays along with it. That case is often better served by the robust interval
statistics above. Recovery of large jitter depends on the observed realization and
is not a guarantee for arbitrary randomized sleep sequences.

The harmonic correction — report the smallest divisor lag carrying a near-peak
correlation, so the fundamental is reported rather than 2P or 3P — is deliberately
a loose heuristic. At a 1-in-3 drop rate the fundamental's own correlation is only
~0.3 of the peak, so the tolerance has to be wide; restricting candidates to
divisors of the peak lag is what keeps it from wandering onto an unrelated small
lag. Consequence: a destination carrying two interleaved rhythms reports the
shorter one.

Related: decision 012 (the `temporal` family cap that reusing the `beacon`
detector_id keeps intact).
