# 012: entity risk caps correlated signal families, it does not sum detectors

Status: implemented, pending independent review.

`correlate.entity_risk` deduped per `detector_id` — "one chatty detector cannot
inflate the score" — and then summed those contributions as if each detector
were independent evidence. Several of Cernity's detectors are not independent:
they describe THE SAME underlying behavior under different ids.

- `beacon` and `beacon_fqdn` are one periodic callback, keyed by destination IP
  versus resolved domain.
- `long_connection` and `long_connection_cumulative` overlap by construction;
  `behavioral-detectors/detectors.py` documents the overlap itself.
- `strobe` reads the same (entity, destination) connection series as `beacon`.
- `dns_tunnel`, `dns_exploded`, `dga_domain` and `nxdomain_burst` all read one
  qname series.
- `exfil` and `low_slow_exfil` read one outbound-byte series to one pair.
- `ja4_novelty`, `ja4_transition_burst` and `server_fp_rarity` read one TLS
  handshake series.

So a single real behavior — one host beaconing to one destination — could post
five independent severity contributions and trip the `risk-threshold` incident
path on its own. Correlated indicators share causes; adding them is double
counting, and it inflates exactly the entities an analyst most needs ranked
honestly.

Decision: per-`detector_id` dedup and the existing time decay are unchanged, and
those contributions are then grouped into **signal families** whose SUM is
capped per family. Total risk is the sum of the capped family totals.

- `FAMILY` maps detector_id to one of `fingerprint`, `temporal`, `volume`,
  `dns`, `destination`, `signature`. A detector_id **absent** from the map is its
  own family, so unmapped and future detectors keep today's behavior exactly and
  nothing silently loses weight.
- `FAMILY_CAP` scales the per-family ceilings to Cernity's 1..10 severity scale,
  keeping their relative proportions and putting the largest family at 10.0 —
  one maximum-severity finding, below the 12.0 `risk_threshold`. The property
  this buys: **no single behavior, however many detector_ids describe it, can
  alone trip an incident, while two independent behaviors still can.** Caps are
  tunable through the `params` dict, not hardcoded at the call site.
- `risk_families` returns the per-family breakdown (`raw`, `capped`, `cap`,
  `detectors`) and `build_incident` carries it as a `risk_families` element,
  appended rather than inserted — downstream consumers index the `entities`
  payload positionally. An incident therefore shows WHICH behavior was capped
  and by how much, instead of just a smaller number.
- The kill-chain and multi-tactic incident triggers are untouched. Only the
  `risk-threshold` trigger changes, and it changes by reading a non-inflated
  score.

What this is NOT: a confidence model. Capping says "this is one behavior, count
it once at its family's weight". It does not model observation quality — a
beacon seen while the sensor was dropping packets still carries full confidence.
Quality-aware confidence needs per-finding sensor attribution, which not every
detector emits yet; it is tracked separately and deliberately out of scope here.

Related: decision 011 (the JA4 detectors this places in the `fingerprint`
family).
