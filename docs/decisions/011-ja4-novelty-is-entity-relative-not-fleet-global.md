# 011: JA4 novelty is entity-relative; fleet popularity is context, not trust

Status: implemented, pending independent review.

`protocol-detectors` scored a TLS client fingerprint against ONE global
per-tenant seen-set: `ja4_rarity` fired when a fingerprint had never been seen
anywhere in the fleet, past a warmup of 5 distinct fingerprints and with a
one-day TTL. That is the wrong question in four ways, and the detector it
produced was close to unusable:

- **The actual signal was invisible.** "This workstation's TLS stack just
  changed" is the behavioral tell — a host that starts speaking a Go or Python
  TLS stack where it previously spoke only a browser's. A global set cannot see
  it: if any server anywhere in the fleet already used that fingerprint, the
  first appearance on a new host produced nothing at all.
- **Popularity became permanent trust.** One environment-wide allowlist means a
  fingerprint shared by both browsers and malware is clean forever, everywhere.
- **The baseline was never mature.** Five distinct fingerprints is not a
  baseline, and a one-day TTL emptied the set daily — so everything was novel at
  startup and the detector re-alerted on the same benign fingerprints on a
  rolling 24-hour cycle.
- **Standalone novelty was mid-severity.** Severity 5 / confidence 0.5 for a new
  fingerprint, when browser point-releases, VPN clients, software rollouts and
  middlebox TLS re-origination all legitimately introduce new fingerprints.

Decision: client-side JA4 novelty is scored **per source entity**, with the
fleet as context rather than as the baseline.

- **Validation gates features.** `proto.ja4_valid` must accept the string before
  any part of it is used; `ja4_parts` / `ja4_ac` return nothing for an invalid
  one. A fingerprint that arrives pre-flattened to a bare hash has no A/B/C
  parts and therefore no AC key — it must not be invented. An invalid JA4 falls
  back to the legacy JA3 rarity path and never pollutes the AC baseline.
- **Maturity requires traffic AND coverage.** `baseline_maturity` returns
  `cold` / `warming` / `ready` from both an observation count and an elapsed
  span. Elapsed idle time alone cannot warm a host, and a busy host cannot warm
  in an hour. Below `ready` the detector is learn-only: it emits nothing and
  still records the observation. The baseline TTL expires on **inactivity**, not
  on a tumbling deadline — an earlier revision used a tumbling counter, which
  meant any entity below ~14 TLS events/day could never reach `ready` and every
  entity went un-covered for one day in seven.
- **Fleet rarity counts ENTITIES, not events.** `JA4_RARE_IN_FLEET` is keyed by
  how many distinct entities have presented the fingerprint. The old global set
  could not distinguish one host using a fingerprint a thousand times from a
  thousand hosts using it once.
- **Standalone novelty is informational.** `JA4_NEW_TO_ENTITY` alone is severity
  2 / confidence 0.3. Severity rises only with a corroborating factor
  (rare-in-fleet, or a caller-supplied corroboration flag), and is capped well
  below high: this detector must never reach high severity on fingerprint
  evidence alone.
- **AC similarity de-escalates.** When a fingerprint is new to the entity but
  its `a_c` key is one the entity already speaks, that is evidence of a benign
  variant of a known stack (a browser point-release), so `JA4_AC_SIMILARITY`
  LOWERS severity and confidence. AC comparison is supporting evidence only and
  is never a malicious verdict.
- **Transition bursts are a separate detector.** `ja4_transition_burst` fires on
  many distinct valid fingerprints from one entity inside a window —
  randomized-fingerprint impersonation, which per-fingerprint novelty cannot
  see by construction. Its window is anchored to the latest observation in the
  series, not to the wall clock, so replay is deterministic.

What is deliberately NOT claimed: a JA4 does not identify a program, a device,
a person, a malware family or an adversary. Nothing is blocked or suppressed by
fingerprint, and `ja4_novelty` is not promoted on its own.

Server-side rarity (`server_fp_rarity`, ja4s/ja3s) is unchanged: it is a
property of the destination, not of a source entity's baseline, so the
fleet-global set is the right shape there.

Related: decision 012 puts both JA4 detectors in one risk family, so novelty and
a transition burst on the same handshake series cannot sum as independent
evidence.
