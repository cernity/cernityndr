# 013: sensor observation quality discounts confidence, never severity

Status: implemented, pending independent review.

Coverage-detector co-produces `sensor-quality.v1` on `ndr.sensor.quality.v1`
with its existing severity-6 coverage findings. Quality samples bypass episode
dedup so recovery reaches finding-service. Missing capture/app-layer measurements
remain null. A measured blind verdict takes precedence over capture degradation;
otherwise both signals must be measured healthy to assert good. The existing
coverage-finding heuristic and episode dedup are unchanged, including its legacy
interpretation of absent app-layer counters. Quality is more conservative about
missing measurements and does not discount those alone.

Finding-service applies the latest available quality at candidate construction.
It derives sensor identity from explicit sensor_ids or preserved source records
(sensor_id, then host). Without an attributable sensor, quality is unknown. For
multiple sensors the strongest measured discount applies once; representative
provenance cannot establish the fraction of evidence from each sensor. With no
lookup argument, build_finding retains its exact legacy output, including sensor
attribution defaults. The live service always supplies the lookup.

Defaults (environment overrides):

- `NDR_QUALITY_DEGRADED_FACTOR=0.7`
- `NDR_QUALITY_BLIND_FACTOR=0.4`
- `NDR_QUALITY_CONFIDENCE_FLOOR=0.05`
- `NDR_QUALITY_TTL_SECS=300`
- `NDR_QUALITY_MAX_SENSORS=10000`

Factors and floor must be in (0, 1]. Good/unknown leave confidence exactly
unchanged. Discounted confidence stops at the floor, except already sub-floor
inputs (including existing zero) remain unchanged: never increase confidence to
meet a floor. The explanatory block records the effective multiplier after floor
clamping, original confidence, chosen sensor, verdict and reasons. These policy
weights are not calibrated probabilities. Severity and enrichment/delivery routes
remain those of the original candidate, avoiding delivery delays from degradation.

Cache entries expire to unknown on either observation age or local receipt age.
Duplicates and older samples cannot refresh TTL or overwrite recovery. Oldest
received entries are evicted at the size limit. Unknown is not healthy and carries
no discount; unmeasured deployments are not penalized. The bounded cache is local,
not durable or a historical interval join. Cross-topic arrival ordering, clock
skew, restart, eviction, and consumer-group partition assignment can leave a
candidate without a usable sample. This slice does not guarantee quality coverage
across multiple finding-service replicas; fleet-wide fan-out/history is deferred.
Cumulative Suricata counters also cannot identify exactly when loss occurred.
No verdict asserts that the observed network was safe.

Persist observation_quality as a JSON String column alongside source_events so
capture finalization after restart retains the explanation and original value.
Existing ClickHouse installations must apply the idempotent ALTER in
`deploy/clickhouse/init/02-detection.sql` before upgrading finding-service.

Related: decision 012 (family-capped entity risk — that caps the evidence; this
discounts the confidence in it). The quality verdict is co-produced with the
`coverage_degraded` health finding by the same service, which is what keeps the
spec invariant true: confidence is only ever discounted for a sensor that is
simultaneously raising a health alert.
