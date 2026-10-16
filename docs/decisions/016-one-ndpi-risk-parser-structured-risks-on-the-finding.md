# 016: one nDPI risk parser, and structured risks ride on the finding

Status: implemented, pending independent review.

Suricata's nDPI plugin emits `flow_risk` as a mapping whose VALUES are risk
OBJECTS, not names:

```json
"flow_risk": {"188": {"risk": "Susp DNS Traffic",
                      "risk_score": {"client": 350, "server": 110, "total": 460},
                      "severity": "Medium"}}
```

`app._ndpi_risks` folded that dict's keys and values into strings with `str()`,
on the stated assumption that a value is a name (`{id: name}` / `{name: true}`).
On the real shape `str()` yields a Python repr, and a delivered finding in this
repo's published evidence carries the whole object as one `ndpi_risk` entity
value: `"{'risk': 'Susp DNS Traffic', 'risk_score': {...}, 'severity': 'Medium'}"`.
Nothing downstream could filter on severity, threshold on `score.total`, or group
by risk name. The legacy substring matcher appeared to work only because the repr
happens to contain the name — `"susp"` matched a formatting artefact.

Two decisions follow.

**One parser, shared by both nDPI modes.** `ndpi_policy.parse_ndpi_risks` (plan
008 U1) already handles every shape a real deployment emits — the structured
mapping, `{id: name}`, `{name: true}`, lists of names or of objects, a bare
string, absent — keeping a malformed entry with a reason instead of discarding
its siblings, and stopping the traversal at `MAX_RISKS` so a hostile 10k-entry
risk set is never built and then trimmed. `detectors.ndpi_risks` projects an
entry down to the four fields the legacy path needs (`id`, `name`, `severity`,
`score`) rather than re-deriving the shape handling. So `legacy` and `structured`
can never disagree about a risk's fields, and a new producer quirk is fixed once.

Shared parsing, NOT shared field selection. Which field is read, and how a name
is bounded, stay per-mode, because changing either changes what a legacy sensor
detects: the legacy path keeps its historical `risk or flow_risk` precedence
(`risk` wins whenever truthy) and matches the sensor's full, untruncated string,
while the structured classifier prefers canonical `flow_risk` and bounds a stored
name at `MAX_NAME`. An earlier revision of this decision routed legacy through
the classifier's precedence and accepted the change; review showed it silently
dropped real detections (`{"risk": [...], "flow_risk": null}` stopped matching),
so it is reverted — `ndpi_policy.parse_risk_value` takes the container and the
name bound from its caller.

**The structure rides on the entity, not in a string.** `finding.schema.json`
types `entities` as `array|string` with unconstrained `object` items, so a nested
object needs no contract change (`ndpi_evidence` already relies on this). The
`ndpi_risk` entity keeps `value` as the sorted matched risk NAMES — what the
legacy consumers read — and carries the parsed objects alongside in `risks`.
Re-stringifying for the SIEM boundary was rejected: that is the defect.

Matching moved onto the real fields (`detectors._risk_text`: name plus the native
severity tier). `HIGH_NDPI_RISKS` and the names it matches are unchanged — no
current entry is a substring of any nDPI tier, so what counts as high risk is
identical, now for the right reason. Severity also stays nDPI's own tier: a risk
is evidence to assess, never proof of compromise.

Not in scope, and still flat: `normalizer._risks` reads `ndpi.risk` only and
keeps the dict's KEYS, so `ndpi_risk_set` in ClickHouse is ids (or empty for a
`flow_risk`-only sensor) — lossy, but it never shipped a repr, and the column is
`Array(String)`.

Related: plan 008 (`ndpi_policy.py`, the structured classifier), decision 013
(confidence is discounted, not inflated, by observation quality).
