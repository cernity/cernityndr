# Cernity product evaluation

Even with the audit defects fixed, Cernity needs several product capabilities to fulfill its promise of fewer, more useful security findings. The largest gaps are environmental context, investigation support, operator feedback, and visibility into detection coverage.

The central architecture supports the project’s goals. The current [roadmap](roadmap.md) emphasizes additional detectors and ML, but the capabilities below should take priority. These are recommendations based on the implementation review, not claims of measured customer demand.

Related: [Independent implementation audit](cernity-independent-audit.md).

## 1. Understand what is normal for each environment

Cernity has an asset-service foundation and fleet prevalence scoring. It does not yet provide enough context to reliably distinguish an attack from legitimate administration.

A backup server transferring large volumes and a workstation doing the same thing need different treatment. A vulnerability scanner touching every host should be evaluated differently from an employee laptop.

The product needs:

- Asset roles, business criticality, owners, and network zones.
- Historical baselines across multiple observation windows.
- Comparisons with similar assets, rather than only the entire fleet.
- Explicit handling of newly discovered assets and insufficient history.
- Reliable identity across DHCP changes, overlapping site addresses, and duplicate sensor observations.

**Why this matters:** statistical abnormality becomes more useful when Cernity can explain why that behavior is unusual for that asset.

## 2. Make every finding an investigation starting point

Sending a finding to a SIEM is only part of the workflow. An analyst must be able to establish what happened and assess the scope.

Cernity should deliver a consistent evidence package containing the observation, relevant baseline, contributing signals, affected entities, detector/configuration version, and evidence references. It should also provide an authenticated way to retrieve the surrounding telemetry from central storage.

This preserves the principle that raw telemetry does not need to be continuously ingested into the SIEM. Analysts can retrieve relevant evidence when investigating.

Comparable products explicitly connect alerts to investigation: Security Onion supports pivots from alerts into hunting, packet capture, and cases; Corelight documents SIEM alert exports with investigation pivots. These establish a useful workflow benchmark, not proof that Cernity needs their interfaces. [Security Onion alerts](https://docs.securityonion.net/en/3/main/alerts/), [Corelight alert export](https://eu.investigator.corelight.com/docs/alerts/alert-export.html).

## 3. Add a controlled analyst feedback loop

Thresholds and allowlists already exist. What is missing is a complete workflow for recording whether a finding was malicious, expected activity, a false positive, or unresolved—and using that feedback safely.

A useful implementation would support scoped exceptions with an owner, reason, expiration, and audit history. Before activating a detection change, operators should be able to replay retained telemetry and inspect which findings would disappear or appear.

**Why this matters:** Cernity’s promise of reduced noise requires an ongoing tuning process. Static defaults cannot establish that outcome across different networks.

## 4. Tell operators what Cernity can actually see and detect

The coverage detector currently checks some capture-loss and application-parsing conditions. A product needs a broader capability inventory.

For every sensor and detector, expose states such as:

| State | Meaning |
|---|---|
| Active | Required telemetry is arriving and compatible |
| Learning | Available history is insufficient |
| Degraded | Missing fields, packet loss, or processing backlog affects results |
| Unsupported | This sensor cannot supply the required evidence |
| Disabled | An operator deliberately turned it off |

A detector that depends on unavailable Kerberos fields should visibly say so. A silent sensor must not look equivalent to a healthy sensor observing no threats.

This capability is particularly important because Cernity intentionally relies on existing, potentially heterogeneous Suricata deployments.

## 5. Provide an operational control interface

Delegating investigations and case management to the SIEM is consistent with the project’s scope. Operators still need a way to manage Cernity itself.

A CLI/API, with a small administration interface if useful, should cover sensor enrollment, credential rotation, configuration distribution, detection status, delivery failures, storage usage, and upgrades.

The distinction matters: a findings engine still needs product administration, even when it does not own the analyst console.

For smaller deployments, offer a tested installation profile with sensible defaults and optional components clearly separated. Keeping modular detection code does not require every installation to manage every available service.

## 6. Define the response contract

The inspected implementation has external response hooks and simulated containment. To support the “response” portion of NDR, Cernity should either provide or explicitly delegate a complete action lifecycle:

- Requested action and target.
- Authorization policy.
- Execution acknowledgment.
- Success, failure, and reversal status.
- Audit linkage to the originating finding.

Implementing one response integration thoroughly would provide stronger evidence of operational usefulness than listing several generic webhook destinations.

## 7. Measure the outcome the product promises

The most important product metric is not the number of detectors or ATT&CK tags. It is whether Cernity helps operators find consequential threats with less investigation work.

The evaluation should measure:

- Threats detected and missed, including misses introduced by suppression.
- Delivered false positives across representative benign environments.
- Duplicate findings and findings per incident.
- Evidence completeness and investigation effort.
- Delivery reliability and detection latency.
- Central resource cost and sensor overhead.

Compare against a tuned Suricata-to-SIEM workflow, not just an unfiltered stream. RITA is also a relevant behavioral comparison because it already provides beacon detection and can run separately from its capture system. [RITA documentation](https://www.activecountermeasures.com/free-tools/rita/).

## Red-team assessment

Each addition introduces tradeoffs. Baselines can learn compromised behavior; exceptions can hide attacks; evidence retention increases storage and privacy requirements; a control interface creates another security boundary. These features need explicit uncertainty, restricted permissions, auditable changes, and bounded retention.

The roadmap’s emphasis on ML as the largest next capability should also be challenged. The audit did not establish that missing ML is the limiting factor. Incorrect telemetry handling, incomplete context, unreliable delivery, and missing investigation workflows would undermine an ML detector too.

## Recommended sequence

1. Repair the audited reliability and security defects.
2. Add coverage visibility and evidence retrieval.
3. Implement contextual baselines and feedback.
4. Expand detection methods based on measured misses.

That sequence most directly supports Cernity’s stated goal: delivering fewer findings that an operator can understand, investigate, and act on.
