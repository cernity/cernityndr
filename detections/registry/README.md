# detections/registry/ — published detection-registry entries

The committed, published set of detection-registry entries (plan 025 U1 schema,
`contracts/detection-registry.schema.json`). One file per detection; each is a
governance record whose `manifest_ref` points at the SHIPPED Detection Capability
Manifest (`detections/manifest/*.manifest.json`) that backs it.

This is the registry *input* to the published detection-quality scoreboard
(`services/detection-registry/scoreboard.py`): the generator loads these entries
through the U1 `RegistryStore` (so every committed entry is schema-validated and its
`manifest_ref` is proven to resolve), resolves each `manifest_ref` to join the
detection's identity + lifecycle with the manifest's maturity status + ATT&CK, and
attaches the MEASURED per-detector quality from feedback-service.

`detection_id` (registry identity) deliberately differs from the manifest's
`detector_id` (e.g. `dns-tunnel-entropy` → `dns-detector`): the join resolves through
`manifest_ref`, never by assuming the two ids are equal.
