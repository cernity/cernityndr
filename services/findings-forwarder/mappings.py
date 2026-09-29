"""Stable pivot fields (v2 §18.4) + CIM/ECS field-mapping helpers.

Every exported finding carries the same STABLE pivot field set so an analyst pivots on the same
event across SIEMs regardless of transport. `pivot(finding)` extracts the canonical set (contracts/
siem_pivot.schema.json); `to_cim` / `to_ecs` rename it to Splunk CIM and Elastic/OpenSearch ECS.

Pure helpers, mirroring cef.py: no transport, no live SIEM, unit-testable. Every pivot key is always
present in the output — a value absent on the finding is emitted as an explicit null (never dropped),
so a pivot is either a working link or a documented gap.

§26 IP: CIM/ECS names are authored independently from open Splunk CIM and Elastic Common Schema
references — no Corelight assets or wording. Where a field has a recognized home in the standard it
maps there; where it does not, CIM uses the sanctioned `vendor_*` extension namespace and ECS uses a
custom `cernity.*` namespace (both standards' documented mechanisms for vendor-specific fields)."""
import json
import re

# canonical pivot field -> Splunk CIM field name.
# Real CIM homes: signature_id (Intrusion_Detection — the SIGNATURE/detector identity, shared by
# every finding that detector emits; NOT a per-finding occurrence id), risk_object (Risk-Based
# Alerting), asset_id (Asset_And_Identity), dvc (device), community_id (Zeek/Stream TA de-facto).
# The finding OCCURRENCE id has no CIM occurrence field, so it rides the vendor_ extension prefix
# (vendor_finding_id); the rest of the vendor-specific pivots do too.
CIM_MAP = {
    "finding_id": "vendor_finding_id",
    "signature_id": "signature_id",
    "revision": "vendor_finding_revision",
    "incident_id": "vendor_incident_id",
    "entity_id": "risk_object",
    "asset_key": "asset_id",
    "community_id": "community_id",
    "observation_point": "dvc",
    "observation_id": "vendor_observation_id",
    "pcap_evidence_id": "vendor_pcap_evidence_id",
    "file_artifact_id": "vendor_file_artifact_id",
    "investigation_id": "vendor_investigation_id",
    "model_version": "vendor_model_version",
    "detector_version": "vendor_detector_version",
}

# canonical pivot field -> Elastic Common Schema (ECS) field name.
# Real ECS homes: event.id (the unique id of THIS event = the finding occurrence), rule.id (the
# rule/detector identity that produced it), event.sequence, host.id, network.community_id,
# observer.name, rule.version. The rest use a custom cernity.* namespace (ECS's documented
# convention for fields with no core home).
ECS_MAP = {
    "finding_id": "event.id",
    "signature_id": "rule.id",
    "revision": "event.sequence",
    "incident_id": "cernity.incident_id",
    "entity_id": "cernity.entity_id",
    "asset_key": "host.id",
    "community_id": "network.community_id",
    "observation_point": "observer.name",
    "observation_id": "cernity.observation_id",
    "pcap_evidence_id": "cernity.pcap_evidence_id",
    "file_artifact_id": "cernity.file_artifact_id",
    "investigation_id": "cernity.investigation_id",
    "model_version": "cernity.model_version",
    "detector_version": "rule.version",
}

# The capture (pcap) object bucket — services/capture-agent writes evidence_refs as
# `[minio://]ndr-pcap/<tenant-seg>/<finding>-<profile>.pcap` (PCAP_BUCKET, default below). evidence_refs
# is a HETEROGENEOUS list: correlation-service puts constituent finding_ids there, anomaly-detector puts
# obs_ids. Only a ref into the capture bucket (or a bare *.pcap object) is captured-packet evidence.
# ponytail: matches the default bucket name; a deployment that renames PCAP_BUCKET keeps the same
# helper as long as the ref still ends .pcap — widen to the configured bucket only if one drops that.
_PCAP_BUCKET = "ndr-pcap"

# Canonical observation id: services/normalizer/models.py and asset-service/resolution.py both mint it
# as `"obs:" + sha256(...).hexdigest()` (obs: + 64 lowercase hex). anomaly-detector puts the bare
# obs_id straight into evidence_refs (services/anomaly-detector/features.py), so an observation pivot
# has to recognize that shape there — not only in source_events[].obs_id.
_OBS_REF = re.compile(r"^obs:[0-9a-f]{64}$")


def _is_obs_ref(ref):
    """True for a canonical observation reference (`obs:<64-hex>`) — the id the normalizer/asset-service
    mint and the anomaly-detector drops into evidence_refs. Excludes the pcap objects and finding_ids
    that also share evidence_refs."""
    return isinstance(ref, str) and bool(_OBS_REF.match(ref))


def _is_capture_ref(ref):
    """True only for a captured-packet evidence reference — a MinIO object in the pcap bucket
    (`[scheme://]ndr-pcap/...`) or a bare `*.pcap` object. Rejects the finding_ids (correlation) and
    obs_ids (anomaly-detector) that also live in evidence_refs, so a pivot never labels one of those
    as packet capture."""
    if not isinstance(ref, str) or not ref:
        return False
    body = ref.split("://", 1)[-1]                # drop any scheme (minio://, s3://, ...)
    return body.startswith(_PCAP_BUCKET + "/") or ref.endswith(".pcap")


def _entities(finding):
    """The finding's entities as a list of dicts (detectors emit a JSON-serialized string on the
    wire; the raw array is also accepted — same contract cef.py honors)."""
    ents = finding.get("entities")
    if isinstance(ents, str):
        try:
            ents = json.loads(ents)
        except (ValueError, TypeError):
            ents = []
    return [e for e in (ents or []) if isinstance(e, dict)]


def _first(seq, pred, key="value"):
    for e in seq:
        if pred(e):
            v = e.get(key)
            if v not in (None, ""):
                return v
    return None


def _source_events(finding):
    se = finding.get("source_events") or []
    return [e for e in se if isinstance(e, dict)]


def pivot(finding):
    """Extract the canonical §18.4 pivot field set from a finding. Every key is present; a field with
    no value on the finding is null. Values are drawn from the finding's top-level fields, falling
    back to the entities list / source_events / evidence_refs (the same provenance cef.py pivots on).
    Callable with no SIEM and no transport."""
    ents = _entities(finding)
    se = _source_events(finding)
    sensors = finding.get("sensor_ids") or []
    refs = finding.get("evidence_refs") or []
    return {
        "finding_id": finding.get("finding_id"),
        # signature identity: the detector/rule that fired (shared by every finding it emits) — an
        # explicit signature_id wins, else the detector_id. Distinct from the per-finding finding_id.
        "signature_id": finding.get("signature_id") or finding.get("detector_id"),
        "revision": finding.get("revision"),
        "incident_id": finding.get("incident_id"),
        # entity spine: an explicit field wins; else the correlation "entity" subject entity.
        "entity_id": finding.get("entity_id")
        or _first(ents, lambda e: e.get("type") == "entity"),
        # asset key: explicit field, else an "asset"-typed entity value.
        "asset_key": finding.get("asset_key")
        or _first(ents, lambda e: e.get("type") == "asset"),
        # community_id: explicit field, else the first source event's flow hash (cef.py parity).
        "community_id": finding.get("community_id")
        or (se[0].get("community_id") if se else None),
        # observation point: an explicit canonical observation_point wins, else the finding's sensor_id,
        # else the first of its sensor_ids (anomaly findings emit the list, not a scalar).
        "observation_point": finding.get("observation_point")
        or finding.get("sensor_id")
        or (sensors[0] if sensors else None),
        # observation id, in precedence order: an explicit observation_id, else the first source event's
        # obs_id, else the first canonical obs ref in evidence_refs (anomaly-detector puts obs_ids there
        # and emits no source_events). Selection rule for multiple obs refs: first in list order.
        "observation_id": finding.get("observation_id")
        or (se[0].get("obs_id") if se else None)
        or next((r for r in refs if _is_obs_ref(r)), None),
        # pcap/evidence: an explicit field wins, else the first evidence ref that is a verified capture
        # object (never a finding_id/obs_id that shares evidence_refs). Null when no capture is present.
        "pcap_evidence_id": finding.get("pcap_evidence_id")
        or next((r for r in refs if _is_capture_ref(r)), None),
        "file_artifact_id": finding.get("file_artifact_id"),      # Track A; null until then
        "investigation_id": finding.get("investigation_id"),      # U9; null until then
        "model_version": finding.get("model_version"),
        "detector_version": finding.get("detector_version"),
    }


def to_cim(finding):
    """Canonical pivot set renamed to Splunk CIM field names. Every CIM key present (null where the
    finding has no value)."""
    p = pivot(finding)
    return {CIM_MAP[k]: v for k, v in p.items()}


def to_ecs(finding):
    """Canonical pivot set renamed to Elastic Common Schema (ECS) field names. Every ECS key present
    (null where the finding has no value). Keys are flat dotted paths — Elasticsearch expands
    `network.community_id` into the nested object on ingest.
    ponytail: flat dotted keys, not pre-nested dicts; nest here only if a consumer needs the object
    form before ingest."""
    p = pivot(finding)
    return {ECS_MAP[k]: v for k, v in p.items()}
