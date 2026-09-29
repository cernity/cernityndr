import mappings

# Representative finding: entities as a JSON string (wire form), community_id + obs_id in
# source_events, an evidence ref, an ML model version.
FINDING = {
    "finding_id": "beacon-1", "revision": 2, "detector_id": "slips_ml",
    "detector_version": "2.0", "model_version": "slips-2026.09",
    "tenant_id": "default", "sensor_ids": ["sensor-a", "sensor-b"],
    "entities": ('[{"type":"entity","role":"subject","value":"default|asset:h7"},'
                 '{"type":"asset","role":"subject","value":"asset:h7"},'
                 '{"type":"ip","role":"src","value":"10.0.0.5"}]'),
    "evidence_refs": ["minio://ndr-pcap/x.pcap", "minio://ndr-pcap/y"],
    "source_events": [{"event_type": "quic", "community_id": "1:abc=", "obs_id": "obs:" + "a" * 64}],
    "incident_id": "incident-default|asset:h7-1700",
}

CANONICAL = set(mappings.pivot(FINDING))


def test_pivot_draws_every_field_from_finding():
    p = mappings.pivot(FINDING)
    assert p["finding_id"] == "beacon-1"
    assert p["signature_id"] == "slips_ml"           # detector identity, not the finding id
    assert p["revision"] == 2
    assert p["incident_id"] == "incident-default|asset:h7-1700"
    assert p["entity_id"] == "default|asset:h7"      # "entity"-typed subject entity
    assert p["asset_key"] == "asset:h7"              # "asset"-typed entity
    assert p["community_id"] == "1:abc="             # from source_events[0]
    assert p["observation_point"] == "sensor-a"      # first sensor
    assert p["observation_id"] == "obs:" + "a" * 64  # source_events[0].obs_id
    assert p["pcap_evidence_id"] == "minio://ndr-pcap/x.pcap"  # first evidence ref
    assert p["model_version"] == "slips-2026.09"
    assert p["detector_version"] == "2.0"


def test_scenario1_every_pivot_field_present_or_null():
    # Scenario 1: every canonical field surfaces in BOTH maps (present, or explicitly null) for a
    # sparse finding — nothing is silently dropped.
    sparse = {"finding_id": "x"}
    cim, ecs = mappings.to_cim(sparse), mappings.to_ecs(sparse)
    for canon in CANONICAL:
        assert mappings.CIM_MAP[canon] in cim
        assert mappings.ECS_MAP[canon] in ecs
    # finding_id is the one always-present pivot (CIM vendor_finding_id / ECS event.id); the rest,
    # including signature_id (no detector on a bare finding), are explicit null.
    assert cim["vendor_finding_id"] == "x" and ecs["event.id"] == "x"
    for canon in CANONICAL - {"finding_id"}:
        assert cim[mappings.CIM_MAP[canon]] is None
        assert ecs[mappings.ECS_MAP[canon]] is None


def test_scenario2_spot_check_valid_cim_and_ecs_names():
    # Scenario 2: the maps land on real Splunk CIM / ECS field names for the fields with a standard
    # home (the rest use the sanctioned vendor_/cernity. extension namespaces).
    # signature_id is the SIGNATURE/detector identity (Intrusion_Detection); the per-finding
    # occurrence id has no CIM occurrence home, so it rides vendor_finding_id — the two are distinct.
    assert mappings.CIM_MAP["signature_id"] == "signature_id"      # Intrusion_Detection
    assert mappings.CIM_MAP["finding_id"] == "vendor_finding_id"   # occurrence id, NOT signature_id
    assert mappings.CIM_MAP["entity_id"] == "risk_object"          # Risk-Based Alerting
    assert mappings.CIM_MAP["asset_key"] == "asset_id"             # Asset_And_Identity
    assert mappings.CIM_MAP["observation_point"] == "dvc"          # device
    assert mappings.CIM_MAP["community_id"] == "community_id"      # Zeek/Stream TA
    assert mappings.CIM_MAP["model_version"].startswith("vendor_")  # extension namespace

    assert mappings.ECS_MAP["finding_id"] == "event.id"            # unique id of this event
    assert mappings.ECS_MAP["signature_id"] == "rule.id"           # the rule/detector identity
    assert mappings.ECS_MAP["revision"] == "event.sequence"
    assert mappings.ECS_MAP["asset_key"] == "host.id"
    assert mappings.ECS_MAP["community_id"] == "network.community_id"
    assert mappings.ECS_MAP["observation_point"] == "observer.name"
    assert mappings.ECS_MAP["detector_version"] == "rule.version"
    assert mappings.ECS_MAP["investigation_id"].startswith("cernity.")  # custom namespace


def test_scenario3_file_artifact_and_investigation_roundtrip():
    # Scenario 3: a finding carrying the Track A / U9 fields round-trips through both maps.
    f = dict(FINDING, file_artifact_id="fa-42", investigation_id="case-9")
    cim, ecs = mappings.to_cim(f), mappings.to_ecs(f)
    assert cim[mappings.CIM_MAP["file_artifact_id"]] == "fa-42"
    assert cim[mappings.CIM_MAP["investigation_id"]] == "case-9"
    assert ecs["cernity.file_artifact_id"] == "fa-42"
    assert ecs["cernity.investigation_id"] == "case-9"


def test_scenario4_mapping_independent_of_transport():
    # Scenario 4: helpers are pure — no env, no socket, no SIEM. A plain dict in, a plain dict out.
    cim = mappings.to_cim(FINDING)
    assert cim["signature_id"] == "slips_ml"          # detector identity in the CIM signature field
    assert cim["vendor_finding_id"] == "beacon-1"     # occurrence id preserved in the vendor field
    assert mappings.to_ecs(FINDING)["network.community_id"] == "1:abc="
    assert mappings.to_ecs(FINDING)["event.id"] == "beacon-1"


def test_signature_id_is_detector_identity_not_finding_id():
    # Reviewer B-3: two findings from the SAME detector share signature_id but keep distinct
    # finding_ids — signature identity is the detector/rule, not the occurrence.
    a = {"finding_id": "f-1", "detector_id": "zeek_ssh_bruteforce"}
    b = {"finding_id": "f-2", "detector_id": "zeek_ssh_bruteforce"}
    ca, cb = mappings.to_cim(a), mappings.to_cim(b)
    assert ca["signature_id"] == cb["signature_id"] == "zeek_ssh_bruteforce"
    assert ca["vendor_finding_id"] == "f-1" and cb["vendor_finding_id"] == "f-2"
    # ECS: same rule.id, different event.id.
    ea, eb = mappings.to_ecs(a), mappings.to_ecs(b)
    assert ea["rule.id"] == eb["rule.id"] == "zeek_ssh_bruteforce"
    assert ea["event.id"] == "f-1" and eb["event.id"] == "f-2"
    # An explicit signature_id on the finding wins over detector_id.
    assert mappings.pivot({"finding_id": "f-3", "detector_id": "d", "signature_id": "SIG-9"})["signature_id"] == "SIG-9"


def test_pcap_evidence_only_from_capture_refs():
    # Reviewer B-2: pcap_evidence_id is a captured-packet object, never a finding_id/obs_id that
    # also lives in evidence_refs.
    # A correlation incident's refs are constituent finding_ids -> no capture -> null.
    assert mappings.pivot({"finding_id": "i", "evidence_refs": ["finding-1", "beacon-2"]})["pcap_evidence_id"] is None
    # An anomaly finding's obs-id refs -> no capture -> null.
    assert mappings.pivot({"finding_id": "a", "evidence_refs": ["obs:" + "a" * 64]})["pcap_evidence_id"] is None
    # Mixed list: skip the finding_id, pick the actual capture object (the reviewer's probe).
    mixed = mappings.pivot({"finding_id": "m", "evidence_refs": ["finding-1", "minio://ndr-pcap/x.pcap"]})
    assert mixed["pcap_evidence_id"] == "minio://ndr-pcap/x.pcap"
    # A bare (unscheme'd) capture-agent ref is recognized too.
    bare = mappings.pivot({"finding_id": "b", "evidence_refs": ["ndr-pcap/t-default/b-full.pcap"]})
    assert bare["pcap_evidence_id"] == "ndr-pcap/t-default/b-full.pcap"
    # Explicit pcap_evidence_id always wins.
    exp = mappings.pivot({"finding_id": "e", "pcap_evidence_id": "cap-7", "evidence_refs": ["finding-1"]})
    assert exp["pcap_evidence_id"] == "cap-7"


def test_observation_id_from_anomaly_evidence_refs():
    # Reviewer round-2 B-1: anomaly-detector (services/anomaly-detector/features.py) puts the bare
    # canonical obs_id into evidence_refs and emits no source_events. The observation pivot must
    # recognize it there, through BOTH maps.
    obs = "obs:" + "a" * 64
    anomaly = {"finding_id": "anom-1", "detector_id": "anomaly", "evidence_refs": [obs],
               "sensor_ids": ["sensor-a"]}
    assert mappings.pivot(anomaly)["observation_id"] == obs
    assert mappings.to_cim(anomaly)["vendor_observation_id"] == obs
    assert mappings.to_ecs(anomaly)["cernity.observation_id"] == obs
    # Precedence: explicit observation_id > source_events[].obs_id > evidence_refs obs ref.
    exp = mappings.pivot({"finding_id": "x", "observation_id": "obs:" + "0" * 64, "evidence_refs": [obs]})
    assert exp["observation_id"] == "obs:" + "0" * 64
    se = mappings.pivot({"finding_id": "x", "source_events": [{"obs_id": "obs:" + "b" * 64}],
                         "evidence_refs": [obs]})
    assert se["observation_id"] == "obs:" + "b" * 64
    # Multiple obs refs: first in list order (documented selection rule); a pcap/finding_id ref is skipped.
    multi = mappings.pivot({"finding_id": "x",
                            "evidence_refs": ["finding-1", "obs:" + "c" * 64, "obs:" + "d" * 64]})
    assert multi["observation_id"] == "obs:" + "c" * 64
    # A non-canonical ref (finding_id, pcap object) is not mistaken for an observation.
    assert mappings.pivot({"finding_id": "x", "evidence_refs": ["finding-1", "minio://ndr-pcap/y.pcap"]})["observation_id"] is None


def test_explicit_observation_point_preserved():
    # Reviewer round-2 B-2: an explicit canonical observation_point must survive, ahead of the sensor
    # fallbacks, through both maps.
    f = {"finding_id": "f", "observation_point": "sensor-x", "sensor_ids": ["sensor-a"]}
    assert mappings.pivot(f)["observation_point"] == "sensor-x"
    assert mappings.to_cim(f)["dvc"] == "sensor-x"
    assert mappings.to_ecs(f)["observer.name"] == "sensor-x"
    # Fallbacks still apply when no explicit observation_point: sensor_id, then sensor_ids[0].
    assert mappings.pivot({"finding_id": "f", "sensor_id": "sensor-s"})["observation_point"] == "sensor-s"
    assert mappings.pivot({"finding_id": "f", "sensor_ids": ["sensor-a"]})["observation_point"] == "sensor-a"


def test_pivot_accepts_raw_entity_array_and_asset_fallback():
    # entities as a raw array (not a JSON string), no incident/model — asset_key still resolves,
    # ML-less fields go null.
    f = {"finding_id": "y", "detector_version": "1.0",
         "entities": [{"type": "asset", "value": "asset:z"}]}
    p = mappings.pivot(f)
    assert p["asset_key"] == "asset:z" and p["entity_id"] is None
    assert p["model_version"] is None and p["community_id"] is None


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"ok  {fn.__name__}")
    print(f"all {len(fns)} mappings tests passed")
