# U5: one managed file-hash matcher

Status: implemented, pending independent review.

Threat-intel owns file-hash matching and registers file-threat's MalwareBazaar
feed as an abuse.ch connector (score 90, trust 0.9, TLP green, one-day validity).
The existing intel lifecycle merges provenance by tenant, type and indicator.
Hash finding identity excludes feed provenance so adding a second contributor
within the existing host/hour dedup window does not emit a second hash finding.
Other indicator dimensions retain their existing identity and audit behavior.

File-threat retains independent risky executable delivery detection. It no longer
fetches hash feeds or emits file_malware_hash. Historical findings remain supported
by finding-service. Managed hash findings use threat_intel, category malware, and
the existing intel_match preservation through finding finalization. The finding
schema's match type adds hash; intel.v1 and hunt.v1 are unchanged.

Deployment must configure threat-intel's existing INTEL_DB with a writable,
persistent SQLite path and migrate MALWAREBAZAAR_FEED and NDR_MALWARE_HASHES from
file-threat to threat-intel. INTEL_FEEDS continues to configure other managed feeds.
Unset INTEL_DB retains the legacy non-hash static mode; it does not bypass the
managed hash policy. EICAR and operator hashes are registered as operator intel
at startup with the existing connector validity, never unconditional matches.

Live input is suricata.file.v1: file-observer currently writes ClickHouse only,
so subscribing to a canonical file bus would silently miss live observations.
Raw hashes require the original file-threat hash_is_complete plus digest syntax
validation. Canonical file observations use hashes_only/bytes_available state,
which attests producer-side completeness; metadata_only never matches even if a
malformed payload contains a hash. Source-record hashes never match file intel.

Hunts reuse the existing ndr.evidence_observations view, whose U1a migration
06-file-observation.sql already unions ndr.file_observation. A second query or
source-specific checkpoint would duplicate this data. Existing store.py persists
hash hits and dual timestamps unchanged, with tenant-qualified idempotent keys.
No checkpoint migration or new table is needed. Tests cover this existing source
binding, hash dimensions, persisted restarts, and tenant boundaries.

Verification is local with backend doubles; no live feed download, ClickHouse,
broker, image build, or deployed SIEM delivery is established by these tests.
