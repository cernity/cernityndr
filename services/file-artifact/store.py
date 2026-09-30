"""file-artifact store (Increment 3, U2): pure storage + policy logic for the carved-
file artifact plane. app.py is the Kafka/MinIO shell.

Bytes come from the EXISTING capture-agent -> MinIO carved-file stream
(ndr.file.extracted.v1). U2 re-keys the source object under a tenant-scoped key
`ndr-files/<tenant-segment>/<sha256>` (the legacy `ndr-files/<sha256>` had NO tenant
segment — a U1a-class cross-tenant collision). The artifact id is the SHA-256 of the
bytes, so identical bytes are idempotent WITHIN a tenant but land in DISTINCT keys
ACROSS tenants.

Design (mirrors capture-agent.preserve/retrieve_pcap):
  - tenant is SERVER-DERIVED from the trusted producer's tenant-scoped source key,
    never from a wire-supplied tenant field (guardrail §26 multi-tenant isolation).
  - the capture-agent uploads to a STAGING key (`.../incoming/<sha>`); this gate
    validates the bytes (size + archive depth/member size + zip-slip) BEFORE promoting
    them to the ACCEPTED key (`.../artifacts/<sha>`). A rejected upload is never promoted,
    and retrieval serves ONLY the accepted namespace — so a malicious archive the gate
    rejects can never be handed to a caller even though its staged bytes still exist.
  - retention is enforced two ways: verify_retention() fails closed at startup unless the
    bucket carries the configured expiry lifecycle, and retrieve() refuses artifacts older
    than the retention window (expired bytes are never served, even pre-sweep).
  - retrieval is authenticated + audited and enforces caller-tenant == key-tenant.
  - a PERMANENT PolicyError (bad archive/size/source key) is distinguished from a
    transient infra error so the consumer can skip the former but replay the latter.
No boto3/kafka import here so the logic is unit-testable with a mock store.
"""
from __future__ import annotations

import hashlib
import io
import os
import zipfile
import zlib
from datetime import datetime, timezone

import object_keys

FILES_BUCKET = os.environ.get("FILES_BUCKET", "ndr-files")
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE", "67108864"))       # 64 MiB
MAX_ARCHIVE_DEPTH = int(os.environ.get("MAX_ARCHIVE_DEPTH", "4"))
# Days the accepted artifact is retained; retrieval refuses anything older and the
# bucket lifecycle (verified at startup) sweeps it. Kept in lock-step with the compose
# `mc ilm rule ... --expire-days` so a caller can never read past the promised window.
RETENTION_DAYS = int(os.environ.get("ARTIFACT_RETENTION_DAYS", "7"))
# Logical extraction root every archive entry must resolve under (zip-slip guard).
EXTRACT_ROOT = "artifacts"


class PolicyError(ValueError):
    """A PERMANENT policy rejection: oversize artifact, archive too deep, oversize
    archive member, zip-slip entry, malformed archive, or a source key that is not
    tenant-scoped. The event can never succeed on replay, so the consumer may safely
    skip past it. Transient infra errors (fetch/S3/network) are NOT PolicyError — they
    must leave the offset uncommitted so a restart retries them. Subclasses ValueError
    so existing `pytest.raises(ValueError, ...)` assertions keep matching."""


def artifact_id(data: bytes) -> str:
    """The artifact id is the SHA-256 of the bytes (content-addressed)."""
    return hashlib.sha256(data).hexdigest()


def creates_object(ev: dict) -> bool:
    """Only a bytes-bearing extraction creates an object. A metadata_only/hashes_only
    file observation has no bytes to store (U2 scope: NO object). Default is
    bytes_available because the carved-file stream ships bytes."""
    if not isinstance(ev, dict) or not ev.get("object_ref"):
        return False
    return ev.get("state", "bytes_available") == "bytes_available"


def is_zip(data: bytes) -> bool:
    """Is this a ZIP archive we must validate? True when the classic PK magic sits at
    offset 0, OR when a readable End-Of-Central-Directory record is present anywhere in the
    bytes. The first-four-bytes check alone missed a ZIP with PREPENDED bytes (an SFX/`MZ`
    stub, or a nested archive embedded after other data): its local-file magic is no longer
    at offset 0, yet zipfile locates the central directory from the END and reads it fine —
    so such a prefixed archive skipped traversal + nesting validation entirely and could be
    promoted. Scan for the EOCD (what zipfile.is_zipfile does) so prefixed and nested
    prefixed archives are recognized too. A leading-magic-but-malformed blob still trips the
    magic branch and is rejected as a malformed archive downstream."""
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return True
    return zipfile.is_zipfile(io.BytesIO(data))   # EOCD scan: catches prefixed/SFX zips


def _escapes_root(name: str, root: str = EXTRACT_ROOT) -> bool:
    """Zip-slip guard: does this archive entry resolve OUTSIDE the extraction root?
    Absolute paths, drive-letter/backslash and `..` traversal all escape."""
    if not name or name.startswith("/") or name.startswith("\\") or "\\" in name:
        return True
    dest = os.path.normpath(os.path.join(root, name))
    return dest != root and not dest.startswith(root + os.sep)


def validate_archive(data: bytes, *, max_depth: int = MAX_ARCHIVE_DEPTH,
                     max_file_size: int = MAX_FILE_SIZE, _depth: int = 1) -> None:
    """Recursively validate a zip archive BEFORE any expansion/storage: reject when it
    nests deeper than `max_depth`, when a member's UNCOMPRESSED size exceeds
    `max_file_size` (checked from the header, before reading — decompression-bomb
    guard), or when ANY entry path escapes the extraction root (zip-slip). Raises
    ValueError on the first violation; returns None if the archive is safe. Non-zip
    bytes are trivially safe."""
    if not is_zip(data):
        return
    if _depth > max_depth:
        raise PolicyError("archive exceeds max_archive_depth")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        # A malformed archive is a PERMANENT input violation, not an infra fault: it will
        # be malformed on every replay, so the consumer must be able to skip past it
        # rather than crash-loop on it (raise PolicyError, not a bare ValueError).
        raise PolicyError(f"malformed archive: {exc}") from exc
    with zf:
        for info in zf.infolist():
            # Check EVERY entry path — directories too. A directory entry like `../escape/`
            # escapes the root exactly as a file entry does; skipping the check for dirs
            # (before validating their path) let `../escape/` through. Validate first, then
            # skip a safe directory's size/nesting checks (a dir has no bytes to bound).
            if _escapes_root(info.filename):
                raise PolicyError(f"zip-slip: entry escapes root: {info.filename!r}")
            if info.is_dir():
                continue
            if info.file_size > max_file_size:
                raise PolicyError("archive member exceeds max_file_size")
            try:
                member = zf.read(info)                 # size bounded by the check above
            except (zipfile.BadZipFile, OSError, EOFError, RuntimeError, zlib.error) as exc:
                # A member that will not decompress is a permanent violation too — a
                # corrupt/truncated deflate stream (BadZipFile/EOFError), an unsupported
                # compression method (NotImplementedError), or any other read-time failure
                # (RuntimeError, e.g. an encryption flag we did not catch above). Reject it,
                # don't replay it forever.
                raise PolicyError(f"unreadable archive member: {exc}") from exc
            if is_zip(member):                         # nested archive: recurse
                validate_archive(member, max_depth=max_depth,
                                 max_file_size=max_file_size, _depth=_depth + 1)


def _object_exists(s3, bucket: str, key: str) -> bool:
    """Idempotency probe: is the object already stored under this key?"""
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except Exception:                                  # noqa: BLE001 — absent or unreadable -> re-store
        return False


def store(ev: dict, fetch, s3, audit, *, max_file_size: int = MAX_FILE_SIZE,
          max_archive_depth: int = MAX_ARCHIVE_DEPTH) -> "dict | None":
    """Ingest one ndr.file.extracted.v1 event: download the carved bytes via `fetch`,
    enforce size + archive-depth + zip-slip, store under the source's tenant-scoped
    key, and return the artifact record linking bytes_available (or None if the event
    has no bytes to store). `fetch(source_ref) -> bytes` and `s3` (put/head/get_object)
    are injected so this is testable without boto3. Every path is audited."""
    src = ev.get("object_ref")
    base = {"action": "file.artifact.store", "source_ref": str(src)[:256],
            "sensor_id": ev.get("sensor_id") if isinstance(ev, dict) else None,
            "sha256": ev.get("sha256") if isinstance(ev, dict) else None}
    if not creates_object(ev):
        audit({**base, "outcome": "skipped", "reason": "no bytes (metadata_only/hashes_only)"})
        return None
    # Tenant is SERVER-DERIVED from the trusted producer's tenant-scoped source key.
    tseg = object_keys.key_tenant_segment(src, FILES_BUCKET)
    if tseg is None:
        # A non-tenant-scoped source key (legacy `ndr-files/<sha>`) is a PERMANENT input
        # violation — it will never gain a tenant segment on replay, so raise PolicyError
        # and let the consumer commit past it instead of crash-looping.
        audit({**base, "outcome": "rejected", "reason": "source key not tenant-scoped"})
        raise PolicyError("source object_ref is not tenant-scoped")
    audit({**base, "outcome": "attempt", "tenant_segment": tseg})
    try:
        data = fetch(src)                              # a fetch/S3 failure here is TRANSIENT
        if len(data) > max_file_size:
            raise PolicyError("artifact exceeds max_file_size")
        # Validate archives BEFORE storing anything (fail closed on depth/size/zip-slip).
        validate_archive(data, max_depth=max_archive_depth, max_file_size=max_file_size)
        aid = artifact_id(data)
        # Content-address integrity: the id IS the hash of the stored bytes. If the producer
        # announced a sha256, it MUST equal the computed one — a mismatch means the announcement
        # (and any linkage keyed on it) can't be trusted, so reject permanently rather than store
        # bytes under a hash that doesn't describe them.
        announced = (ev.get("sha256") or "").strip().lower()
        if announced and announced != aid:
            raise PolicyError("announced sha256 does not match stored bytes")
        # Promote validated bytes into the ACCEPTED namespace (`.../artifacts/<sha>`),
        # NOT the raw staging namespace the untrusted producer uploaded to. Retrieval
        # serves only the accepted namespace, so a rejected/never-validated staging object
        # (e.g. a zip-slip archive) can never be handed to a caller.
        key = object_keys.accepted_key(tseg, aid, FILES_BUCKET)
        bucket, _, okey = key.partition("/")
        record = {"artifact_id": aid, "object_ref": key, "size": len(data),
                  "mime": (ev.get("mime") or None), "tenant_segment": tseg,
                  "sha256": aid, "sensor_id": ev.get("sensor_id")}
        if _object_exists(s3, bucket, okey):
            audit({**base, "outcome": "idempotent", "artifact_id": aid, "resource_id": key})
            return record
        s3.put_object(Bucket=bucket, Key=okey, Body=data, ServerSideEncryption="AES256",
                      Metadata={"tenant-segment": tseg, "sha256": aid})
        audit({**base, "outcome": "stored", "artifact_id": aid, "resource_id": key,
               "bytes": len(data)})
        return record
    except Exception:
        audit({**base, "outcome": "failed", "tenant_segment": tseg})
        raise


def _rule_covers_artifacts(rule) -> bool:
    """Does this lifecycle rule actually apply to the STORED artifact objects? Accepted
    artifacts key as `<tenant-segment>/artifacts/<sha>` within the bucket, and the tenant
    segment is dynamic — so only a rule that applies to EVERY object (no prefix, or an
    empty prefix, and no tag filter) is guaranteed to cover every tenant's artifacts. A
    rule scoped to an unrelated prefix (e.g. `unrelated/`) or to a tag (our objects carry
    no such tag) does NOT cover them, so it cannot stand in for the retention promise.
    Prefix may live at the legacy top-level `Prefix`, at `Filter.Prefix`, or inside
    `Filter.And`; tags at `Filter.Tag` or `Filter.And.Tags`."""
    flt = rule.get("Filter")
    prefix = rule.get("Prefix", "")                    # legacy (pre-Filter) top-level prefix
    tags = []
    if isinstance(flt, dict):
        if isinstance(flt.get("And"), dict):
            prefix = flt["And"].get("Prefix", prefix)
            tags = flt["And"].get("Tags") or []
        else:
            prefix = flt.get("Prefix", prefix)
            if flt.get("Tag"):
                tags = [flt["Tag"]]
    if tags:                                           # tag-scoped: artifact objects are untagged
        return False
    return not prefix                                  # only an empty/absent prefix covers all tenants


def verify_retention(s3, *, bucket: str = FILES_BUCKET, retention_days: int = RETENTION_DAYS) -> int:
    """Fail closed at startup unless `bucket` carries an ENABLED expiry lifecycle whose
    window is <= the configured retention AND whose filter actually COVERS the stored
    artifact objects, so a served artifact can never outlive the promised window. Mirrors
    capture-agent.preserve's store-side lifecycle verification: a producer flag or an
    in-app boolean cannot stand in for real bucket configuration, and neither can a
    lifecycle rule scoped to some other prefix/tag. Raises PolicyError when the lifecycle
    is missing or incompatible; returns the window."""
    try:
        rules = s3.get_bucket_lifecycle_configuration(Bucket=bucket).get("Rules", [])
    except Exception as exc:                            # noqa: BLE001 — no lifecycle at all
        raise PolicyError(f"artifact bucket lifecycle not configured: {exc}") from exc
    ok = [r for r in rules if r.get("Status") == "Enabled"
          and type(r.get("Expiration", {}).get("Days")) is int
          and 0 < r["Expiration"]["Days"] <= retention_days
          and _rule_covers_artifacts(r)]
    if not ok:
        raise PolicyError(
            f"artifact bucket lifecycle missing an enabled expiry rule <= {retention_days}d "
            "that covers the stored artifact objects")
    return retention_days


def _expired(last_modified, now, retention_days: int) -> bool:
    """Is a stored object past the retention window? Fail closed on a missing/garbled
    LastModified (treat as expired) — never serve bytes whose age we cannot bound."""
    if not isinstance(last_modified, datetime):
        return True
    lm = last_modified if last_modified.tzinfo else last_modified.replace(tzinfo=timezone.utc)
    return (now - lm).total_seconds() > retention_days * 86400


def retrieve(ref, auth_header, tokens, s3, audit, *, max_size: int = MAX_FILE_SIZE,
             now: "datetime | None" = None, retention_days: int = RETENTION_DAYS) -> bytes:
    """Authenticated, tenant-scoped, audited download. `tokens` is SERVER configuration:
    token -> {actor, tenant_id, file_read: true, reason?}. Access is denied unless the
    grant is a file reader for the tenant that OWNS the key AND the key is in that tenant's
    ACCEPTED-artifact namespace (a raw staging / un-promoted object is never servable). An
    object older than the retention window is refused even before the lifecycle sweep runs.
    The audit line records who/what/why/result on every path; audit intent must succeed
    before the object store is touched."""
    now = datetime.now(timezone.utc) if now is None else now
    grant = tokens.get(auth_header[7:]) if isinstance(auth_header, str) and auth_header.startswith("Bearer ") else None
    if not isinstance(grant, dict):
        grant = None
    event = {"action": "file.artifact.download", "resource_id": str(ref)[:256],
             "actor": grant.get("actor") if grant else "anonymous",       # who
             "tenant_id": grant.get("tenant_id") if grant else None,
             "why": grant.get("reason") if grant else None}               # why
    if (not grant or grant.get("file_read") is not True or not grant.get("tenant_id")
            or not grant.get("actor") or not object_keys.valid_key(ref)
            or not object_keys.in_accepted_namespace(
                ref, object_keys.tenant_segment(grant["tenant_id"]), FILES_BUCKET)):
        audit({**event, "outcome": "denied"})
        raise PermissionError("file artifact access denied")
    audit({**event, "outcome": "attempt"})
    try:
        bucket, _, key = ref.partition("/")
        obj = s3.get_object(Bucket=bucket, Key=key)
        try:
            if _expired(obj.get("LastModified"), now, retention_days):
                raise ValueError("artifact past retention window")
            if obj["ContentLength"] > max_size:
                raise ValueError("object exceeds download budget")
            data = obj["Body"].read(max_size + 1)
            if len(data) > max_size or len(data) != obj["ContentLength"]:
                raise ValueError("invalid object length")
            # The key's final segment IS the artifact id (sha256 of bytes): verify the
            # stored bytes still match, so tampering/corruption is caught, not served.
            if hashlib.sha256(data).hexdigest() != key.rsplit("/", 1)[-1]:
                raise ValueError("object digest mismatch")
        finally:
            obj["Body"].close()
        audit({**event, "outcome": "success", "bytes": len(data)})        # what + result
        return data
    except Exception:
        audit({**event, "outcome": "failed"})
        raise
