"""Shared tenant-safe MinIO object-key discipline (Increment 3, U2).

Lifted out of services/capture-agent/agent.py so the PCAP plane and the carved-file
artifact plane share ONE key discipline: the same collision-free tenant segment, the
same "trust a bus-advertised key only inside its own tenant namespace" rule, and the
same charset/traversal validation. Before U2 the carved-file object key was
`ndr-files/<sha256>` with NO tenant segment — a U1a-class cross-tenant collision
where one tenant's carved file could overwrite (or be read as) another's. Both planes
now key on `<bucket>/<tenant-segment>/<...>`.

Pure, dependency-free; safe to import from any service and from the shared/ test gate.
"""
from __future__ import annotations

import hashlib
import re

# A MinIO object key we're willing to trust verbatim off the bus: safe charset,
# bounded length, no path traversal, no absolute path.
_SAFE_KEY = re.compile(r"^[A-Za-z0-9._\-/]{1,256}$")

# Absent/empty tenant -> this explicit, documented segment (never str(None) = 'None').
DEFAULT_TENANT_SEGMENT = "_no-tenant"

# The carved-file plane keeps the untrusted producer's upload (STAGING) and the
# gatekeeper-accepted artifact (ACCEPTED) in SEPARATE namespaces under a tenant. The
# capture-agent uploads to `<bucket>/<tseg>/incoming/<sha>`; file-artifact validates
# those bytes and, only on success, promotes them to `<bucket>/<tseg>/artifacts/<sha>`.
# Retrieval serves ONLY the accepted namespace, so an archive the gate rejected (or a
# raw upload nobody validated) can never be handed to a caller. Both namespaces still
# key tenant as the 2nd path segment, so key_tenant_segment/retrieval isolation hold.
STAGING_PREFIX = "incoming"
ARTIFACT_PREFIX = "artifacts"


def valid_key(ref) -> bool:
    """A key is trustworthy only if it is a bounded, safe-charset string with no `..`
    traversal and no absolute path. A forged/untrusted ref off the bus must never
    become an arbitrary object key."""
    return (isinstance(ref, str) and bool(_SAFE_KEY.match(ref))
            and ".." not in ref and not ref.startswith("/"))


def tenant_segment(tenant) -> str:
    """Collision-free, path-safe tenant namespace for an object key. The FULL SHA-256
    digest of the raw tenant id is the collision-free part, so distinct tenant ids
    never map to the same segment and one tenant's object can never overwrite another's.
    The sanitized 32-char prefix is only a readable label and may collide; the full
    digest (not a truncation) is what guarantees distinctness. Absent/empty ->
    DEFAULT_TENANT_SEGMENT."""
    if tenant is None or not str(tenant).strip():
        return DEFAULT_TENANT_SEGMENT
    raw = str(tenant)
    safe = re.sub(r"[^A-Za-z0-9._\-]", "", raw).replace("..", "").strip(".")[:32] or "t"
    return f"{safe}-{hashlib.sha256(raw.encode()).hexdigest()}"


def in_tenant_namespace(ref, tseg: str, bucket: str) -> bool:
    """Is a (syntactically safe) key inside THIS tenant's namespace,
    i.e. `<bucket>/<tseg>/...`? A legacy unnamespaced ref or another tenant's ref
    carries a different second segment and fails this check — so an advertised
    reference off the bus can never redirect I/O into a different tenant's space.
    `tseg` is collision-free (sha-suffixed), so a match genuinely belongs to it."""
    return isinstance(ref, str) and ref.startswith(f"{bucket}/{tseg}/")


def segment_key(tseg: str, name: str, bucket: str) -> str:
    """Compose `<bucket>/<tseg>/<name>` from an already-derived tenant segment."""
    return f"{bucket}/{tseg}/{name}"


def file_key(tenant, name: str, bucket: str) -> str:
    """Tenant-scoped key for `tenant`: `<bucket>/<tenant-segment>/<name>`."""
    return segment_key(tenant_segment(tenant), name, bucket)


def staging_key(tenant, name: str, bucket: str) -> str:
    """Untrusted-upload (staging) key: `<bucket>/<tenant-segment>/incoming/<name>`.
    The capture-agent writes carved bytes here; they are NOT servable until the
    file-artifact gate validates and promotes them to the accepted namespace."""
    return f"{bucket}/{tenant_segment(tenant)}/{STAGING_PREFIX}/{name}"


def accepted_key(tseg: str, name: str, bucket: str) -> str:
    """Gatekeeper-accepted artifact key: `<bucket>/<tseg>/artifacts/<name>`, composed
    from an already-derived (server-side) tenant segment. Only keys under this namespace
    are ever served by retrieval."""
    return f"{bucket}/{tseg}/{ARTIFACT_PREFIX}/{name}"


def in_accepted_namespace(ref, tseg: str, bucket: str) -> bool:
    """Is `ref` an accepted-artifact key inside THIS tenant's namespace, i.e.
    `<bucket>/<tseg>/artifacts/...`? A staging (`.../incoming/...`) or another tenant's
    key fails, so retrieval never serves un-promoted or cross-tenant bytes."""
    return isinstance(ref, str) and ref.startswith(f"{bucket}/{tseg}/{ARTIFACT_PREFIX}/")


def key_tenant_segment(ref, bucket: str) -> "str | None":
    """The tenant segment embedded in a `<bucket>/<tseg>/<rest>` key, or None if `ref`
    is not a safe, tenant-scoped key under `bucket`. This is how a consumer SERVER-
    DERIVES the tenant from a trusted producer's key instead of a wire-supplied field."""
    if not valid_key(ref):
        return None
    parts = ref.split("/")
    if len(parts) >= 3 and parts[0] == bucket and parts[1]:
        return parts[1]
    return None


# A carved-file sha256 leaf: the capture-agent names every carved object by its digest.
_SHA256 = re.compile(r"[0-9a-f]{64}")


def staging_sha(ref, bucket: str) -> "str | None":
    """The sha256 leaf of a valid tenant-scoped STAGING key
    `<bucket>/<tenant-segment>/incoming/<sha256>`, or None. A carved-file consumer
    (file-yara) uses this to accept EXACTLY the staging references the capture-agent now
    produces — one tenant segment then `incoming/` then the digest — and reject anything
    else (legacy unnamespaced `<bucket>/<sha>`, an accepted-artifact key, a forged path).
    The single source of truth for the staging key shape both producer and consumer share."""
    if not valid_key(ref):
        return None
    parts = ref.split("/")
    if (len(parts) == 4 and parts[0] == bucket and parts[1]
            and parts[2] == STAGING_PREFIX and _SHA256.fullmatch(parts[3])):
        return parts[3]
    return None
