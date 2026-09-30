"""Sensor-side capture agent — pure logic (plan U10-follow-up).

Runs ON the sensor (ol9-suri). Subscribes to arm directives over Kafka (NOT SSH,
NOT an exposed socket — no central key-holding), arms Suricata's conditional-PCAP
via the LOCAL command socket, ships the bounded PCAP to MinIO, disarms, and emits
the enrichment request + a completion status so the orchestrator frees the budget.

This module is the pure, testable half: directive validation, dataset selection,
pcap-key derivation, window-pcap selection, and local budget checks. app.py wires
it to Kafka, the local socket, the pcap dir, and MinIO.
"""
from __future__ import annotations
import hashlib
import os
import re

# Tenant-safe key discipline is shared with the file-artifact plane (U2). These
# names were lifted verbatim into shared/object_keys.py; re-exported here so existing
# callers (retrieve_pcap, tests) keep resolving agent.tenant_segment / agent._valid_key.
import object_keys
from object_keys import DEFAULT_TENANT_SEGMENT, tenant_segment

# Same mapping the orchestrator uses (v2 §18.2). Kept local so the agent has no
# import dependency on the orchestrator package.
PROFILE_DATASET = {
    "ip": ("ndr-capture-ip", "ip"),
    "ja4": ("ndr-capture-ja4", "string"),
    "sni": ("ndr-capture-sni", "string"),
    "dns": ("ndr-capture-dns", "string"),
}

# Local defense-in-depth budget (behind the orchestrator's gates). A sensor never
# lets central logic push it past its own capture ceiling (v2 §21.3).
LOCAL_MAX_CONCURRENT = int(os.environ.get("AGENT_MAX_CONCURRENT", "2"))
DEFAULT_TTL_SECS = int(os.environ.get("AGENT_DEFAULT_TTL_SECS", "120"))
DEFAULT_MAX_BYTES = int(os.environ.get("AGENT_DEFAULT_MAX_BYTES", "104857600"))  # 100 MiB


def for_this_sensor(directive: dict, my_sensor: str) -> bool:
    """An agent only actuates directives addressed to its own sensor_id."""
    return directive.get("sensor_id") == my_sensor


def validate(directive: dict) -> tuple[bool, str]:
    """Reject malformed/unsupported directives before touching the socket."""
    profile = directive.get("capture_profile", "ip")
    value = (directive.get("value") or "").strip()
    if profile not in PROFILE_DATASET:
        return False, f"unknown profile {profile}"
    if not value:
        return False, "empty value"
    # Guard the socket from injection: dataset values are single tokens, never
    # shell/socket control. IPs and fingerprints have no whitespace.
    if any(c.isspace() for c in value):
        return False, "value has whitespace"
    return True, "ok"


def dataset_for(profile: str) -> tuple[str, str]:
    return PROFILE_DATASET[profile]


def _valid_key(ref) -> bool:
    """See object_keys.valid_key — the shared bus-key trust rule (kept as a local
    alias so retrieve_pcap and the tests read the same)."""
    return object_keys.valid_key(ref)


def _sanitize(s, default: str = "cap") -> str:
    """Reduce a directive-supplied component to a safe filename atom (no separators
    and no dot-run traversal, so it can never introduce traversal in the fallback)."""
    s = re.sub(r"[^A-Za-z0-9._\-]", "", str(s)).replace("..", "").strip(".")[:128]
    return s or default


# tenant_segment + DEFAULT_TENANT_SEGMENT are imported from object_keys above and kept
# in lock-step with capture-orchestrator's tenant_segment. The bucket-parameterized
# namespace check is aliased to the PCAP bucket so pcap_key/retrieve_pcap read as before.
def _in_tenant_namespace(ref: str, tseg: str) -> bool:
    """Is a (syntactically safe) advertised key inside THIS directive's tenant PCAP
    namespace, i.e. `ndr-pcap/<tseg>/...`? See object_keys.in_tenant_namespace."""
    return object_keys.in_tenant_namespace(ref, tseg, "ndr-pcap")


def pcap_key(directive: dict) -> str:
    """MinIO object key (bucket/key) the agent uploads to and hands to Zeek.
    Matches what the orchestrator advertised so the loop stays consistent. An
    advertised pcap_ref is honored only if it is a safe key AND belongs to the
    directive's own tenant namespace; otherwise the computed fallback is
    tenant-namespaced (no cross-tenant overwrite) with every component sanitized.
    The tenant check is what closes the overwrite path: without it a forged/legacy
    ref would be uploaded verbatim, letting one tenant land in another's namespace."""
    tseg = tenant_segment(directive.get("tenant_id"))
    ref = directive.get("pcap_ref")
    if _valid_key(ref) and _in_tenant_namespace(ref, tseg):
        return ref
    fid = _sanitize(directive.get("finding_id") or directive.get("value"))
    profile = _sanitize(directive.get("capture_profile", "ip"))
    return f"ndr-pcap/{tseg}/{fid}-{profile}.pcap"


def window_pcaps(entries: list[tuple[str, float]], start_ts: float) -> list[str]:
    """Given (path, mtime) pairs, return pcap files touched during the capture
    window (mtime >= start), newest last. The conditional pcap-log is shared
    across concurrent arms; with a single arm this is exactly the target's
    traffic. ponytail: shared file under concurrent arms — BPF-narrow on upload
    if precise per-arm isolation is ever needed."""
    return [p for p, m in sorted(entries, key=lambda e: e[1]) if m >= start_ts - 1.0]


# --- look-back retrieval from the rolling ring (plan 2026-08-25-002, U2) --------
# The ring (a separate always-on pcap-log) holds recent external packets. On a
# look-back arm the agent slices [trigger - lookback, trigger] out of it and
# carves the finding's connection, so the forward-only conditional capture is no
# longer blind to the packets that preceded the trigger.
LOOKBACK_FORWARD_BUFFER = float(os.environ.get("AGENT_LOOKBACK_FORWARD_BUFFER", "60"))


def wants_lookback(directive: dict) -> bool:
    """A directive opts into look-back with a positive `lookback_secs` or `mode`."""
    try:
        if int(directive.get("lookback_secs") or 0) > 0:
            return True
    except (TypeError, ValueError):
        pass
    return directive.get("mode") == "lookback"


def lookback_pcaps(entries: list[tuple[str, float]], trigger_ts: float,
                   lookback_secs: float) -> list[str]:
    """Ring files (path, mtime) overlapping the pre-trigger window
    [trigger - lookback, trigger + forward-buffer], oldest first. The small
    forward buffer includes the file that was still being written when the finding
    fired (its mtime sits at or just after the trigger). If the ring holds less
    than `lookback`, this simply returns the files that exist, never errors."""
    lo = trigger_ts - lookback_secs
    hi = trigger_ts + LOOKBACK_FORWARD_BUFFER
    return [p for p, m in sorted(entries, key=lambda e: e[1]) if lo <= m <= hi]


def capture_bpf(directive: dict) -> "str | None":
    """BPF that isolates the finding's own connection (F11). The forward conditional
    pcap-log and the rolling ring are both SHARED across concurrent arms, so carving
    by this filter before upload keeps one finding's slice from leaking another
    finding's packets. Buildable only for the IP profile (a packet-level host filter);
    app-layer profiles (sni/ja4/dns) have no packet BPF from an IP-keyed capture, so
    return None (ship as captured — best effort)."""
    if directive.get("capture_profile", "ip") == "ip":
        value = (directive.get("value") or "").strip()
        # validate() already guarantees no whitespace; guard the shell/BPF anyway
        if value and not any(c.isspace() for c in value):
            return f"host {value}"
    return None


# Look-back uses the same per-finding isolation filter as the forward path.
lookback_bpf = capture_bpf


def lookback_key(directive: dict) -> str:
    """MinIO key for the look-back pcap: the forward key with a -lookback marker,
    so the backward slice does not overwrite the forward capture."""
    base = pcap_key(directive)
    root, _, ext = base.rpartition(".")
    return f"{root}-lookback.{ext}" if root else f"{base}-lookback"


def budget_ok(active_jobs: int) -> tuple[bool, str]:
    if active_jobs >= LOCAL_MAX_CONCURRENT:
        return False, "agent_max_concurrent"
    return True, "ok"


# Measured uploader health (F11): a stalled uploader = jobs in flight but no forward
# progress (an arm started or a slice shipped) within AGENT_STALE_SECS. Idle (no active
# jobs) is healthy. Replaces the constant-healthy stub so a wedged MinIO/socket flips
# the readiness probe instead of silently pretending to be up.
AGENT_STALE_SECS = float(os.environ.get("AGENT_STALE_SECS", "300"))


def uploader_healthy(active_jobs: int, secs_since_progress: float,
                     stale_secs: float = AGENT_STALE_SECS) -> bool:
    if active_jobs <= 0:
        return True
    return secs_since_progress < stale_secs


def ttl_secs(directive: dict) -> int:
    try:
        return int(directive.get("ttl_secs") or DEFAULT_TTL_SECS)
    except (TypeError, ValueError):
        return DEFAULT_TTL_SECS


def max_bytes(directive: dict) -> int:
    try:
        return int(directive.get("max_bytes") or DEFAULT_MAX_BYTES)
    except (TypeError, ValueError):
        return DEFAULT_MAX_BYTES


# --- file extraction shipping (plan U5, Track A1) -------------------------------
# Suricata file-store (v2) writes carved files named by their SHA256. The agent
# ships new ones to MinIO and announces them so file-yara can scan the content,
# catching novel malware a hash blocklist cannot. Reuses the same MinIO/Kafka
# plumbing as the pcap path (no new transport).
FILES_BUCKET = os.environ.get("FILES_BUCKET", "ndr-files")
FILESTORE_DIR = os.environ.get("FILESTORE_DIR", "/var/log/suricata/filestore")
MIN_FILE_BYTES = int(os.environ.get("AGENT_MIN_FILE_BYTES", "1"))
MAX_FILE_BYTES = int(os.environ.get("AGENT_MAX_FILE_BYTES", "67108864"))  # 64 MiB


def sha_from_name(name: str) -> "str | None":
    """Suricata file-store names the carved object exactly by its SHA256, with no
    suffix. Recover the sha from the filename, and skip sidecars that share the
    hash (<sha>.json / <sha>.meta) so we never ship the metadata instead of the
    payload."""
    base = os.path.basename(name)
    if "." in base:                 # a suffix means a sidecar, not the carved file
        return None
    base = base.lower()
    if len(base) == 64 and all(c in "0123456789abcdef" for c in base):
        return base
    return None


def should_ship_file(size: int, sha256, seen) -> bool:
    """Skip already-shipped (by sha), empty, and oversize files."""
    if not sha256 or sha256 in seen:
        return False
    return MIN_FILE_BYTES <= size <= MAX_FILE_BYTES


def file_object_key(tenant, sha256: str) -> str:
    """Tenant-scoped STAGING MinIO key for a carved file (U2). The agent is an untrusted
    producer: it uploads to `ndr-files/<tenant-segment>/incoming/<sha256>`, NOT the
    servable artifact key. The file-artifact gate validates those bytes and promotes them
    to `ndr-files/<tenant-segment>/artifacts/<sha256>`; retrieval serves only the accepted
    namespace, so an unvalidated (e.g. zip-slip) upload can never be handed to a caller.

    Re-key: the legacy key was `ndr-files/<sha256>` with NO tenant segment — a U1a-class
    cross-tenant collision (two tenants carving identical bytes shared one object; a
    forged sha could read/overwrite another tenant's file). Now tenant is the 2nd path
    segment on both the staging and accepted keys.

    Migration: existing legacy `ndr-files/<sha256>` objects are NOT tenant-scoped and
    the file-artifact service refuses them (key_tenant_segment -> None). Re-key them
    under the tenant that produced them, or let the bucket lifecycle expire them; do not
    read them cross-tenant in the interim."""
    return object_keys.staging_key(tenant, sha256, FILES_BUCKET)


def file_extracted_event(sensor_id: str, sha256: str, size: int, tenant=None,
                         mime: str = "") -> dict:
    """Shape an ndr.file.extracted.v1 announcement (consumed by file-yara and, from
    U2, file-artifact). object_ref is now tenant-scoped (see file_object_key); state
    is bytes_available because the carved bytes were shipped to MinIO."""
    return {"sensor_id": sensor_id, "sha256": sha256, "size": size, "mime": mime,
            "tenant_id": tenant, "state": "bytes_available",
            "object_ref": file_object_key(tenant, sha256)}


# U6: an in-memory rolling PCAP ring fed by tcpdump, not a new packet engine.
# Memory avoids an unbounded spool on disk. Host swap/core dumps must be disabled
# or encrypted. All capture and expiry clocks below are injectable for unit tests.
import struct
import threading
import time
from collections import deque
import capture_v2


class PacketRing:
    def __init__(self, policy, audit, clock=time.monotonic, wall=time.time):
        self.policy, self.audit, self.clock, self.wall = policy, audit, clock, wall
        self.records = deque()
        self.size = 0
        self.dropped = 0
        self.header = None
        self.closed = False
        self.lock = threading.RLock()
        capture_v2.validate_policy(policy, wall())
        if (policy.get('enabled') is not True or policy.get('sensitive') is not False
                or not policy.get('tenant_id') or not policy.get('sensor_id')
                or not policy.get('policy_id') or policy.get('expires_at', 0) <= wall()
                or policy.get('ring_bytes', 0) < 65536 or policy.get('ring_seconds', 0) <= 0):
            raise PermissionError('buffering requires an unexpired local opt-in policy')
        audit({'action': 'pcap.buffer.start', 'tenant_id': policy['tenant_id'],
               'sensor_id': policy['sensor_id'], 'policy_id': policy['policy_id']})

    def expire(self):
        with self.lock:
            cutoff = self.clock() - self.policy['ring_seconds']
            expired_policy = self.closed or self.wall() >= self.policy['expires_at']
            while self.records and (expired_policy or self.records[0][0] <= cutoff):
                self.size -= len(self.records.popleft()[2]) + 192
                self.dropped += 1
            return not expired_policy

    def close(self):
        with self.lock:
            self.closed = True
            self.expire()

    def append(self, ts, record):
        with self.lock:
            if not self.expire():
                return False
            # Account record bytes AND a conservative per-record Python overhead.
            charge = len(record) + 192
            if charge + 24 > self.policy['ring_bytes']:
                self.dropped += 1
                return False
            while self.records and self.size + charge + 24 > self.policy['ring_bytes']:
                self.size -= len(self.records.popleft()[2]) + 192
                self.dropped += 1
            self.records.append((self.clock(), ts, record))
            self.size += charge
            return True

    def slice(self, start, end, limit):
        with self.lock:
            self.expire()
            out = bytearray(self.header or b'')
            selected, truncated = 0, False
            for _, ts, record in self.records:
                if start <= ts < end:
                    if len(out) + len(record) > limit:
                        truncated = True
                        break
                    out.extend(record)
                    selected += 1
            return bytes(out), {'selected_packets': selected, 'truncated': truncated,
                                'ring_drops_total': self.dropped,
                                'capture_loss': 'unknown', 'complete': False}

    def ingest(self, stream):
        """Read bounded classic-PCAP records from tcpdump stdout. Reject pcapng,
        inconsistent lengths and oversized records; never allocate from unchecked input.
        """
        def read_exact(n):
            buf = bytearray()
            while len(buf) < n:
                chunk = stream.read(n - len(buf))
                if not chunk:
                    if not buf:
                        return b''
                    raise ValueError('truncated PCAP')
                buf.extend(chunk)
            return bytes(buf)
        header = read_exact(24)
        if len(header) != 24 or header[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
            raise ValueError('unsupported PCAP header')
        endian = '<' if header[0] == 0xd4 else '>'
        _, major, minor, _, _, snaplen, _ = struct.unpack(endian + 'IHHIIII', header)
        if (major, minor) != (2, 4) or not 1 <= snaplen <= 65535:
            raise ValueError('unsupported PCAP format')
        with self.lock:
            if self.header and self.header != header:
                raise ValueError('capture format changed')
            self.header = header
        while self.expire():
            rec = read_exact(16)
            if not rec:
                return
            sec, usec, size, original = struct.unpack(endian + 'IIII', rec)
            if size > snaplen or original < size or usec >= 1000000:
                raise ValueError('invalid PCAP record')
            data = read_exact(size)
            if len(data) != size:
                raise ValueError('truncated PCAP packet')
            self.append(sec + usec / 1e6, rec + data)


def carve_pcap(data, address):
    """tcpdump interprets packets/BPF; failure NEVER falls back to unfiltered bytes."""
    import ipaddress
    import subprocess
    host = str(ipaddress.ip_address(address))
    import tempfile
    # Some platform libpcap builds cannot seek/probe stdin. A 0600 bounded
    # anonymous file works on Linux and macOS. It has no pathname to survive a
    # process crash; tcpdump inherits only this descriptor, never a public spool.
    with tempfile.TemporaryFile() as source:
        source.write(data)
        source.seek(0)
        result = subprocess.run(['tcpdump', '-r', f'/dev/fd/{source.fileno()}', '-w', '-', 'host', host],
                                pass_fds=(source.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=15, check=True)
        return result.stdout


def preserve(directive, ring, s3, audit, budget, now=None, carve=carve_pcap):
    """A mockable store boundary. Store retention is mandatory, not an Expires hint.
    Bucket MUST have S3 lifecycle expiration for tag cernity-pcap=v2 (see ADR).
    Downloads additionally enforce the signed object's expires-at metadata.
    """
    now = ring.wall() if now is None else now
    event = {k: directive.get(k) for k in ('request_id', 'tenant_id', 'sensor_id', 'finding_id')}
    audit({**event, 'action': 'pcap.preserve.request'})
    reserved = False
    try:
        capture_v2.authorize(directive, ring.policy, now)
        # Verify the actual store policy; a producer or local boolean assertion
        # cannot stand in for retention configuration.
        if s3.get_bucket_versioning(Bucket='ndr-pcap').get('Status') in ('Enabled', 'Suspended'):
            raise PermissionError('preserve requires a nonversioned bucket')
        rules = s3.get_bucket_lifecycle_configuration(Bucket='ndr-pcap').get('Rules', [])
        matching = [rule for rule in rules if rule.get('Status') == 'Enabled'
                    and rule.get('Filter') == {'Tag': {'Key': 'cernity-pcap', 'Value': 'v2'}}
                    and type(rule.get('Expiration', {}).get('Days')) is int
                    and 0 < rule['Expiration']['Days'] * 86400 <= directive['limits']['retention_s']]
        if not matching:
            raise PermissionError('object lifecycle not configured')
        # Defense in depth even with a memory ring: refuse under host disk pressure.
        import shutil
        import tempfile
        if shutil.disk_usage(tempfile.gettempdir()).free < ring.policy['min_free_bytes'] + directive['limits']['max_bytes']:
            raise ValueError('disk free space below policy')
        budget.reserve(directive, ring.policy)
        reserved = True
        data, coverage = ring.slice(directive['window']['start'], directive['window']['end'],
                                    directive['limits']['max_bytes'])
        if coverage['selected_packets'] == 0:
            raise ValueError('no packets in requested window')
        data = carve(data, directive['value'])
        if not 24 < len(data) <= directive['limits']['max_bytes']:
            raise ValueError('empty slice or object budget exceeded')
        # Reuse U1a's tenant namespace; hash the request identity to avoid retries or
        # another finding overwriting an object while readers hold its reference.
        key = pcap_key({'tenant_id': directive['tenant_id'], 'capture_profile': 'preserve',
                        'finding_id': hashlib.sha256(directive['request_id'].encode()).hexdigest()})
        bucket, _, obj = key.partition('/')
        expires = now + directive['limits']['retention_s']
        digest = hashlib.sha256(data).hexdigest()
        metadata = {'tenant-id': hashlib.sha256(directive['tenant_id'].encode()).hexdigest(),
                    'expires-at': str(expires), 'sha256': digest}
        audit({**event, 'action': 'pcap.upload.attempt', 'resource_id': key, 'bytes': len(data)})
        s3.put_object(Bucket=bucket, Key=obj, Body=data, Metadata=metadata,
                      ServerSideEncryption='AES256', Tagging='cernity-pcap=v2')
        audit({**event, 'action': 'pcap.upload.success', 'resource_id': key, 'bytes': len(data)})
        return {**event, 'state': 'completed', 'armed': False, 'kind': 'preserve',
                'pcap_ref': key, 'bytes': len(data), 'sha256': digest,
                'coverage': {**coverage, 'window': directive['window'],
                             'request_latency_s': now - directive['window']['end'],
                             'interface': ring.policy.get('interface')}, 'expires_at': expires}
    except Exception:
        audit({**event, 'action': 'pcap.preserve.failed'})
        raise
    finally:
        if reserved:
            budget.finish(directive)


def retrieve_pcap(ref, auth_header, tokens, s3, audit, now=None, max_size=100_000_000):
    """Authenticated, tenant/RBAC scoped download; no public/presigned URL escape.
    tokens is SERVER configuration: token -> {actor, tenant_id, pcap_read: true}.
    Audit intent must succeed before the object store is touched.
    """
    now = time.time() if now is None else now
    grant = tokens.get(auth_header[7:]) if isinstance(auth_header, str) and auth_header.startswith('Bearer ') else None
    if not isinstance(grant, dict):
        grant = None
    event = {'action': 'pcap.download', 'resource_id': str(ref)[:256],
             'actor': grant.get('actor') if grant else 'anonymous',
             'tenant_id': grant.get('tenant_id') if grant else None}
    if (not grant or grant.get('pcap_read') is not True or not grant.get('tenant_id') or not grant.get('actor')
            or not _valid_key(ref) or not _in_tenant_namespace(ref, tenant_segment(grant['tenant_id']))):
        audit({**event, 'outcome': 'denied'})
        raise PermissionError('PCAP access denied')
    audit({**event, 'outcome': 'attempt'})
    try:
        bucket, _, key = ref.partition('/')
        obj = s3.get_object(Bucket=bucket, Key=key)
        try:
            meta = obj['Metadata']
            expiry = float(meta['expires-at'])
            import math
            if (not math.isfinite(expiry) or expiry <= now
                    or meta['tenant-id'] != hashlib.sha256(grant['tenant_id'].encode()).hexdigest()):
                raise PermissionError('PCAP expired or tenant mismatch')
            if obj['ContentLength'] > max_size:
                raise ValueError('object exceeds download budget')
            data = obj['Body'].read(max_size + 1)
            if len(data) > max_size or len(data) != obj['ContentLength']:
                raise ValueError('invalid object length')
            if hashlib.sha256(data).hexdigest() != meta['sha256']:
                raise ValueError('object digest mismatch')
        finally:
            obj['Body'].close()
        audit({**event, 'outcome': 'success', 'bytes': len(data)})
        return data
    except Exception:
        audit({**event, 'outcome': 'failed'})
        raise
