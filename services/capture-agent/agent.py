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
import os
import re

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


_SAFE_KEY = re.compile(r"^[A-Za-z0-9._\-/]{1,256}$")


def _valid_key(ref) -> bool:
    """A MinIO object key we're willing to trust verbatim from a bus directive: safe
    charset, bounded length, no path traversal, no absolute path. The directive comes
    off the bus, so an untrusted/forged pcap_ref must not become an arbitrary key."""
    return (isinstance(ref, str) and bool(_SAFE_KEY.match(ref))
            and ".." not in ref and not ref.startswith("/"))


def _sanitize(s, default: str = "cap") -> str:
    """Reduce a directive-supplied component to a safe filename atom (no separators
    and no dot-run traversal, so it can never introduce traversal in the fallback)."""
    s = re.sub(r"[^A-Za-z0-9._\-]", "", str(s)).replace("..", "").strip(".")[:128]
    return s or default


def pcap_key(directive: dict) -> str:
    """MinIO object key (bucket/key) the agent uploads to and hands to Zeek.
    Matches what the orchestrator advertised so the loop stays consistent. An
    advertised pcap_ref is honored only if it is a safe key; otherwise (and for the
    computed fallback) every component is sanitized."""
    ref = directive.get("pcap_ref")
    if _valid_key(ref):
        return ref
    fid = _sanitize(directive.get("finding_id") or directive.get("value"))
    profile = _sanitize(directive.get("capture_profile", "ip"))
    return f"ndr-pcap/{fid}-{profile}.pcap"


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


def lookback_bpf(directive: dict) -> "str | None":
    """BPF to carve the finding's connection out of the ring slice. Buildable only
    for the IP profile (a packet-level host filter); app-layer profiles (sni/ja4/
    dns) have no packet BPF from an IP-keyed ring, so return None (no carve)."""
    if directive.get("capture_profile", "ip") == "ip":
        value = (directive.get("value") or "").strip()
        # validate() already guarantees no whitespace; guard the shell/BPF anyway
        if value and not any(c.isspace() for c in value):
            return f"host {value}"
    return None


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


def file_extracted_event(sensor_id: str, sha256: str, size: int, mime: str = "") -> dict:
    """Shape an ndr.file.extracted.v1 announcement for file-yara."""
    return {"sensor_id": sensor_id, "sha256": sha256, "size": size,
            "mime": mime, "object_ref": f"{FILES_BUCKET}/{sha256}"}
