"""Offline file forensics for carved files (Tier-1 enrichment).

Adds triage context an analyst can act on without an external sandbox:
  * Shannon entropy of the bytes (high entropy => packed/encrypted/compressed).
  * PE metadata for Windows executables: imphash (import-table fingerprint that
    clusters malware families), DLL/EXE, target machine, and compile timestamp.

Pure + dependency-light: entropy is stdlib only; `pefile` is imported lazily inside
pe_metadata() so this module and its tests load without the library, and any parse
failure degrades to "no PE block" rather than raising.
"""
from __future__ import annotations

import math
from collections import Counter

# Entropy at/above this (max is 8.0 bits/byte) reads as packed/encrypted/compressed.
PACKED_ENTROPY = 7.2                     # ponytail: heuristic threshold; raise if noisy


def shannon_entropy(data: bytes) -> float:
    """Bits per byte, 0.0 (uniform) .. 8.0 (random). Empty => 0.0."""
    if not data:
        return 0.0
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in Counter(data).values()), 3)


def is_pe(data: bytes) -> bool:
    return len(data) >= 2 and data[:2] == b"MZ"


def pe_metadata(data: bytes) -> dict:
    """imphash + basic PE header facts, or {} for non-PE / unparseable / no pefile."""
    if not is_pe(data):
        return {}
    try:
        import pefile
    except Exception:                                # noqa: BLE001 - optional dependency
        return {}
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        out = {"is_dll": bool(pe.is_dll()),
               "machine": hex(pe.FILE_HEADER.Machine),
               "compile_time": int(pe.FILE_HEADER.TimeDateStamp)}
        ih = pe.get_imphash()
        if ih:
            out["imphash"] = ih
        pe.close()
        return out
    except Exception:                                # noqa: BLE001 - malformed PE is non-fatal
        return {}


def forensics(data: bytes) -> dict:
    """Full forensic block for a carved file's bytes."""
    ent = shannon_entropy(data)
    out = {"size": len(data), "entropy": ent}
    if ent >= PACKED_ENTROPY:
        out["packed_or_encrypted"] = True
    pe = pe_metadata(data)
    if pe:
        out["pe"] = pe
    return out
