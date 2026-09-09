"""DNS detections beyond tunneling (Tier-1 detection-gap fill).

The behavioral-detectors service already scores DNS *tunneling* (query volume +
subdomain entropy). This adds the DNS detections that nothing else does, all from
`suricata.dns.v1` data we already collect:

  - dga_domain    : the registered label looks algorithmically generated (DGA C2).
  - nxdomain_burst: a client getting many NXDOMAINs fast (DGA rendezvous sweep /
                    C2 fallback churn).

Pure and testable; app.py is the Kafka I/O shell and owns the NXDOMAIN window.
"""
import math
from collections import Counter

_VOWELS = set("aeiou")


def query_name(eve: dict) -> str:
    """Extract the queried name from a Suricata DNS EVE record (v3 grouped or flat)."""
    d = eve.get("dns") or {}
    qs = d.get("queries")
    if isinstance(qs, list) and qs:
        return (qs[0].get("rrname") or "").lower()
    return (d.get("rrname") or "").lower()


def rcode(eve: dict) -> str:
    d = eve.get("dns") or {}
    return str(d.get("rcode") or "").upper()


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in Counter(s).values())


def registered_label(qname: str) -> str:
    """The label to score for DGA: the second-to-last label (the registered
    domain, left of the public suffix). Scoring THIS and not the full name avoids
    the classic false positive where a random-looking *subdomain* sits under a
    benign service (d2k1f...cloudfront.net -> 'cloudfront'; randomhash.s3... -> 's3')."""
    parts = [p for p in (qname or "").strip(".").split(".") if p]
    if len(parts) < 2:
        return ""
    return parts[-2]


def dga_score(qname: str) -> tuple[float, str]:
    """0..1 DGA-likeness of the registered label. Combines Shannon entropy,
    longest consonant run, vowel scarcity, and digit ratio. Labels shorter than
    8 chars score 0 (too short to be confidently algorithmic)."""
    label = registered_label(qname)
    if len(label) < 8:
        return 0.0, label
    ent = min(_shannon(label) / 4.0, 1.0)             # ~4 bits max over [a-z0-9]
    digits = sum(c.isdigit() for c in label) / len(label)
    vowels = sum(c in _VOWELS for c in label) / len(label)
    run = mx = 0
    for c in label:
        if c.isalpha() and c not in _VOWELS:
            run += 1
            mx = max(mx, run)
        else:
            run = 0
    consonant = min(mx / 6.0, 1.0)
    vowel_scarcity = 1.0 - min(vowels / 0.30, 1.0)    # English is ~40% vowels
    score = 0.35 * ent + 0.25 * consonant + 0.20 * vowel_scarcity + 0.20 * min(digits / 0.30, 1.0)
    return round(min(score, 1.0), 3), label


def is_dga(qname: str, threshold: float = 0.72) -> tuple[bool, float, str]:
    score, label = dga_score(qname)
    return score >= threshold, score, label


def nxdomain_burst(count: int, threshold: int = 20) -> bool:
    """True when a client's NXDOMAIN count in the window crosses the threshold."""
    return count >= threshold
