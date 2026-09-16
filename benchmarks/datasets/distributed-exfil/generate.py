#!/usr/bin/env python3
"""Distributed low-and-slow exfil scenario (§49.4 positive path + §43.5 matched benign control).

Ground truth: internal host 10.0.0.15 exfiltrates to an EXTERNAL collector by SPREADING the
transfer across MANY materially-contributing flows — each below the burst ceiling, cumulatively
in the low-and-slow band (5MB..50MB). This is the sustained-trickle pattern exfil_check misses
and low_slow_exfil is meant to catch (T1029/T1030).

The MATCHED BENIGN CONTROL (§43.5) shares the surface features the detector keys on — same source,
same external-egress shape, comparable total bytes, many connections — but concentrates the bytes in
ONE bulk transfer with small callbacks (a legitimate backup upload). It has < 5 material flows, so it
is NOT distributed low-and-slow. A correct detector fires on the spread transfer and stays silent on
the concentrated one: the discrimination is the whole point of the §49.4 materiality feature (it is
NOT a beacon-specific exclusion). Both live in one pcap so the positive and its control run under
identical conditions.

COMPRESSED timespan (M1.6): the episode is spread over ~90s so paced replay (§5) completes quickly
while the flows still land inside the detector's rolling window. Deterministic (fixed seed + stamps).
"""
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap
import random

random.seed(2029)
BASE = 1_700_000_000
MSS = 1460                      # genuine MTU-sized segments — real byte counts, no jumbo-frame inflation
SRC = "10.0.0.15"              # internal exfiltrating host
EXFIL_DST = "203.0.113.200"   # external collector (positive) — TEST-NET-3 documentation range
BENIGN_DST = "198.51.100.50"  # external backup target (concentrated control) — TEST-NET-2 documentation range
AUTHZ_DST = "192.0.2.100"     # AUTHORIZED distributed transfer (§59.3 selectivity) — TEST-NET-1; allowlisted at run time
pkts = []


def _stamp(p, t):
    p.time = t
    return p


def bulk_session(src, dst, dport, t0, total_bytes, dur=1.0):
    """A single TCP session that carries `total_bytes` client->server across MSS-sized segments,
    spread over `dur` seconds. Suricata records this as one flow with bytes_toserver ~= total_bytes,
    so each session is one entry in the detector's per-flow (exb) window."""
    sport = random.randint(1024, 65535)
    sc, ss = random.randint(0, 2**31), random.randint(0, 2**31)
    c2s, s2c = IP(src=src, dst=dst), IP(src=dst, dst=src)
    pkts.append(_stamp(Ether() / c2s / TCP(sport=sport, dport=dport, flags="S", seq=sc), t0))
    pkts.append(_stamp(Ether() / s2c / TCP(sport=dport, dport=sport, flags="SA", seq=ss, ack=sc + 1), t0 + 0.005))
    pkts.append(_stamp(Ether() / c2s / TCP(sport=sport, dport=dport, flags="A", seq=sc + 1, ack=ss + 1), t0 + 0.008))
    nseg = max(1, (total_bytes + MSS - 1) // MSS)
    seq = sc + 1
    for i in range(nseg):
        n = min(MSS, total_bytes - i * MSS)
        t = t0 + 0.01 + dur * (i / nseg)
        pkts.append(_stamp(Ether() / c2s / TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=ss + 1) / Raw(b"\x11" * n), t))
        seq += n
        if i % 8 == 0:      # occasional server ack (keeps the session realistic; server->client bytes stay small)
            pkts.append(_stamp(Ether() / s2c / TCP(sport=dport, dport=sport, flags="A", seq=ss + 1, ack=seq), t + 0.002))
    pkts.append(_stamp(Ether() / c2s / TCP(sport=sport, dport=dport, flags="FA", seq=seq, ack=ss + 1), t0 + dur + 0.02))
    pkts.append(_stamp(Ether() / s2c / TCP(sport=dport, dport=sport, flags="FA", seq=ss + 1, ack=seq + 1), t0 + dur + 0.03))


def dns(src, qname, t):
    sport = random.randint(1024, 65535)
    pkts.append(_stamp(Ether() / IP(src=src, dst="10.0.0.1") / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname)), t))


# --- POSITIVE: distributed low-and-slow exfil ---------------------------------------------------
# 11 materially-contributing flows (>= min_material_flows=5, >= min_conns=10), ~520KB each ->
# ~5.7MB total, inside the low-and-slow band (>= 5MB low_floor, < 50MB burst ceiling). Session
# start times are IRREGULAR (random jitter) so the transfer is NOT periodic — this isolates the
# low_slow_exfil signal from the beaconing detector: a genuine low-and-slow exfil trickles at
# irregular intervals, and we want the exfil label to reach the SIEM on its own, not be deduped
# behind a c2/beacon finding on the same entity pair.
EXFIL_FLOWS = 11
EXFIL_PER_FLOW = 520_000
_t = 0.0
for i in range(EXFIL_FLOWS):
    bulk_session(SRC, EXFIL_DST, 443, BASE + _t, EXFIL_PER_FLOW, dur=random.uniform(1.0, 3.0))
    _t += random.uniform(2.0, 14.0)      # irregular gaps -> not a beacon

# --- MATCHED AUTHORIZED CONTROL (§59.3 selectivity): SAME distributed low-and-slow SHAPE ----------
# Identical to the positive — 11 material flows, ~5.7MB, irregular timing — but to an AUTHORIZED
# destination (declared on NDR_EXFIL_ALLOWLIST at run time, e.g. a sanctioned offsite backup). The
# ONLY difference from the positive is authorization CONTEXT, not traffic shape: a correct detector
# must NOT raise low_slow_exfil here. This is the "distributed transfer is not itself malicious" test.
_t = 0.0
for i in range(EXFIL_FLOWS):
    bulk_session(SRC, AUTHZ_DST, 443, BASE + _t, EXFIL_PER_FLOW, dur=random.uniform(1.0, 3.0))
    _t += random.uniform(2.0, 14.0)

# --- MATCHED BENIGN CONTROL: concentrated bulk upload + callbacks -------------------------------
# One 5.7MB transfer (a backup) + 12 small callback flows (2KB each: status pings) at IRREGULAR
# intervals (so they don't beacon either). Same source, comparable total bytes and connection
# count, but only ONE material flow -> NOT distributed. A correct detector emits NO exfil finding.
bulk_session(SRC, BENIGN_DST, 443, BASE + 5.0, 5_700_000, dur=40.0)
_t = 8.0
for i in range(12):
    bulk_session(SRC, BENIGN_DST, 443, BASE + _t, 2_000, dur=0.2)
    _t += random.uniform(3.0, 11.0)      # irregular callbacks -> not a beacon

# --- benign background so the run is not exfil-only ---------------------------------------------
webs = ["www.example.com", "cdn.example.net", "api.github.com"]
for i in range(30):
    dns(random.choice(["10.0.0.10", "10.0.0.11"]), random.choice(webs), BASE + i * 3.0)

pkts.sort(key=lambda p: p.time)
wrpcap("/out/distributed-exfil.pcap", pkts)
print(f"wrote {len(pkts)} packets -> /out/distributed-exfil.pcap "
      f"(exfil {EXFIL_FLOWS}x{EXFIL_PER_FLOW}B spread; benign 1x5.7MB concentrated + 12 callbacks)")
