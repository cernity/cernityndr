#!/usr/bin/env python3
"""S11 — short/sparse activity below the detector's evidence threshold: only 4 callbacks from
10.0.0.5 (beacon_score needs >= 6), so the behavioural detector CANNOT confirm a beacon. The
point is to check the report HONESTLY admits the miss and the unavailable evidence, not to score
a detection. Deterministic (fixed seed + timestamps)."""
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap
import random

random.seed(1111)
BASE = 1_700_000_000
pkts = []


def _stamp(p, t):
    p.time = t
    return p


def tcp_session(src, dst, dport, t0, payload=b""):
    sport = random.randint(1024, 65535)
    sc, ss = random.randint(0, 2**31), random.randint(0, 2**31)
    c2s, s2c = IP(src=src, dst=dst), IP(src=dst, dst=src)
    pkts.append(_stamp(Ether() / c2s / TCP(sport=sport, dport=dport, flags="S", seq=sc), t0))
    pkts.append(_stamp(Ether() / s2c / TCP(sport=dport, dport=sport, flags="SA", seq=ss, ack=sc + 1), t0 + 0.02))
    pkts.append(_stamp(Ether() / c2s / TCP(sport=sport, dport=dport, flags="A", seq=sc + 1, ack=ss + 1), t0 + 0.03))
    if payload:
        pkts.append(_stamp(Ether() / c2s / TCP(sport=sport, dport=dport, flags="PA", seq=sc + 1, ack=ss + 1) / Raw(payload), t0 + 0.05))
    pkts.append(_stamp(Ether() / c2s / TCP(sport=sport, dport=dport, flags="FA", seq=sc + 1 + len(payload), ack=ss + 1), t0 + 0.10))


# Only 4 callbacks — deliberately below the beacon evidence threshold.
t = BASE
for _ in range(4):
    tcp_session("10.0.0.5", "203.0.113.66", 443, t, payload=b"\x17\x03\x03\x00\x10" + bytes(random.getrandbits(8) for _ in range(16)))
    t += random.uniform(4.0, 6.0)

# A little benign background so the baseline arm is non-empty.
tb = BASE
for _ in range(20):
    tb += random.uniform(0.5, 3.0)
    pkts.append(_stamp(Ether() / IP(src=random.choice(["10.0.0.10", "10.0.0.11"]), dst="8.8.8.8")
                       / UDP(sport=random.randint(1024, 65535), dport=53)
                       / DNS(rd=1, qd=DNSQR(qname="www.example.com")), tb))

pkts.sort(key=lambda p: p.time)
wrpcap("/out/synthetic-sparse.pcap", pkts)
print(f"wrote {len(pkts)} packets -> /out/synthetic-sparse.pcap")
