#!/usr/bin/env python3
"""S08 — dedup: one host beacons to TWO distinct C2s. Each beacon is ~20 near-identical
callbacks (repetition that must collapse to one finding per incident), and the two C2s are two
DISTINCT incidents (dedup must not hide the second). Tests that repeated detection reduces
analyst repetition WITHOUT hiding a new incident. Compressed (~100s), deterministic."""
from scapy.all import Ether, IP, TCP, Raw, wrpcap
import random

random.seed(808)
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


def beacon(src, dst, count, interval, start):
    t = start
    for _ in range(count):
        tcp_session(src, dst, 443, t, payload=b"\x17\x03\x03\x00\x20" + bytes(random.getrandbits(8) for _ in range(32)))
        t += interval


beacon("10.0.0.5", "203.0.113.66", 20, 5.0, BASE)        # incident A (repeated -> 1 finding)
beacon("10.0.0.5", "198.51.100.77", 20, 5.0, BASE + 2.5)  # incident B (distinct -> must not be hidden)

pkts.sort(key=lambda p: p.time)
wrpcap("/out/synthetic-dedup.pcap", pkts)
print(f"wrote {len(pkts)} packets -> /out/synthetic-dedup.pcap")
