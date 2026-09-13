#!/usr/bin/env python3
"""Synthetic beacon scenario (built-in). Ground truth: malicious host 10.0.0.5, a periodic C2
beacon with no signature — the behavioural gap raw Suricata misses and Cernity's beaconing
detector catches. Benign hosts do ordinary DNS/HTTP.

COMPRESSED real timespan (M1.6): the beacon fires every 5s (still regular = beaconing), so the
whole scenario spans ~100s and a PACED replay (CERNITY_FEED_PACED=1, honouring inter-arrival
timing per §5) completes in ~100s instead of the ~20min a 60s interval would take. The interval
is real recorded timing, not an accelerated clock. Deterministic (fixed seed + timestamps)."""
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap
import random

random.seed(1337)
BASE = 1_700_000_000
BEACON_INTERVAL = 5      # seconds between callbacks (compressed but regular)
BEACONS = 20
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
        pkts.append(_stamp(Ether() / s2c / TCP(sport=dport, dport=sport, flags="A", seq=ss + 1, ack=sc + 1 + len(payload)), t0 + 0.07))
    pkts.append(_stamp(Ether() / c2s / TCP(sport=sport, dport=dport, flags="FA", seq=sc + 1 + len(payload), ack=ss + 1), t0 + 0.10))


def dns(src, qname, t):
    sport = random.randint(1024, 65535)
    pkts.append(_stamp(Ether() / IP(src=src, dst="8.8.8.8") / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname)), t))


# Malicious: 10.0.0.5 beacons to a fixed C2 at a regular interval (documentation-range dest).
C2 = "203.0.113.66"
for i in range(BEACONS):
    tcp_session("10.0.0.5", C2, 443, BASE + i * BEACON_INTERVAL,
                payload=b"\x17\x03\x03\x00\x20" + bytes(random.getrandbits(8) for _ in range(32)))

# Benign: ordinary, irregular DNS + HTTP from two clean hosts, over the same ~100s window.
domains = ["www.google.com", "cdn.example.net", "api.github.com", "images.unsplash.com"]
webs = ["93.184.216.34", "151.101.1.140", "140.82.112.3"]
t = BASE
for _ in range(40):
    t += random.uniform(0.3, 3.0)
    if random.random() < 0.6:
        dns(random.choice(["10.0.0.10", "10.0.0.11"]), random.choice(domains), t)
    else:
        tcp_session(random.choice(["10.0.0.10", "10.0.0.11"]), random.choice(webs), 80, t,
                    payload=b"GET / HTTP/1.1\r\nHost: example\r\n\r\n")

pkts.sort(key=lambda p: p.time)
wrpcap("/out/synthetic-beacon.pcap", pkts)
print(f"wrote {len(pkts)} packets -> /out/synthetic-beacon.pcap (span ~{BEACONS*BEACON_INTERVAL}s)")
