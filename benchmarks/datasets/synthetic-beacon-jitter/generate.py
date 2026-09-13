#!/usr/bin/env python3
"""S02 — jittered C2 callbacks. Same episode as S01 (malicious 10.0.0.5 -> C2 203.0.113.66) but
the callback interval JITTERS around 5s (uniform 3-7s) instead of a fixed period, to test that
beaconing sensitivity survives realistic jitter (the detector scores regularity with Bowley-skew
+ MADM, which a few jittered intervals should not defeat). Compressed real timespan (~100s) so a
paced replay stays short. Deterministic (fixed seed + timestamps)."""
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap
import random

random.seed(2026)
BASE = 1_700_000_000
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
    pkts.append(_stamp(Ether() / c2s / TCP(sport=sport, dport=dport, flags="FA", seq=sc + 1 + len(payload), ack=ss + 1), t0 + 0.10))


def dns(src, qname, t):
    pkts.append(_stamp(Ether() / IP(src=src, dst="8.8.8.8") / UDP(sport=random.randint(1024, 65535), dport=53) / DNS(rd=1, qd=DNSQR(qname=qname)), t))


C2 = "203.0.113.66"
t = BASE
for _ in range(BEACONS):
    tcp_session("10.0.0.5", C2, 443, t, payload=b"\x17\x03\x03\x00\x20" + bytes(random.getrandbits(8) for _ in range(32)))
    t += random.uniform(3.0, 7.0)          # jittered interval around 5s

domains = ["www.google.com", "cdn.example.net", "api.github.com"]
webs = ["93.184.216.34", "151.101.1.140"]
tb = BASE
for _ in range(40):
    tb += random.uniform(0.3, 3.0)
    if random.random() < 0.6:
        dns(random.choice(["10.0.0.10", "10.0.0.11"]), random.choice(domains), tb)
    else:
        tcp_session(random.choice(["10.0.0.10", "10.0.0.11"]), random.choice(webs), 80, tb,
                    payload=b"GET / HTTP/1.1\r\nHost: example\r\n\r\n")

pkts.sort(key=lambda p: p.time)
wrpcap("/out/synthetic-beacon-jitter.pcap", pkts)
print(f"wrote {len(pkts)} packets -> /out/synthetic-beacon-jitter.pcap")
