#!/usr/bin/env python3
"""Benign-only scenario (S10) for the valid-empty-completion gate. Ordinary DNS + HTTP on
standard ports from two clean hosts; NO beacon, NO malicious host, NO port/proto mismatch.
Deterministic (fixed seed + timestamps). Both arms should complete with zero detections."""
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap
import random

random.seed(4242)
BASE = 1_700_000_000
pkts = []


def _stamp(p, t):
    p.time = t
    return p


def tcp_http(src, dst, t0):
    sport = random.randint(1024, 65535)
    sc, ss = random.randint(0, 2**31), random.randint(0, 2**31)
    c2s, s2c = IP(src=src, dst=dst), IP(src=dst, dst=src)
    pkts.append(_stamp(Ether() / c2s / TCP(sport=sport, dport=80, flags="S", seq=sc), t0))
    pkts.append(_stamp(Ether() / s2c / TCP(sport=80, dport=sport, flags="SA", seq=ss, ack=sc + 1), t0 + 0.02))
    pkts.append(_stamp(Ether() / c2s / TCP(sport=sport, dport=80, flags="A", seq=sc + 1, ack=ss + 1), t0 + 0.03))
    body = b"GET / HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    pkts.append(_stamp(Ether() / c2s / TCP(sport=sport, dport=80, flags="PA", seq=sc + 1, ack=ss + 1) / Raw(body), t0 + 0.05))
    pkts.append(_stamp(Ether() / s2c / TCP(sport=80, dport=sport, flags="A", seq=ss + 1, ack=sc + 1 + len(body)), t0 + 0.07))
    pkts.append(_stamp(Ether() / c2s / TCP(sport=sport, dport=80, flags="FA", seq=sc + 1 + len(body), ack=ss + 1), t0 + 0.10))


def dns(src, qname, t):
    sport = random.randint(1024, 65535)
    pkts.append(_stamp(Ether() / IP(src=src, dst="8.8.8.8") / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname)), t))


hosts = ["10.0.0.10", "10.0.0.11"]
domains = ["www.example.com", "cdn.example.net", "api.github.com", "images.unsplash.com"]
webs = ["93.184.216.34", "151.101.1.140", "140.82.112.3"]
t = BASE
for _ in range(50):
    t += random.uniform(2, 30)
    if random.random() < 0.5:
        dns(random.choice(hosts), random.choice(domains), t)
    else:
        tcp_http(random.choice(hosts), random.choice(webs), t)

pkts.sort(key=lambda p: p.time)
wrpcap("/out/synthetic-benign.pcap", pkts)
print(f"wrote {len(pkts)} packets -> /out/synthetic-benign.pcap")
