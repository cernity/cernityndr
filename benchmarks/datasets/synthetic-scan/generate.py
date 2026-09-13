#!/usr/bin/env python3
"""S04 — internal scan / lateral fan-out: one host (10.0.0.8) sends SYNs to many internal hosts
on a service port (445), the strobe/fan-out signature, against a benign backdrop. Tests whether
related events are consolidated into one incident rather than N alerts. Compressed (~60s),
deterministic (fixed seed + timestamps)."""
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap
import random

random.seed(404)
BASE = 1_700_000_000
pkts = []


def _stamp(p, t):
    p.time = t
    return p


def syn(src, dst, dport, t):
    pkts.append(_stamp(Ether() / IP(src=src, dst=dst)
                       / TCP(sport=random.randint(1024, 65535), dport=dport, flags="S",
                             seq=random.randint(0, 2**31)), t))


# Scanner: 10.0.0.8 SYN-scans 10.0.0.20..10.0.0.70 on 445 (+ a few on 3389), ~0.4s apart.
t = BASE
for host in range(20, 71):
    syn("10.0.0.8", f"10.0.0.{host}", 445, t)
    t += random.uniform(0.2, 0.6)
    if host % 7 == 0:
        syn("10.0.0.8", f"10.0.0.{host}", 3389, t)
        t += random.uniform(0.2, 0.6)

# Benign backdrop: ordinary DNS from clean hosts over the same window.
tb = BASE
for _ in range(30):
    tb += random.uniform(0.5, 2.5)
    pkts.append(_stamp(Ether() / IP(src=random.choice(["10.0.0.10", "10.0.0.11"]), dst="8.8.8.8")
                       / UDP(sport=random.randint(1024, 65535), dport=53)
                       / DNS(rd=1, qd=DNSQR(qname="www.example.com")), tb))

pkts.sort(key=lambda p: p.time)
wrpcap("/out/synthetic-scan.pcap", pkts)
print(f"wrote {len(pkts)} packets -> /out/synthetic-scan.pcap")
