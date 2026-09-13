#!/usr/bin/env python3
"""S06 — DNS tunnelling: one host (10.0.0.9) emits many long, high-entropy encoded subdomains
under a single parent (data.t.example.net), the signature of DNS-tunnel exfiltration, against a
benign backdrop of ordinary lookups. Tests tunnel sensitivity vs DNS false positives. Compressed
timespan (~90s), deterministic (fixed seed + timestamps)."""
from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap
import random
import string

random.seed(606)
BASE = 1_700_000_000
PARENT = "data.t.example.net"
pkts = []


def _stamp(p, t):
    p.time = t
    return p


def dns(src, qname, t):
    pkts.append(_stamp(Ether() / IP(src=src, dst="8.8.8.8")
                       / UDP(sport=random.randint(1024, 65535), dport=53)
                       / DNS(rd=1, qd=DNSQR(qname=qname)), t))


def _label(n):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


# Tunnel host: ~60 queries, each a long encoded label under the one parent, ~1.5s apart.
t = BASE
for _ in range(60):
    dns("10.0.0.9", f"{_label(28)}.{_label(20)}.{PARENT}", t)
    t += random.uniform(0.8, 2.2)

# Benign backdrop: ordinary short lookups to varied domains from clean hosts.
benign = ["www.google.com", "cdn.example.net", "api.github.com", "images.unsplash.com", "mail.proton.me"]
tb = BASE
for _ in range(40):
    tb += random.uniform(0.5, 3.0)
    dns(random.choice(["10.0.0.10", "10.0.0.11"]), random.choice(benign), tb)

pkts.sort(key=lambda p: p.time)
wrpcap("/out/synthetic-dns-tunnel.pcap", pkts)
print(f"wrote {len(pkts)} packets -> /out/synthetic-dns-tunnel.pcap")
