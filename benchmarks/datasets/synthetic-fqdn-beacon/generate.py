#!/usr/bin/env python3
"""S03 — FQDN beacon: 10.0.0.5 periodically resolves ONE callback domain (cdn.evil.example) that
ROTATES its A-record across several IPs, then connects to whichever IP it got. Per-IP the beacon
looks sparse, but aggregated by DOMAIN (via the ip->domain cache the detector builds from DNS
answers) it is a regular beacon over rotating destinations. Tests domain aggregation + selectivity.
Requires DNS RESPONSES (answers) so the resolver mapping is learnable. Compressed (~90s),
deterministic."""
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap
import random

random.seed(303)
BASE = 1_700_000_000
DOMAIN = "cdn.evil.example"
ROTATE = ["203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13"]
pkts = []


def _stamp(p, t):
    p.time = t
    return p


def dns_round(client, qname, answer_ip, t):
    sport = random.randint(1024, 65535)
    # query
    pkts.append(_stamp(Ether() / IP(src=client, dst="8.8.8.8") / UDP(sport=sport, dport=53)
                       / DNS(rd=1, qd=DNSQR(qname=qname)), t))
    # response with a rotating A record (populates the resolver's ip->domain mapping)
    pkts.append(_stamp(Ether() / IP(src="8.8.8.8", dst=client) / UDP(sport=53, dport=sport)
                       / DNS(qr=1, aa=1, qd=DNSQR(qname=qname),
                             an=DNSRR(rrname=qname, type="A", ttl=60, rdata=answer_ip)), t + 0.01))


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


t = BASE
for i in range(16):
    ip = ROTATE[i % len(ROTATE)]
    dns_round("10.0.0.5", DOMAIN, ip, t)
    tcp_session("10.0.0.5", ip, 443, t + 0.2, payload=b"\x17\x03\x03\x00\x20" + bytes(random.getrandbits(8) for _ in range(32)))
    t += 5.0

# benign DNS backdrop
tb = BASE
for _ in range(20):
    tb += random.uniform(0.5, 3.0)
    dns_round(random.choice(["10.0.0.10", "10.0.0.11"]), "www.example.com", "93.184.216.34", tb)

pkts.sort(key=lambda p: p.time)
wrpcap("/out/synthetic-fqdn-beacon.pcap", pkts)
print(f"wrote {len(pkts)} packets -> /out/synthetic-fqdn-beacon.pcap")
