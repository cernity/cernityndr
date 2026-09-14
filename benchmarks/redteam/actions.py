"""Attack-action library for the Stage-5 red-team orchestrator.

Each builder returns an action = {id, behavior, attacker, targets, cmd}: the behaviour CLASS matches
the scorer taxonomy (recon/c2/exfil/lateral), attacker+targets are the independent-truth entities,
and `cmd` is the REAL command that puts the traffic on the wire. Commands assume the tools are present
and an ISOLATED target range (never point these at anything you do not own). Swap tools/targets per
lab; the orchestrator's truth is derived from attacker/targets/behavior, not from the specific tool.
"""


def scan(attacker, targets, ports="445,3389"):
    """SYN scan across internal hosts (recon). targets = the scanned host IPs (independent truth)."""
    return {"id": "rt-scan", "behavior": "recon", "attacker": attacker, "targets": list(targets),
            "cmd": ["nmap", "-sS", "-n", "-p", ports, *targets]}


def beacon(attacker, c2, interval=5, count=20, port=443):
    """A periodic C2 beacon with no signature (c2). A scripted regular caller — the behavioural gap
    raw Suricata misses. targets = [c2]."""
    one = (f"import socket,time\n"
           f"for _ in range({count}):\n"
           f"    s=socket.socket();\n"
           f"    try:\n        s.connect(('{c2}',{port})); s.sendall(b'\\x17\\x03\\x03\\x00 '+b'x'*32)\n"
           f"    except OSError: pass\n"
           f"    finally: s.close()\n"
           f"    time.sleep({interval})\n")
    return {"id": "rt-beacon", "behavior": "c2", "attacker": attacker, "targets": [c2],
            "cmd": ["python3", "-c", one]}


def dns_tunnel(attacker, resolver, base_domain, queries=60):
    """High-entropy/high-cardinality DNS to one base domain (exfil via DNS tunnel). targets=[resolver]."""
    one = (f"import socket,os,base64\n"
           f"for i in range({queries}):\n"
           f"    lbl=base64.b32encode(os.urandom(20)).decode().strip('=').lower()[:40]\n"
           f"    q=lbl+'.'+'{base_domain}'\n"
           f"    try: socket.getaddrinfo(q,53)\n"
           f"    except OSError: pass\n")
    return {"id": "rt-dns-tunnel", "behavior": "exfil", "attacker": attacker, "targets": [resolver],
            "cmd": ["python3", "-c", one]}


def exfil(attacker, dest, mb=50, port=443):
    """A single large outbound transfer (exfil / large_transfer). targets=[dest]."""
    one = (f"import socket\n"
           f"s=socket.socket()\n"
           f"try:\n    s.connect(('{dest}',{port}))\n    b=b'x'*65536\n"
           f"    for _ in range({mb}*16): s.sendall(b)\n"
           f"except OSError: pass\n"
           f"finally: s.close()\n")
    return {"id": "rt-exfil", "behavior": "exfil", "attacker": attacker, "targets": [dest],
            "cmd": ["python3", "-c", one]}


def lateral(attacker, targets, user="svc", pw="x"):
    """East-west lateral movement / SMB fan-out (lateral). targets = the internal hosts hit.
    Uses crackmapexec if present; the truth is the attacker->targets relationship regardless of tool."""
    return {"id": "rt-lateral", "behavior": "lateral", "attacker": attacker, "targets": list(targets),
            "cmd": ["crackmapexec", "smb", *targets, "-u", user, "-p", pw]}
