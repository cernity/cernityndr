# Configuring Suricata for Cernity — for the best results

Cernity is only as good as what Suricata tells it. This page is the complete guide to
configuring Suricata so Cernity's detectors have everything they need. You do **not**
run any Cernity logic on the sensor — Suricata produces telemetry, and the Cernity
shipper forwards it. Turning on the right telemetry here is what unlocks the detection.

If you only do three things: **split EVE**, **community-id**, and **JA3/JA4 fingerprints**.
Everything else below makes it better.

---

## The exact settings Cernity needs (at a glance)

These are the specific `suricata.yaml` keys that matter, and why. **Required** = Cernity's
core detection depends on it; **recommended** = materially better detection.

| Setting | Value | Req? | Enables |
|---|---|---|---|
| `outputs.eve-log` × 2 | split into `eve-alerts.json` + `eve-nsm.json` | **required** | the two topics Cernity reads |
| `eve-log.community-id` | `true` (on **both** eve-logs) | **required** | flow correlation key |
| `eve-log.types` | `flow, dns(v3), tls, http, ssh, files, anomaly` / `alert` | **required** | the detectors' inputs |
| `app-layer.protocols.tls.ja3-fingerprints` | `yes` | **strongly rec.** | JA3 known-bad match (threat-intel) |
| `app-layer.protocols.tls.ja4-fingerprints` | `yes` | **strongly rec.** | JA4/JA3 rarity (protocol-detectors) |
| nDPI plugin loaded | `plugins: [ …/ndpi.so ]` | **strongly rec.** | `ndpi.flow_risk` → behavioral detector |
| `tls.extended` / `http.extended` | `yes` | recommended | cert + HTTP detail |
| `dns.version` | `3` | **required** | DNS-tunneling + dns-detector |
| `files.force-hash` | `[sha256]` | recommended | file-threat hash match |
| `file-store.enabled` | `yes` (v2, force-filestore) | overlay-only | file-yara YARA scanning |

The sections below give the full config blocks and the reasoning. A copy-paste
`suricata.yaml` fragment with all of it is in the **Complete config fragment** section
near the end.

---

## 1. Split the EVE output into two files

Cernity reads two files so alerts and network telemetry are shipped separately:

- `eve-alerts.json` — signature alerts
- `eve-nsm.json` — network-security-monitoring records (flow, dns, tls, http, ssh,
  fileinfo, anomaly)

In `suricata.yaml`:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve-alerts.json
      community-id: true
      types:
        - alert

  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve-nsm.json
      community-id: true
      types:
        - flow
        - dns:
            version: 3
        - tls:
            extended: yes
        - http:
            extended: yes
        - ssh
        - files:
            force-magic: yes
            force-hash: [sha256]
        - anomaly
```

## 2. community-id — the flow correlation key (essential)

`community-id: true` (shown above, on **both** outputs) adds a stable hash of the
connection 5-tuple that is identical across tools and directions. Cernity uses it to
line up records that belong to the same connection, and carries it onto per-flow
findings as `community_id` so you can pivot a finding straight into Zeek/Arkime/another
Suricata by the same key (see `docs/enrichment.md`). Keep `community-id-seed` the same
(0) on every sensor so the hashes match fleet-wide. Turn it on everywhere.

## 3. JA3 / JA4 — high-value TLS fingerprints (see §7 for why)

```yaml
app-layer:
  protocols:
    tls:
      ja3-fingerprints: yes
      ja4-fingerprints: yes
```

This puts `ja3`, `ja3s`, and `ja4` on every TLS record. Cernity uses them three
different ways (§7). This is the single most valuable optional field for detection.

## 4. nDPI — application ID + a flow-risk engine (strongly recommended)

ntop's nDPI tags each flow with the real application (`ndpi.proto`), a safety class
(`ndpi.breed`), and a **risk verdict** (`ndpi.flow_risk`: malicious JA3/JA4, DGA,
cleartext credentials, self-signed/expired TLS, anonymizers, …). Cernity's
`behavioral-detectors` reads `ndpi.flow_risk` and raises a high-precision finding when
nDPI flags a flow malicious — free, high-signal detection.

nDPI is a Suricata **plugin** (you need a Suricata built with `--enable-ndpi`; some
vendor images ship it). Load it and make sure the risk set lands on flow records:

```yaml
plugins:
  - /usr/lib/suricata/ndpi.so           # path from your nDPI-enabled build

# then the flow output (in the eve-nsm block above) carries ndpi.proto / breed / flow_risk
```

Consult the Suricata + nDPI docs for the exact build for your version.

## 5. File hashing + extraction (for the file-inspection overlay)

`force-hash: [sha256]` (shown in §1) lets `file-threat` match carved files against
hash blocklists. To also scan carved files with YARA (the `file-yara` service), enable
file extraction so the bytes are available:

```yaml
file-store:
  version: 2
  enabled: yes
  force-filestore: yes
```

Only needed if you run the file-inspection overlay.

## 6. Extended protocol logging (more for the detectors to work with)

- **TLS `extended: yes`** — certificate subject/issuer, validity dates, SNI, version.
  Feeds `protocol-detectors` (self-signed / short-lived cert detection) and the
  threat-intel cert blocklist match.
- **HTTP `extended: yes`** — host, URI, user-agent, method, status. Feeds `http-detector`.
- **DNS `version: 3`** — the current record shape Cernity expects; feeds `dns-detector`
  and the behavioral DNS-tunneling signal.
- **SSH** — feeds SSH brute-force detection.
- **anomaly** — Suricata's own protocol anomalies; feeds `anomaly-detector`.

## 7. JA3 / JA4 — where the value comes from

**What they are.** A TLS handshake has a recognizable shape — which ciphers, extensions,
and options a client offers. **JA3** (and the newer, more robust **JA4**) hash that shape
into a short fingerprint. Because the fingerprint comes from *how* the client speaks TLS,
it identifies the client software **even though the traffic is encrypted** — you can't
read the payload, but you can often tell *what made the connection*. Malware families,
C2 frameworks, and specific tools have characteristic fingerprints.

**Cernity turns that into detection three ways:**

1. **Known-bad matching (`threat-intel`).** Every observed **JA3** is checked against
   **abuse.ch's SSLBL JA3 blocklist** (`ja3_fingerprints.csv`) — a curated list of
   fingerprints seen in malware/C2. A hit is a high-confidence C2/malware finding, on
   encrypted traffic, with no payload inspection. (The same service matches Feodo C2 IPs
   and SSLBL certificate SHA1s.)

2. **Rarity / novelty (`protocol-detectors`).** Cernity keeps a fleet-wide set of the
   client fingerprints it has seen — **JA4 if the record has it, otherwise JA3** (so
   rarity works whichever you enabled), tracked in separate sets so the two types never
   mix. After a warm-up (default 5 distinct), a fingerprint that has **never been seen
   before** is flagged as rare — a new/unusual client appearing in your environment,
   which is exactly how a fresh implant or tool shows up. Tunable: `JA4_WARMUP`,
   `JA4_SEEN_TTL` (default 1 day).

3. **nDPI risk (edge).** nDPI independently flags a **malicious JA3/JA4** as part of its
   `flow_risk` set (§4), which the behavioral detector acts on.

So JA3/JA4 gives you **both** sides of detection on encrypted traffic: *"this fingerprint
is known bad"* (threat-intel) and *"this fingerprint is new/unusual here"* (rarity) —
plus nDPI's verdict. None of it requires decrypting TLS. **This is why enabling
`ja3-fingerprints` and `ja4-fingerprints` (§3) matters so much.**

### JA4+ — the full fingerprint suite

**JA4** (TLS client) is one member of FoxIO's **JA4+** suite, which also fingerprints the
TLS **server** (JA4S), **HTTP** clients (JA4H), **certificates** (JA4X), and **SSH**
(JA4SSH) — so you can fingerprint both ends and multiple protocols, not just the TLS
client. That's powerful for spotting C2: a malicious server has a characteristic JA4S,
a malware HTTP client a characteristic JA4H.

Where Cernity gets JA4+:

- **Edge (always on):** Suricata emits the TLS client **JA4** (and JA3). That's what the
  rarity + known-bad detection above run on, continuously, for the whole fleet.
- **On-demand enrichment (`zeek-central`):** the central Zeek used for packet forensics
  loads FoxIO's JA4 package and **extracts the full JA4+ suite** — JA4 (TLS client),
  **JA4S** (TLS server), **JA4H** (HTTP), **JA4X** (certificate), **JA4SSH** (SSH) — from
  any flow that gets captured, and attaches them to the finding as pivotable IOCs
  (`iocs.ja4`, `ja4s`, `ja4h`, `ja4ssh`). This is the right home for JA4+ depth: rich
  fingerprint context on the findings worth investigating, rather than a fleet-wide
  firehose (server-fingerprint rarity is noisy across legitimate new services, so Cernity
  keeps always-on rarity to the client fingerprint and reserves the server/HTTP/cert/SSH
  fingerprints for this enrichment path).

## 8. Capture and performance

- Sniff a **SPAN/mirror port or a tap**. The capture NIC has no IP and runs promiscuous —
  it only receives copies, never transmits.
- **Prompt flow emission** matters for beacon timing accuracy — Cernity scores beaconing
  on the interval between flow records, so keep flow timeouts sane (Suricata defaults are
  fine for most; very long timeouts blur the interval).
- **High rate (10 Gbps+):** pair Suricata with ntop's **PF_RING (ZC)** for kernel-bypass
  capture without drops. Watch Suricata's `capture.kernel_drops` — drops mean missed
  detections.
- Use up-to-date rules (e.g. ET Open via `suricata-update`) so `ids-alerts` has signal to
  promote.

## 9. Best-results checklist

- [ ] Split EVE into `eve-alerts.json` + `eve-nsm.json`
- [ ] `community-id: true` on both outputs
- [ ] `ja3-fingerprints: yes` + `ja4-fingerprints: yes`
- [ ] nDPI plugin loaded (flows carry `ndpi.flow_risk`)
- [ ] TLS + HTTP `extended: yes`, DNS `version: 3`, SSH, anomaly
- [ ] `force-hash: [sha256]` (and file-store if using the file overlay)
- [ ] Capturing a mirror/tap, promiscuous, drops near zero

## Complete config fragment (copy-paste)

Merge this into your `suricata.yaml` (paths and the nDPI plugin location depend on your
build). This is every Cernity-relevant setting in one place:

```yaml
plugins:
  - /usr/lib/suricata/ndpi.so            # from an nDPI-enabled Suricata build (strongly recommended)

app-layer:
  protocols:
    tls:
      ja3-fingerprints: yes              # -> threat-intel JA3 known-bad match
      ja4-fingerprints: yes              # -> protocol-detectors JA4/JA3 rarity

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve-alerts.json
      community-id: true
      types:
        - alert

  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve-nsm.json
      community-id: true
      types:
        - flow                           # carries ndpi.proto / breed / flow_risk when the plugin is loaded
        - dns:
            version: 3
        - tls:
            extended: yes
        - http:
            extended: yes
        - ssh
        - files:
            force-magic: yes
            force-hash: [sha256]
        - anomaly
        - krb5                             # kerberoasting, AS-REP roasting, password spraying
        - smb                              # ransomware-over-SMB, lateral-exec named pipes, SMB spray
        - dcerpc                           # lateral movement (PsExec/WMI/scheduled-task RPC)

# Only if you run the file-inspection overlay (file-yara):
file-store:
  version: 2
  enabled: yes
  force-filestore: yes
```

### Telemetry availability notes (east-west / evasion detectors)

These detectors depend on how much of each protocol Suricata surfaces in EVE, which
varies by version. Cernity's logic is built to fire the moment the field appears and
to stay quiet (never false-positive) when it doesn't:

- **AS-REP roasting** needs a Kerberos *pre-auth-absent* signal on the AS-REQ. Current
  Suricata EVE does not expose a pre-auth flag, so this detector is **dormant** until a
  build does — it never guesses.
- **Ransomware-over-SMB** and **lateral-exec pipes** rely on SMB command/filename and
  named-pipe fields; granularity varies by Suricata version and SMB dialect.
- **Password spraying** reads Kerberos pre-auth-failure error codes and/or SMB
  session-setup logon failures; account names may not always be present.
- **Domain fronting** fires on ECH (only in very recent Suricata TLS output) or a
  cleartext HTTP `Host` disagreeing with the flow's TLS `SNI`. Fully-encrypted HTTPS
  fronting (no visible Host) is **not** detectable and deliberately does not fire.
- **LLMNR/NBT-NS poisoning** logic exists but Suricata surfaces LLMNR only as DNS
  events (udp/5355) and does **not** decode NBT-NS (udp/137); coverage is LLMNR/mDNS-leaning.

## 10. Point the shipper at these files

The Cernity shipper defaults to `/var/log/suricata/eve-alerts.json` and
`/var/log/suricata/eve-nsm.json`. If Suricata writes elsewhere, set `SURICATA_LOG_DIR`
(or the individual paths) when you start the sensor bundle — see `docs/deploy-sensor.md`.

## What Cernity does with each event type

| EVE event | Topic | Used by |
|---|---|---|
| alert | `suricata.raw.v1` | ids-alerts |
| flow (+ ndpi, community-id) | `suricata.flow.v1` | behavioral, east-west, anomaly, coverage |
| dns (v3) | `suricata.dns.v1` | dns-detector, behavioral (tunneling) |
| tls (+ ja3/ja4, extended) | `suricata.tls.v1` | protocol-detectors (JA4 rarity, certs), threat-intel (JA3) |
| http (extended) | `suricata.http.v1` | http-detector |
| ssh | `suricata.ssh.v1` | protocol-detectors (SSH brute force) |
| fileinfo (+ hash) | `suricata.file.v1` | file-threat, file-yara |
| anomaly | `suricata.anomaly.v1` | anomaly-detector |
