# Suricata logging vs Zeek — capability parity

A common objection to a Suricata-based NDR is "but Zeek gives richer protocol logs." This page
maps, log type by log type, what **Zeek** produces standalone against the **Suricata EVE**
output Cernity configures (see [suricata-config.md](suricata-config.md)). The goal is to show
that a properly-configured Suricata gives Cernity essentially the same protocol telemetry Zeek
does — and to be honest about the two places it doesn't.

The table below is generated from `benchmarks/parity.py` (the source of truth, unit-tested);
the [benchmark](../benchmarks/) runs Zeek as a reference arm over the same PCAP so this parity
is *demonstrated*, not just asserted.

## Parity map

| Zeek log | Suricata EVE equivalent | Coverage | Note |
|---|---|---|---|
| `conn` | flow (+ community-id) | full | connection records + flow hash |
| `dns` | dns (version 3) | full | queries and answers |
| `http` | http (extended) | full | method / host / user-agent / status |
| `ssl` | tls (extended) | full | version / SNI / cipher |
| `x509` | tls subject/issuer/notbefore/notafter | partial | cert fields, not the full DER chain |
| `files` | files (force-hash) | full | file extraction + hashes |
| `ssh` | ssh | full | client/server banners |
| `smb` | smb | partial | command/filename; op granularity varies by Suricata version |
| `kerberos` | krb5 | partial | sname/encryption/error_code; no pre-auth flag exposed |
| `dce_rpc` | dcerpc | full | interface UUIDs |
| `ntlm` | smb.ntlmssp | partial | surfaced inside smb events |
| `ja4` | tls.ja4 / ja4s | full | client + server fingerprints |
| `weird` | anomaly | partial | Suricata anomaly events cover some Zeek "weird"s |
| `notice` | (none — Cernity findings) | none | Zeek's scripted notices have no direct EVE analog; **Cernity's detectors ARE that behavioral layer** — the point of the whole comparison |

## Reading it

- **Full coverage** on the workhorse protocol logs (conn/dns/http/ssl/files/ssh/dce_rpc) plus
  JA4 fingerprinting: Suricata EVE feeds Cernity the same connection and protocol structure
  Zeek would.
- **Partial** on `x509`, `smb`, `kerberos`, `ntlm`, `weird`: Suricata surfaces the fields
  Cernity's detectors need, but with less depth than Zeek in places (full cert chains,
  fine-grained SMB ops, Kerberos pre-auth state). These are documented telemetry limits, not
  detection gaps in Cernity's logic — the [Suricata config notes](suricata-config.md) call out
  exactly where.
- **`notice` is the honest gap — and the thesis.** Zeek's value beyond raw logs is its scripted
  `notice` layer (behavioral judgments). Suricata has no equivalent. That behavioral layer is
  precisely what **Cernity** adds on top of Suricata: stateful detectors, a findings lifecycle,
  correlation. So "Suricata + Cernity" occupies the same space as "Zeek + its notice scripts",
  and the benchmark measures whether it does so as well or better.
