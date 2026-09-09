# Finding enrichment — giving the analyst more context

A raw Cernity finding tells you *what* happened ("this host looks like C2") and *who*
was involved (the IPs, domains, fingerprints). **Enrichment** adds the context an analyst
needs to triage it fast: where in the world that IP is, who owns the network, how old the
domain is, whether a fingerprint matches a known tool, and a flow key to pivot into other
tools. All of it is attached to the finding before it reaches your SIEM.

Enrichment happens in **finding-service**, in two tiers:

- **Tier 1 — offline, zero external dependencies.** Runs on every finding once the local
  databases are mounted. Nothing leaves your network.
- **Tier 2 — opt-in adapters.** Off by default. Each is enabled by a config toggle or an
  API key. Some make outbound lookups (RDAP, GreyNoise); all are cached and best-effort —
  a slow or failed lookup never blocks or drops a finding.

Everything is configured through `cernity.env` (copied from `cernity.env.example`). **No
image rebuild is needed** — set the variables, restart finding-service, done.

---

## What gets added to a finding

Enrichment adds these top-level fields to the finding JSON your SIEM receives:

```jsonc
{
  "finding_id": "beacon-1234-...",
  "category": "c2",
  "entities": [ ... ],
  "community_id": "1:LQU9qZlK+B5F3KDmev6m5PMibrg=",   // Tier 1: cross-tool flow key
  "geo": {                                             // Tier 1: per external IP
    "203.0.113.9": { "country": "NL", "asn": 14061, "as_org": "DigitalOcean" }
  },
  "intel": {                                           // Tier 2: only enabled adapters appear
    "rdns":        { "203.0.113.9": "vps-abc.example.net" },
    "domains":     { "brand-new.evil.com": { "age_days": 3, "nrd": true } },
    "fingerprints":{ "t13d1516h2_...": "Cobalt Strike (default)" },
    "reputation":  { "203.0.113.9": "malicious" }
  }
}
```

---

## Tier 1 — GeoIP + ASN + community ID (offline)

### GeoIP + ASN

Every external (globally-routable) IP in a finding gets a `geo` block: country, ASN
number, and the AS organization. Internal/RFC1918 addresses are skipped.

This uses **MaxMind GeoLite2** databases, which are free but require a (free) account:

1. **Create a free MaxMind account:** <https://www.maxmind.com/en/geolite2/signup>.
2. In the account portal, **generate a license key** (Account → Manage License Keys).
3. **Download** `GeoLite2-Country.mmdb` (or `GeoLite2-City.mmdb`) and `GeoLite2-ASN.mmdb`.
   The download endpoint issues a 302 redirect, so **`curl` needs `-L`** (without it you
   get a 0-byte file):

   ```bash
   KEY=your-license-key
   for ed in GeoLite2-Country GeoLite2-ASN; do
     curl -sL "https://download.maxmind.com/app/geoip_download?edition_id=$ed&license_key=$KEY&suffix=tar.gz" \
       | tar xz --strip-components=1 --wildcards '*/'"$ed"'.mmdb'
   done
   ```
   Or automate refresh with MaxMind's official
   [`geoipupdate`](https://github.com/maxmind/geoipupdate) tool using your key.
4. **Mount them** into the finding-service container and point the env vars at them:

   ```yaml
   # in your finding-service service definition (compose overlay or values)
   volumes:
     - /srv/geoip:/geoip:ro
   ```
   ```bash
   # cernity.env
   GEOIP_DB=/geoip/GeoLite2-Country.mmdb
   GEOIP_ASN_DB=/geoip/GeoLite2-ASN.mmdb
   ```
5. Restart finding-service. On startup it logs `geoip=geo+asn` (or `geoip=off` if the DBs
   weren't found). That's it — no key lives in Cernity, only the downloaded DB files.

> MaxMind's license permits this use, but you accept their GeoLite2 EULA when you sign up.
> If you can't use MaxMind, any `.mmdb` in the same format works (e.g. DB-IP's free files).

### Community ID (flow pivot key)

[Community ID](https://github.com/corelight/community-id-spec) is a standard hash of a
flow's 5-tuple that Suricata, Zeek, and Arkime all compute the same way — so you can take
the `community_id` on a Cernity finding and search for the exact same flow in any of them.

**Enable it in Suricata** (it's the only step; Cernity carries it through automatically):

```yaml
# suricata.yaml
outputs:
  - eve-log:
      community-id: true
      community-id-seed: 0        # keep 0 across all sensors so hashes match
```

Cernity surfaces it on per-flow findings (e.g. TLS fingerprint / certificate anomalies).
See `docs/suricata-config.md` for the full Suricata setup.

---

## Tier 2 — opt-in enrichment adapters

All of these are **off until you turn them on**. Enable only what you want.

### Reverse DNS — `INTEL_RDNS`

PTR lookup on external IPs via the resolver the container already uses. No account, no key.

```bash
INTEL_RDNS=1
```

The only cost is a DNS query per new IP (cached for an hour). If your finding-service
host has no outbound DNS, leave it off.

### Domain age / newly-registered-domain — `INTEL_RDAP`

Looks up a domain's registration date via **RDAP** (the modern, free, keyless successor to
WHOIS) and flags domains younger than `INTEL_NRD_DAYS` as `nrd: true`. Freshly-registered
domains are one of the strongest phishing/C2 signals there is.

```bash
INTEL_RDAP=1
INTEL_NRD_DAYS=30        # tune to taste; 30 is a common threshold
```

No sign-up. It queries the public `rdap.org` redirector, which routes to the right
registry. Results are cached 24h (registration dates don't change). Some ccTLDs don't
expose RDAP registration events — those simply return no age, which is fine.

### JA3/JA4 → known-tool naming — `INTEL_FP_MAP`

Turns a raw fingerprint into a name ("Cobalt Strike", "Sliver", "Chrome 120") using a
JSON map **you supply**. Cernity ships an empty map on purpose — we don't hard-code
fingerprint→malware claims we can't keep current. Populate it from a source you trust.

**Format** — a flat JSON object of `fingerprint: label`:

```json
{
  "t13d1516h2_8daaf6152771_02713d6af862": "Cobalt Strike (default profile)",
  "51c64c77e60f3980eea90869b68c58a8": "Empire agent"
}
```

Point at your file and mount it:

```bash
INTEL_FP_MAP=/intel/fingerprints.json
```

**Where to get fingerprints:** the [abuse.ch JA3 fingerprint blocklist](https://sslbl.abuse.ch/ja3-fingerprints/)
(which Cernity's `threat-intel` service already consumes for *matching*) lists malicious
JA3s with malware names — a good seed. For JA4, FoxIO maintains a
[JA4+ database](https://ja4db.com/). Keep the file updated on whatever cadence suits you;
Cernity reloads it on restart.

### IP reputation — `GREYNOISE_API_KEY` (example adapter)

Tells you whether an external IP is internet-background-noise using
[GreyNoise](https://www.greynoise.io/) — great for cutting mass scanners out of your
triage queue. Returns `noise` (seen scanning) and `riot` (known benign service) always,
plus `classification` (`benign`/`malicious`/`unknown`), `name` (e.g. `Shodan.io`), and
`last_seen` when GreyNoise has observed the IP.

1. **Sign up** for a free GreyNoise Community account: <https://viz.greynoise.io/signup>.
2. **Copy your API key** from the account page.
3. Set it (store it in Vault / your secret manager, not in git):

   ```bash
   GREYNOISE_API_KEY=your-key-here
   ```

The GreyNoise Community endpoint is free with generous limits.

### IP reputation — `VIRUSTOTAL_API_KEY`

Attaches VirusTotal's last-analysis stats (`malicious` / `suspicious` / `harmless` vendor
counts) for an external IP — a quick "how many engines flag this?" read.

1. **Sign up** for a free VirusTotal account: <https://www.virustotal.com/gui/join-us>.
2. **Copy your API key** (Profile → API key).
3. Set it (store it in Vault / your secret manager, not in git):

   ```bash
   VIRUSTOTAL_API_KEY=your-key-here
   ```

The free tier is rate-limited (**4 requests/min, 500/day**), so the built-in 1h per-IP
cache matters — enrichment only queries each IP once an hour. GreyNoise and VirusTotal are
independent; enable either, both, or neither.

> **Privacy — reputation lookups are external-only.** GreyNoise and VirusTotal are only
> ever queried for *globally-routable* IPs. Internal/RFC1918 addresses in a finding are
> never sent to a third-party reputation service — that would be pointless and would leak
> your internal addressing. (Reverse DNS still runs for internal IPs, since it uses your
> own resolver and stays on your network.)

**Adding another reputation source** (AlienVault OTX, AbuseIPDB, …) is the same shape: copy
`virustotal()` in `services/finding-service/intel.py`, change the URL, header, and the field
you read, gate it on its own key variable, and add it to `enrich()`.

### Timeouts

`INTEL_HTTP_TIMEOUT` (default 3s) bounds every online lookup. If a service is slow, the
lookup is skipped and the finding still ships with whatever else succeeded.

---

## Cost / privacy summary

| Adapter | Sign-up | API key | Outbound traffic | Default |
|---|---|---|---|---|
| GeoIP + ASN | MaxMind (free) | key to *download DBs* only | none at runtime | on if DBs mounted |
| Community ID | none | none | none | on if Suricata sends it |
| Reverse DNS | none | none | DNS PTR per IP | off |
| Domain age / NRD | none | none | RDAP query per domain | off |
| Fingerprint naming | none | none | none (local file) | off (empty map) |
| GreyNoise reputation | GreyNoise (free) | yes | HTTPS per IP | off |
| VirusTotal reputation | VirusTotal (free) | yes | HTTPS per IP | off |

Turn on only what fits your privacy posture. For a fully-offline deployment, use Tier 1
(GeoIP + ASN + community ID) and the fingerprint map — none of those leave your network.
