# SIEM integrations

Cernity emits findings only; `findings-forwarder` delivers them to your SIEM. Pick
a sink with `CERNITY_SINK`, or a comma-list to fan out to several at once (each sink
is independent — one failing never blocks the others). Findings are delivered as
JSON where the SIEM accepts it, and as CEF over syslog.

```
CERNITY_SINK=devo                 # one SIEM (the common case)
CERNITY_SINK=devo,webhook         # fan out: Devo for the SOC + a webhook to chat/ticketing
```

Set the variables below in `.env`. All are also listed in `cernity.env.example`.

## file (default)
Writes JSONL to a volume — good for eval and piping into your own collector.
```
CERNITY_SINK=file
CERNITY_SINK_FILE=/out/findings.jsonl
```

## Elasticsearch / OpenSearch
Daily index via the `_bulk` API (same for both).
```
CERNITY_SINK=elasticsearch        # or: opensearch
ES_ENDPOINT=https://siem:9200
ES_USER=elastic
ES_PASSWORD=•••
ES_TLS_VERIFY=false               # for an internal / self-signed CA
ES_INDEX_PREFIX=ndr-findings
```

## Splunk (HEC)
```
CERNITY_SINK=splunk
SPLUNK_HEC_URL=https://splunk:8088/services/collector
SPLUNK_HEC_TOKEN=•••
SPLUNK_SOURCETYPE=cernity:finding
```

## Generic webhook
POSTs `{"findings": [...]}` — use for Slack, ticketing, or a SOAR (n8n / Shuffle / TheHive).
```
CERNITY_SINK=webhook
WEBHOOK_URL=https://example/hook
WEBHOOK_AUTH=Bearer •••           # optional Authorization header
```

## Syslog / CEF
CEF over syslog (TCP, optionally TLS) — reaches QRadar, ArcSight, and most on-prem SIEMs.
```
CERNITY_SINK=syslog
SYSLOG_HOST=siem
SYSLOG_PORT=514
SYSLOG_TLS=false
```

## Devo
Two transports. Payload is JSON by default (Devo is schema-on-read) or CEF.

**Syslog relay (mutual TLS)** — the native path; findings are tagged to a Devo table:
```
CERNITY_SINK=devo
DEVO_TRANSPORT=syslog
DEVO_RELAY=relay.devo
DEVO_PORT=443
DEVO_CERT=/certs/devo.crt
DEVO_KEY=/certs/devo.key
DEVO_CHAIN=/certs/chain.crt       # optional CA chain
DEVO_TAG=my.app.cernity.findings
DEVO_FORMAT=json                  # or: cef
```

**HTTP ingestion API** — token-based, no cert management:
```
CERNITY_SINK=devo
DEVO_TRANSPORT=http
DEVO_ENDPOINT=https://intake.devo/event
DEVO_TOKEN=•••
DEVO_TAG=my.app.cernity.findings
DEVO_FORMAT=json
```

## Adding another SIEM
Each sink is a small adapter in `services/findings-forwarder/adapters.py` exposing
`emit_batch(findings)`, registered in `_make()`. Follow the existing ones (each is
~30 lines) and the CEF helper in `cef.py` for syslog-family targets.
