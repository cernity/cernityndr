# Audit evidence

Scope: local commit `1cffad4cfa1def18eaf8212a9b2e9289dffc0a4e` plus pre-existing documentation changes. See [audit report](../cernity-independent-audit.md).

* `unit-tests.log`: aggregate service/shared/contracts test execution.
* `additional-tests.log`: benchmark, feeder and nested behavioral validation execution.
* `redis-contract-tests.log`: existing contract tests run against an isolated real Redis.
* `reproduce.py`: non-destructive component/configuration probes. Run `python3 docs/audit-evidence/reproduce.py` from the repository root. Requires the project's test dependencies, Docker Compose, and no live services.
* `reproduction-results.json`: results of that probe.
* `additional-probes.json`: JA3 object exception and suppressed finding schema error.
* `redis-window-probe.json`: real Redis retention after refreshing active counter/set keys.
* `quickstart-build.log`: default build/start failure.
* `demo-start.log`: demo startup failure. Broker stderr reported `unrecognised option '--check=false'`; the insecure entrypoint invokes `redpanda start` with an `rpk` option.
* `secure-start.log`: successful startup using temporary generated certificates and credential injected via Compose override.
* `quickstart-findings.jsonl`: beacon produced by replay before audit markers.
* `pipeline-findings.jsonl`: live sink, including duplicate controls and forged final marker.
* `finding-service.log`: final control and stalled signature/TI route observations.
* `topic-observations.json`: actual capture requests and successful enrichment result on the broker.
* `bus-security.json`: unauthenticated/authenticated Kafka connection and sensor final-topic write result.
* `bus-check.py`: live check used against the isolated audit broker. Reads audit credentials from `/tmp/cernity-audit/secrets`; these credentials are not included. It publishes one benign `audit-sensor-forged-final` marker, so do not point it at a production broker.
* `redpanda-image.json`: broker image digest used for execution.

The audit used a distinct `cernity-audit` Compose project. Existing unrelated containers were preserved. The temporary certificate setup ran a copy of `deploy/security/gen-bus-certs.sh` under `/tmp/cernity-audit`, then overrode only the Redpanda certificate mount and credential environment. No service logic was patched to obtain the successful beacon.

The live lifecycle probe published two copies each of three candidates with distinct IDs: a discovery control, `ids_signature`, and `threat_intel`. All used severity 9 and confidence 0.99. It then published an `ok` enrichment result for the signature. The control produced two final file rows; the confirmed-threat candidates produced capture requests. The service has no result-topic subscription, so the published success result cannot complete them.

For the Redis aging probe, a counter received 100 and a set received `old`, both with TTL 1. After 1.2 seconds the same keys received 1 and `new`; after another 1.2 seconds both original observations remained. RedisStore deliberately rounds the expiry up by one second; the total elapsed 2.4 seconds exceeds even the original rounded expiry. Whole-key renewal explains the result.

These probes establish specific defects and narrow successful behaviors. Synthetic benchmark reports and in-process load measurements are not evidence of production accuracy or distributed capacity. Audit-created containers and test volumes were removed after evidence collection; cached build images were retained.
