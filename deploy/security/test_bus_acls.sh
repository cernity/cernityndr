#!/usr/bin/env bash
# F02 acceptance: the produce-only sensor credential cannot forge findings, read
# ndr.* topics, or alter cluster config, while the trusted central principal runs the
# pipeline normally. Stands up a real Redpanda with the secure entrypoint and asserts
# the audit's own negative tests. Requires Docker. Run from the repo root:
#
#   ./deploy/security/test_bus_acls.sh
#
# NOTE: this is an integration test (pulls redpandadata/redpanda, ~1 min); it is not
# part of the fast unit gate (run-tests.sh).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMG="redpandadata/redpanda:latest"
C="cernity-bus-acl-test"
WORK="$(mktemp -d)"
trap 'docker rm -f "$C" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

command -v docker >/dev/null 2>&1 || { echo "SKIP: docker not available"; exit 0; }
docker info >/dev/null 2>&1 || { echo "SKIP: docker daemon not running"; exit 0; }

# Throwaway CA + broker cert (SAN covers the loopback advertised names).
cd "$WORK"
openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes -keyout ca.key -out ca.crt -subj "/CN=test CA" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout broker.key -out broker.csr -subj "/CN=127.0.0.1" 2>/dev/null
echo "subjectAltName = DNS:redpanda, DNS:localhost, IP:127.0.0.1" > broker.ext
openssl x509 -req -in broker.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out broker.crt -days 2 -sha256 -extfile broker.ext 2>/dev/null

docker rm -f "$C" >/dev/null 2>&1 || true
docker run -d --name "$C" --add-host redpanda:127.0.0.1 \
  -e CERNITY_ADVERTISE_HOST=127.0.0.1 \
  -e CERNITY_BUS_USER=cernity-sensor          -e CERNITY_BUS_PASSWORD=sensorpass \
  -e CERNITY_BUS_CENTRAL_USER=cernity-central -e CERNITY_BUS_CENTRAL_PASSWORD=centralpass \
  -e CERNITY_BUS_ADMIN_USER=cernity-admin     -e CERNITY_BUS_ADMIN_PASSWORD=adminpass \
  -v "$ROOT/deploy/central/redpanda/entrypoint.sh:/entrypoint.sh:ro" \
  -v "$ROOT/deploy/central/redpanda/redpanda.yaml.tmpl:/etc/redpanda/redpanda.yaml.tmpl:ro" \
  -v "$WORK:/certs:ro" \
  --entrypoint /entrypoint.sh "$IMG" >/dev/null

echo "waiting for authorization to be enforced..."
for _ in $(seq 1 60); do
  # Wait for the ENFORCED signal (printed AFTER kafka_enable_authorization is set), not
  # the earlier PRODUCE-ONLY line — otherwise the sensor checks race enforcement.
  docker logs "$C" 2>&1 | grep -q "authorization ENFORCED" && break
  docker ps -a --filter "name=$C" --format '{{.Status}}' | grep -qi exited && { echo "FAIL: broker exited"; docker logs "$C" 2>&1 | tail -20; exit 1; }
  sleep 2
done
CEN="-X brokers=redpanda:9092 -X user=cernity-central -X pass=centralpass -X sasl.mechanism=SCRAM-SHA-512"
SEN="-X brokers=127.0.0.1:19092 -X user=cernity-sensor -X pass=sensorpass -X sasl.mechanism=SCRAM-SHA-512 -X tls.enabled=true -X tls.ca=/certs/ca.crt"

# Pre-create the target topics as the central superuser, so WRITE authorization is tested
# on EXISTING topics rather than racing the auto-create path (which returns a different
# error for a denied create).
docker exec "$C" sh -c "rpk topic create ndr.finding.final.v1 suricata.flow.v1 $CEN" >/dev/null 2>&1 || true
# Enforcement on the data path lags the config-set by a beat. Canary-wait until a sensor
# forge on the (now existing) findings topic is actually denied, so no assertion races it.
for _ in $(seq 1 20); do
  c=$(printf '{"canary":1}\n' | docker exec -i "$C" sh -c "rpk topic produce ndr.finding.final.v1 $SEN" 2>&1 || true)
  case "$c" in *AUTHORIZATION_FAILED*) break;; esac
  sleep 2
done

pass=0; fail=0
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }
# Capture output into a var (|| true), then match with `case` — rpk exits non-zero on a
# denied produce, so a `... | grep && ok || bad` pipeline would be masked by pipefail.
run()  { docker exec "$C" sh -c "$1" 2>&1 || true; }
# NOTE the trailing newline: `rpk topic produce` reads newline-delimited records, so a
# record without one is never sent (zero produce, no auth check) — a silent false pass.
runi() { printf '%s\n' "$2" | docker exec -i "$C" sh -c "$1" 2>&1 || true; }
denied() { case "$1" in *AUTHORIZATION_FAILED*) return 0;; *) return 1;; esac; }
# Bounded consume: `rpk consume -n 1` blocks forever if the message never arrives (or a
# read is denied), and `timeout` is not portable — so run it in the background against a
# temp file, give it a few seconds, then kill it and return whatever it captured.
consume() { local out="$WORK/c.$$"; : >"$out"
  docker exec "$C" sh -c "$1" >"$out" 2>&1 & local p=$!
  sleep 8; kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; cat "$out"; }

# Central pipeline (internal SASL) must work: produce + consume ndr.* (topics pre-created above).
o=$(runi "rpk topic produce ndr.finding.final.v1 $CEN" '{"real":"f"}')
denied "$o" && bad "central produces ndr.finding.final.v1" || ok "central produces ndr.finding.final.v1"
o=$(consume "rpk topic consume ndr.finding.final.v1 -o start -n 1 $CEN")
case "$o" in *real*) ok "central consumes ndr.finding.final.v1 (pipeline round-trips)";; *) bad "central consumes ndr.finding.final.v1";; esac

# Sensor confinement (external SASL/TLS) — the audit's negative tests.
o=$(runi "rpk topic produce suricata.flow.v1 $SEN" '{"t":1}')
denied "$o" && bad "sensor blocked from suricata.flow.v1 (should be allowed)" || ok "sensor ALLOWED produce suricata.flow.v1"
o=$(runi "rpk topic produce ndr.finding.final.v1 $SEN" '{"x":1}')
denied "$o" && ok "sensor REFUSED forging ndr.finding.final.v1" || bad "sensor could forge ndr.finding.final.v1"
o=$(runi "rpk topic produce ndr.capture.request.v1 $SEN" '{"x":1}')
denied "$o" && ok "sensor REFUSED ndr.capture.request.v1" || bad "sensor could produce ndr.capture.request.v1"
o=$(run "rpk topic alter-config ndr.finding.final.v1 --set retention.ms=1000 $SEN")
denied "$o" && ok "sensor REFUSED altering topic config" || bad "sensor could alter topic config"
# rpk consume retries silently on a read denial, so assert via the broker authz log.
consume "rpk topic consume suricata.flow.v1 -n 1 -o start $SEN" >/dev/null
if docker logs "$C" 2>&1 | grep "cernity-sensor" | grep "suricata.flow.v1" | grep -q "read"; then
  ok "sensor REFUSED reading suricata.flow.v1 (produce-only)"; else bad "sensor read not refused"; fi

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
