#!/bin/sh
# Redpanda entrypoint that selects the SECURE (default) or INSECURE bus posture.
#
#   default                 external :19092 = SASL/SCRAM-SHA-512 + TLS (from redpanda.yaml.tmpl)
#   CERNITY_INSECURE_BUS=1   external :19092 = plaintext, unauthenticated (DEMO ONLY, warns)
#
# Requires (secure mode): /certs/{broker.crt,broker.key,ca.crt} mounted and
# CERNITY_BUS_USER + CERNITY_BUS_PASSWORD set (see deploy/security/gen-bus-certs.sh).
# POSIX sh + sed only (no bash/envsubst dependency in the redpanda image).
#
# BOOTSTRAP CreateTime RACE — why the ordering below is what it is
# ----------------------------------------------------------------
# The normalizer/asset-service/file-observer/file-yara reject any record whose topic is
# CreateTime. A CreateTime record can only enter via a CreateTime TOPIC, and a topic is
# only born CreateTime if it is auto-created while the cluster default is CreateTime (a
# LogAppendTime topic stamps append-time over whatever the producer sent, so an existing
# LogAppendTime topic can never hold a CreateTime record). The race is closed in TWO places:
#   (a) AT BOOT — both `rpk redpanda start` invocations pass `--set redpanda.auto_create_
#       topics_enabled=false` AND `--set redpanda.log_message_timestamp_type=LogAppendTime`,
#       which seed cluster config BEFORE the Kafka API opens. This is the critical fix for the
#       insecure/demo posture: its plaintext :19092 is reachable the instant it opens, and the
#       `rpk redpanda start` dev path would otherwise bundle auto-create ON (image developer_mode
#       — it is NOT off by default here). With the LogAppendTime default already in force, even a
#       topic auto-created by a sensor connecting at startup is LogAppendTime, so no CreateTime
#       record can be born even before the first admin-API call.
#   (b) POST-START — provision-topics.sh re-asserts the default, creates every input topic
#       with LogAppendTime, and the entrypoint keeps auto-create OFF until provisioning is done
#       (explicit off->provision->on; also correct on a RESTART, where persisted cluster config
#       wins over the first-boot --set).
# A sensor that reaches the Kafka listener mid-bootstrap can at worst get "unknown topic" or an
# auto-created LogAppendTime topic — never a CreateTime one. This protects the EXTERNAL sensor
# at the broker level, which no compose marker can do.
# The readiness marker (/tmp/cernity-bus-ready) additionally gates dependent COMPOSE
# services (their healthcheck requires it), since `rpk cluster health` goes green before
# provisioning finishes. Both prongs are required; neither alone closes the race.
set -eu
HOST="${CERNITY_ADVERTISE_HOST:-127.0.0.1}"
READY_MARKER="/tmp/cernity-bus-ready"
rm -f "$READY_MARKER"   # clear a stale marker left by a prior run of this same container

if [ "${CERNITY_CAPTURE_ENABLED:-0}" = "1" ] && [ "${CERNITY_INSECURE_BUS:-0}" = "1" ]; then
  echo "forensics requires the secure bus" >&2
  exit 1
fi
if [ "${CERNITY_INSECURE_BUS:-0}" = "1" ]; then
  echo "############################################################################" >&2
  echo "# WARNING: CERNITY_INSECURE_BUS=1 - external bus listener :19092 is PLAINTEXT" >&2
  echo "# and UNAUTHENTICATED. Anyone who can reach it can read/inject telemetry." >&2
  echo "# Use only on a fully trusted/throwaway network. NOT for production." >&2
  echo "############################################################################" >&2
  # F09: use `rpk redpanda start` (not raw `redpanda start`) so the insecure fallback
  # takes the SAME startup path as the secure mode below — the raw-binary invocation
  # diverged from the secure path and was the audit's broken insecure fallback.
  # Do NOT `exec`: like the secure path we start the broker in the background, provision
  # the suricata input topics as LogAppendTime BEFORE enabling auto-create, then `wait`.
  # `exec`-ing here was the v1 defect — it returned before provisioning, so the demo/
  # first-run posture never got LogAppendTime and the normalizer crash-looped.
  ADMIN="127.0.0.1:9644"     # local admin API — docker-net-only, never published
  KAFKA="127.0.0.1:9092"     # internal (plaintext, unauthenticated) listener
  # Seed a SAFE cluster config AT BOOT (--set writes it into the config before the Kafka API
  # opens, so it is effective the instant :19092 accepts a connection). The plaintext external
  # listener is reachable immediately and the `rpk redpanda start` dev path would otherwise
  # bundle auto_create_topics_enabled=ON (the image's developer_mode), so a sensor connecting
  # at startup — before any admin-API config call — could birth a CreateTime topic. Both keys
  # close that window: auto-create is off, AND the default stamp is LogAppendTime so even a
  # topic auto-created in the window is LogAppendTime (a CreateTime record can never be born).
  rpk redpanda start --check=false --overprovisioned --smp=1 --memory=1G --reserve-memory=0M \
    --set redpanda.auto_create_topics_enabled=false \
    --set redpanda.log_message_timestamp_type=LogAppendTime \
    --kafka-addr=internal://0.0.0.0:9092,external://0.0.0.0:19092 \
    --advertise-kafka-addr=internal://redpanda:9092,external://"${HOST}":19092 &
  RP=$!
  trap 'kill "$RP" 2>/dev/null || true' EXIT
  trap 'exit 1' INT TERM
  i=0
  until rpk cluster health -X admin.hosts="$ADMIN" >/dev/null 2>&1; do
    kill -0 "$RP" 2>/dev/null || { echo "redpanda exited before admin API came up" >&2; wait "$RP"; exit 1; }
    i=$((i + 1)); [ "$i" -gt 90 ] && { echo "timeout waiting for admin API" >&2; break; }
    sleep 1
  done
  # Re-assert auto-create OFF over the admin API (idempotent). The boot-time --set above
  # already closed the startup window; this keeps the off->provision->on flow explicit and
  # correct on a RESTART too, where persisted cluster config (not the first-boot --set) wins.
  rpk cluster config set auto_create_topics_enabled false -X admin.hosts="$ADMIN" >/dev/null
  # Plaintext provisioning (provision-topics.sh detects CERNITY_INSECURE_BUS and drops SASL):
  # sets log_message_timestamp_type=LogAppendTime, then creates every input topic with it.
  . /provision-topics.sh
  # Safe now: default is LogAppendTime and every input topic exists as LogAppendTime, so any
  # topic auto-created on first produce (detectors/shippers rely on this) inherits it.
  rpk cluster config set auto_create_topics_enabled true -X admin.hosts="$ADMIN" >/dev/null
  : > "$READY_MARKER"   # dependent compose services gate on this (see healthcheck)
  echo "Cernity bus: provisioning complete, readiness marker written (insecure demo posture)" >&2
  # Block on the broker; exit (do NOT fall through into the secure path below) when it stops.
  wait "$RP" && exit 0 || exit "$?"
fi

# secure mode. Three principals, none shared with another's blast radius (F02):
#   * sensor  (distributed to every sensor)  — PRODUCE-ONLY on the telemetry prefix
#   * central (central host only)             — trusted pipeline; runs the detectors,
#                                               finding-service, forwarder (superuser)
#   * admin   (central host only)             — bootstrap/break-glass (superuser)
# A compromised sensor holds only the produce-only credential: it cannot forge
# ndr.finding.final.v1, read another tenant's topics, or alter cluster config.
: "${CERNITY_BUS_USER:?CERNITY_BUS_USER (produce-only sensor credential) required in secure mode (see deploy/security)}"
: "${CERNITY_BUS_PASSWORD:?CERNITY_BUS_PASSWORD required in secure mode (see deploy/security)}"
ADMIN_USER="${CERNITY_BUS_ADMIN_USER:-cernity-admin}"
: "${CERNITY_BUS_ADMIN_PASSWORD:?CERNITY_BUS_ADMIN_PASSWORD (central-only bootstrap superuser) required in secure mode (see deploy/security)}"
CENTRAL_USER="${CERNITY_BUS_CENTRAL_USER:-cernity-central}"
: "${CERNITY_BUS_CENTRAL_PASSWORD:?CERNITY_BUS_CENTRAL_PASSWORD (central pipeline principal) required in secure mode (see deploy/security)}"
SENSOR_PREFIX="${CERNITY_SENSOR_TOPIC_PREFIX:-suricata.}"   # telemetry namespace the sensor may produce to
sed "s|\${CERNITY_ADVERTISE_HOST}|${HOST}|g" \
    /etc/redpanda/redpanda.yaml.tmpl > /etc/redpanda/redpanda.yaml
echo "Cernity bus: SECURE listeners (internal SASL/plaintext, external SASL/TLS) advertised at ${HOST}:19092" >&2

# Start redpanda in the background so we can seed principals + ACLs once the admin API
# is up. Both listeners require SASL, so the ACL calls authenticate as the admin
# superuser over the internal listener (authorization is still OFF during seeding).
ADMIN="127.0.0.1:9644"     # local admin API (users, config) — docker-net-only, never published
KAFKA="127.0.0.1:9092"     # internal SASL listener
# Seed the same SAFE cluster config at boot as the insecure path. Both listeners require SASL
# and no sensor principal is seeded until after provisioning, so no producer can reach the
# Kafka API during the bootstrap window here — but seed it anyway (defense in depth, identical
# to the demo posture): auto-create off + LogAppendTime default effective before the API opens.
rpk redpanda start --check=false --overprovisioned --smp=1 --memory=1G --reserve-memory=0M \
  --set redpanda.auto_create_topics_enabled=false \
  --set redpanda.log_message_timestamp_type=LogAppendTime &
RP=$!
# Provisioning failure must stop the broker, not leave a permissive child alive.
trap 'kill "$RP" 2>/dev/null || true' EXIT
trap 'exit 1' INT TERM
i=0
until rpk cluster health -X admin.hosts="$ADMIN" >/dev/null 2>&1; do
  kill -0 "$RP" 2>/dev/null || { echo "redpanda exited before admin API came up" >&2; wait "$RP"; exit 1; }
  i=$((i + 1)); [ "$i" -gt 90 ] && { echo "timeout waiting for admin API" >&2; break; }
  sleep 1
done

create_bus_user() {   # <user> <password> <label>
  rpk security user create "$1" -p "$2" --mechanism SCRAM-SHA-512 -X admin.hosts="$ADMIN" 2>/dev/null \
    && echo "Cernity bus: created $3 user '$1'" >&2 \
    || echo "Cernity bus: $3 user '$1' already exists" >&2
}

# Re-assert auto-create OFF (idempotent; the boot-time --set already seeded it). Provisioning
# then runs BEFORE the sensor credential exists. The earliest a sensor can authenticate to
# :19092 is after its SCRAM user is seeded below — by then every input topic already exists as
# LogAppendTime, so the sensor can never append a CreateTime record. Explicit here so the
# off->provision->on flow is correct on a RESTART too (persisted config wins, not first-boot --set).
rpk cluster config set auto_create_topics_enabled false -X admin.hosts="$ADMIN" >/dev/null

# 1) Create the bootstrap admin FIRST — provision-topics.sh authenticates as it over the
#    internal SASL listener to create the input topics (authorization is still off).
create_bus_user "$ADMIN_USER" "$CERNITY_BUS_ADMIN_PASSWORD" "bootstrap superuser"

# 2) Provision the suricata input topics as LogAppendTime BEFORE the produce-capable sensor
#    principal exists. ADMIN/KAFKA/ADMIN_USER/CERNITY_BUS_ADMIN_PASSWORD are set above.
. /provision-topics.sh

# 3) Now seed the produce-capable principals. The sensor credential only becomes usable
#    here, after the topics already exist as LogAppendTime.
create_bus_user "$CENTRAL_USER" "$CERNITY_BUS_CENTRAL_PASSWORD" "central pipeline"
create_bus_user "$CERNITY_BUS_USER" "$CERNITY_BUS_PASSWORD" "produce-only sensor"

# 4) The sensor may ONLY produce telemetry: write/describe/create confined to the
#    ${SENSOR_PREFIX}* prefix — no read, no general ndr.* access, no cluster operations. The
#    ACL is written by authenticating as the admin superuser over the internal SASL
#    listener (authorization is still off, but the listener requires authentication).
SASL_ADMIN="-X user=$ADMIN_USER -X pass=$CERNITY_BUS_ADMIN_PASSWORD -X sasl.mechanism=SCRAM-SHA-512"
rpk security acl create --allow-principal "User:$CERNITY_BUS_USER" \
  --operation write --operation describe --operation create \
  --topic "$SENSOR_PREFIX" --resource-pattern-type prefixed \
  -X brokers="$KAFKA" $SASL_ADMIN >/dev/null
# U2: health is a separate mandatory-agent topic, not authority over ndr.*.
rpk security acl create --allow-principal "User:$CERNITY_BUS_USER" \
  --operation write --operation describe --operation create \
  --topic ndr.sensor.health.v1 --resource-pattern-type literal \
  -X brokers="$KAFKA" $SASL_ADMIN >/dev/null
echo "Cernity bus: sensor '$CERNITY_BUS_USER' scoped PRODUCE-ONLY to ${SENSOR_PREFIX}* (F02)" >&2

if [ "${CERNITY_CAPTURE_ENABLED:-0}" = "1" ]; then
  . /provision-capture.sh
fi

# 5) Superusers = the central-only pipeline + bootstrap admin. The sensor is NEVER a
#    superuser (that was the audit's F02 hole). Central services run trusted on the
#    private docker net; their credential never leaves the central host.
rpk cluster config set superusers "['$ADMIN_USER','$CENTRAL_USER']" -X admin.hosts="$ADMIN" >/dev/null
# 6) Enforce ACLs. Until now everything was permitted; from here the sensor is
#    confined to its telemetry namespace and cannot forge findings or read ndr.*.
rpk cluster config set kafka_enable_authorization true -X admin.hosts="$ADMIN" >/dev/null
# 7) Re-enable auto-create ONLY now: the LogAppendTime default is set and every input topic
#    exists as LogAppendTime, so a topic auto-created on first produce (detectors/shippers
#    rely on this, as with the stock flag-based start) inherits LogAppendTime, not CreateTime.
rpk cluster config set auto_create_topics_enabled true -X admin.hosts="$ADMIN" >/dev/null 2>&1 || true
echo "Cernity bus: authorization ENFORCED — sensor '$CERNITY_BUS_USER' confined to ${SENSOR_PREFIX}* (F02)" >&2

# 8) Readiness marker: dependent compose services gate on this (their healthcheck requires
#    it), so nothing consumes/produces before provisioning is done. `rpk cluster health`
#    alone goes green earlier and does NOT close that race.
: > "$READY_MARKER"
echo "Cernity bus: provisioning complete, readiness marker written (secure posture)" >&2
wait "$RP"
