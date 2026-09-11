#!/bin/sh
# Redpanda entrypoint that selects the SECURE (default) or INSECURE bus posture.
#
#   default                 external :19092 = SASL/SCRAM-SHA-512 + TLS (from redpanda.yaml.tmpl)
#   CERNITY_INSECURE_BUS=1   external :19092 = plaintext, unauthenticated (DEMO ONLY, warns)
#
# Requires (secure mode): /certs/{broker.crt,broker.key,ca.crt} mounted and
# CERNITY_BUS_USER + CERNITY_BUS_PASSWORD set (see deploy/security/gen-bus-certs.sh).
# POSIX sh + sed only (no bash/envsubst dependency in the redpanda image).
set -eu
HOST="${CERNITY_ADVERTISE_HOST:-127.0.0.1}"

if [ "${CERNITY_INSECURE_BUS:-0}" = "1" ]; then
  echo "############################################################################" >&2
  echo "# WARNING: CERNITY_INSECURE_BUS=1 - external bus listener :19092 is PLAINTEXT" >&2
  echo "# and UNAUTHENTICATED. Anyone who can reach it can read/inject telemetry." >&2
  echo "# Use only on a fully trusted/throwaway network. NOT for production." >&2
  echo "############################################################################" >&2
  # F09: use `rpk redpanda start` (not raw `redpanda start`) so the insecure fallback
  # takes the SAME startup path as the secure mode below — the raw-binary invocation
  # diverged from the secure path and was the audit's broken insecure fallback.
  exec rpk redpanda start --check=false --overprovisioned --smp=1 --memory=1G --reserve-memory=0M \
    --kafka-addr=internal://0.0.0.0:9092,external://0.0.0.0:19092 \
    --advertise-kafka-addr=internal://redpanda:9092,external://"${HOST}":19092
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
rpk redpanda start --check=false --overprovisioned --smp=1 --memory=1G --reserve-memory=0M &
RP=$!
i=0
until rpk cluster health -X admin.hosts="$ADMIN" >/dev/null 2>&1; do
  kill -0 "$RP" 2>/dev/null || { echo "redpanda exited before admin API came up" >&2; wait "$RP"; exit 1; }
  i=$((i + 1)); [ "$i" -gt 90 ] && { echo "timeout waiting for admin API" >&2; break; }
  sleep 1
done

# 1) Create the three principals via the (local) admin API.
for pair in "$ADMIN_USER:$CERNITY_BUS_ADMIN_PASSWORD:bootstrap superuser" \
            "$CENTRAL_USER:$CERNITY_BUS_CENTRAL_PASSWORD:central pipeline" \
            "$CERNITY_BUS_USER:$CERNITY_BUS_PASSWORD:produce-only sensor"; do
  u="${pair%%:*}"; rest="${pair#*:}"; p="${rest%%:*}"; label="${rest#*:}"
  rpk security user create "$u" -p "$p" --mechanism SCRAM-SHA-512 -X admin.hosts="$ADMIN" 2>/dev/null \
    && echo "Cernity bus: created $label user '$u'" >&2 \
    || echo "Cernity bus: $label user '$u' already exists" >&2
done

# 2) The sensor may ONLY produce telemetry: write/describe/create confined to the
#    ${SENSOR_PREFIX}* prefix — no read, no ndr.* topics, no cluster operations. The
#    ACL is written by authenticating as the admin superuser over the internal SASL
#    listener (authorization is still off, but the listener requires authentication).
SASL_ADMIN="-X user=$ADMIN_USER -X pass=$CERNITY_BUS_ADMIN_PASSWORD -X sasl.mechanism=SCRAM-SHA-512"
rpk security acl create --allow-principal "User:$CERNITY_BUS_USER" \
  --operation write --operation describe --operation create \
  --topic "$SENSOR_PREFIX" --resource-pattern-type prefixed \
  -X brokers="$KAFKA" $SASL_ADMIN >/dev/null
echo "Cernity bus: sensor '$CERNITY_BUS_USER' scoped PRODUCE-ONLY to ${SENSOR_PREFIX}* (F02)" >&2

# 3) Superusers = the central-only pipeline + bootstrap admin. The sensor is NEVER a
#    superuser (that was the audit's F02 hole). Central services run trusted on the
#    private docker net; their credential never leaves the central host.
rpk cluster config set superusers "['$ADMIN_USER','$CENTRAL_USER']" -X admin.hosts="$ADMIN" >/dev/null 2>&1 || true
# 4) Enforce ACLs. Until now everything was permitted; from here the sensor is
#    confined to its telemetry namespace and cannot forge findings or read ndr.*.
rpk cluster config set kafka_enable_authorization true -X admin.hosts="$ADMIN" >/dev/null 2>&1 || true
# Detectors/shippers rely on topics appearing on first produce (as with the stock
# flag-based start); the custom config path needs this set explicitly.
rpk cluster config set auto_create_topics_enabled true -X admin.hosts="$ADMIN" >/dev/null 2>&1 || true
echo "Cernity bus: authorization ENFORCED — sensor '$CERNITY_BUS_USER' confined to ${SENSOR_PREFIX}* (F02)" >&2
wait "$RP"
