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
  exec redpanda start --overprovisioned --smp=1 --memory=1G --reserve-memory=0M \
    --node-id=0 --check=false \
    --kafka-addr=internal://0.0.0.0:9092,external://0.0.0.0:19092 \
    --advertise-kafka-addr=internal://redpanda:9092,external://"${HOST}":19092
fi

# secure mode
: "${CERNITY_BUS_USER:?CERNITY_BUS_USER required in secure mode (see deploy/security)}"
: "${CERNITY_BUS_PASSWORD:?CERNITY_BUS_PASSWORD required in secure mode (see deploy/security)}"
sed "s|\${CERNITY_ADVERTISE_HOST}|${HOST}|g" \
    /etc/redpanda/redpanda.yaml.tmpl > /etc/redpanda/redpanda.yaml
echo "Cernity bus: SECURE external listener (SASL/SCRAM-SHA-512 + TLS) advertised at ${HOST}:19092" >&2

# Start redpanda in the background so we can seed the SCRAM superuser once the admin
# API is up (superusers is a CLUSTER config, and the SCRAM user must exist for the
# external SASL listener to authenticate the sensor).
ADMIN="127.0.0.1:9644"
rpk redpanda start --check=false --overprovisioned --smp=1 --memory=1G --reserve-memory=0M &
RP=$!
i=0
until rpk cluster health -X admin.hosts="$ADMIN" >/dev/null 2>&1; do
  kill -0 "$RP" 2>/dev/null || { echo "redpanda exited before admin API came up" >&2; wait "$RP"; exit 1; }
  i=$((i + 1)); [ "$i" -gt 90 ] && { echo "timeout waiting for admin API" >&2; break; }
  sleep 1
done
rpk security user create "$CERNITY_BUS_USER" -p "$CERNITY_BUS_PASSWORD" \
  --mechanism SCRAM-SHA-512 -X admin.hosts="$ADMIN" 2>/dev/null \
  && echo "Cernity bus: created SCRAM user '$CERNITY_BUS_USER'" >&2 \
  || echo "Cernity bus: SCRAM user '$CERNITY_BUS_USER' already exists" >&2
rpk cluster config set superusers "['$CERNITY_BUS_USER']" -X admin.hosts="$ADMIN" >/dev/null 2>&1 || true
# Detectors/shippers rely on topics appearing on first produce (as with the stock
# flag-based start); the custom config path needs this set explicitly.
rpk cluster config set auto_create_topics_enabled true -X admin.hosts="$ADMIN" >/dev/null 2>&1 || true
wait "$RP"
