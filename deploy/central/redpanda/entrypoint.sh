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
sed -e "s|\${CERNITY_ADVERTISE_HOST}|${HOST}|g" \
    -e "s|\${CERNITY_BUS_USER}|${CERNITY_BUS_USER}|g" \
    /etc/redpanda/redpanda.yaml.tmpl > /etc/redpanda/redpanda.yaml
echo "Cernity bus: SECURE external listener (SASL/SCRAM-SHA-512 + TLS) advertised at ${HOST}:19092" >&2
exec redpanda start --redpanda-cfg /etc/redpanda/redpanda.yaml
