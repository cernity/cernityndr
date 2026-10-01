#!/bin/sh
# Sourced by entrypoint in BOTH bus postures, after the broker's admin API is up and
# BEFORE any producer/consumer connects. Provisions the suricata ingest topics as
# LogAppendTime so the normalizer / asset-service / file-observer — which reject any
# CreateTime record (they cannot derive an ingest instant from it) — consume cleanly
# from a fresh bootstrap.
#
# Posture-aware auth (same script, driven by CERNITY_INSECURE_BUS):
#   secure (default)        authenticate as the bootstrap admin superuser over the
#                           internal SASL listener (both listeners require SASL).
#   CERNITY_INSECURE_BUS=1   plaintext, unauthenticated internal listener (demo posture) —
#                           NO SASL flags. The insecure branch has no seeded principals.
#
# Race-free: each input topic is CREATED WITH message.timestamp.type=LogAppendTime in one
# call (no create-then-alter window during which a sensor could append a CreateTime record).
# The cluster default log_message_timestamp_type is set FIRST so any topic that is instead
# auto-created on first produce (auto_create_topics_enabled is on) also inherits LogAppendTime.
# Topics that already exist from a pre-flip CreateTime deploy are reconciled in place with an
# idempotent alter. Re-runnable on every boot; the sensor stays produce-only (topics are
# admin-provisioned, never created by the sensor principal).
#
# -----------------------------------------------------------------------------------------
# UPGRADING AN EXISTING DEPLOYMENT — the committed-offset backlog case (READ BEFORE UPGRADE)
# -----------------------------------------------------------------------------------------
# Re-running this script reconciles existing CreateTime topics to LogAppendTime, but that only
# fixes NEW records. An already-running `ndr-normalizer` consumer group has a COMMITTED OFFSET
# that takes precedence over auto_offset_reset=latest, so on restart it re-reads the pre-flip
# CreateTime backlog still sitting below its committed position and crash-loops on the
# LogAppendTime check (reproduced on a live cluster). auto_offset_reset only applies when the
# group has NO committed offset (a fresh group / fresh deploy) — it does NOT skip a backlog for
# an existing group. This script does NOT auto-seek an active group: seeking a live consumer is
# unsafe and would silently discard un-ingested data. The operator performs the migration
# explicitly, once, with the normalizer stopped:
#
#   1. Stop the normalizer:            docker compose stop normalizer
#   2. Wait until the group is Empty:  rpk group describe ndr-normalizer   # STATE = Empty
#   3. Seek past the CreateTime backlog (only the normalizer's input topics):
#        rpk group seek ndr-normalizer --to end \
#          --topics suricata.flow.v1,suricata.tls.v1,suricata.dns.v1,suricata.http.v1
#   4. Start the normalizer:           docker compose start normalizer
#
# After step 4 the group's committed offset is at the end, so it only reads freshly produced
# (now LogAppendTime) records. Do NOT weaken the normalizer's timestamp check to avoid this.
# -----------------------------------------------------------------------------------------
set -eu

ADMIN="${ADMIN:-127.0.0.1:9644}"     # local admin API (cluster config)
KAFKA="${KAFKA:-127.0.0.1:9092}"     # internal Kafka listener
TS_TYPE="LogAppendTime"

# Standard suricata ingest topics — the "Ingest" family in contracts/topics.md. Keep in sync
# with CANONICAL_TOPICS in contracts/test_contracts.py (test_provision_topics.py asserts the
# full set, not just the four the normalizer currently consumes; asset-service reads
# suricata.raw.v1, file-observer reads suricata.file.v1, and all must be LogAppendTime).
SURICATA_INPUT_TOPICS="suricata.raw.v1 suricata.flow.v1 suricata.dns.v1 suricata.tls.v1
suricata.http.v1 suricata.ssh.v1 suricata.windows.v1 suricata.file.v1
suricata.anomaly.v1 suricata.stats.v1 suricata.modbus.v1"

if [ "${CERNITY_INSECURE_BUS:-0}" = "1" ]; then
  # Demo posture: plaintext internal listener, no seeded principals, no SASL.
  topic_rpk() { rpk topic "$@" -X brokers="$KAFKA"; }
else
  # Secure posture: authenticate as the bootstrap admin superuser over the internal SASL
  # listener (authorization may already be enforced; admin is a superuser regardless).
  : "${ADMIN_USER:?ADMIN_USER required in secure mode (set by entrypoint)}"
  : "${CERNITY_BUS_ADMIN_PASSWORD:?CERNITY_BUS_ADMIN_PASSWORD required in secure mode}"
  topic_rpk() {
    rpk topic "$@" -X brokers="$KAFKA" \
      -X user="$ADMIN_USER" -X pass="$CERNITY_BUS_ADMIN_PASSWORD" -X sasl.mechanism=SCRAM-SHA-512
  }
fi

# 1) Cluster default BEFORE any topic is created, so an auto-created topic inherits
#    LogAppendTime instead of the Kafka default (CreateTime). Admin API needs no SASL.
rpk cluster config set log_message_timestamp_type="$TS_TYPE" -X admin.hosts="$ADMIN" >/dev/null

# 2) Create each input topic WITH the config atomically. If the topic already exists, create
#    is a no-op failure -> reconcile it in place with an idempotent alter (fixes a pre-flip
#    CreateTime topic). A create failure for any OTHER reason makes the alter fail too, and
#    set -eu aborts the bootstrap (fail closed) rather than leaving a CreateTime topic.
for t in $SURICATA_INPUT_TOPICS; do
  if topic_rpk create "$t" -c message.timestamp.type="$TS_TYPE" >/dev/null 2>&1; then
    echo "Cernity bus: created input topic $t ($TS_TYPE)" >&2
  else
    topic_rpk alter-config "$t" --set message.timestamp.type="$TS_TYPE" >/dev/null
    echo "Cernity bus: reconciled existing input topic $t -> $TS_TYPE" >&2
  fi
done
echo "Cernity bus: suricata ingest topics provisioned with message.timestamp.type=$TS_TYPE" >&2
