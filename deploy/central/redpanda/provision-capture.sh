#!/bin/sh
# Sourced by entrypoint after admin bootstrap; same script is exercised with a fake
# rpk by the offline gate. Never grants topic creation or cluster permissions.
set -eu
: "${CERNITY_BUS_CAPTURE_PASSWORD:?capture password required by forensics overlay}"
CAPTURE_USER="${CERNITY_BUS_CAPTURE_USER:-cernity-capture}"
CAPTURE_SENSOR="${NDR_SENSOR:-sensor-1}"
for identifier in "$CAPTURE_USER" "$CAPTURE_SENSOR"; do
  case "$identifier" in ''|*[!a-zA-Z0-9._-]*) echo "invalid capture identifier" >&2; exit 1;; esac
done
for privileged in "$ADMIN_USER" "$CENTRAL_USER" "$CERNITY_BUS_USER"; do
  [ "$CAPTURE_USER" != "$privileged" ] || { echo "capture principal must be distinct" >&2; exit 1; }
done
rpk security user create "$CAPTURE_USER" -p "$CERNITY_BUS_CAPTURE_PASSWORD" \
  --mechanism SCRAM-SHA-512 -X admin.hosts="$ADMIN" >/dev/null 2>&1 || \
  rpk security user update "$CAPTURE_USER" --new-password "$CERNITY_BUS_CAPTURE_PASSWORD" \
    --mechanism SCRAM-SHA-512 -X admin.hosts="$ADMIN" >/dev/null
capture_admin() {
  rpk "$@" -X brokers="$KAFKA" -X user="$ADMIN_USER" \
    -X pass="$CERNITY_BUS_ADMIN_PASSWORD" -X sasl.mechanism=SCRAM-SHA-512
}
# Reconcile instead of accumulating stale prefix/wildcard grants on restart.
# No resource filter means all ACLs for this exact dedicated principal.
capture_admin security acl delete --allow-principal "User:$CAPTURE_USER" \
  --deny-principal "User:$CAPTURE_USER" --no-confirm >/dev/null
capture_acl() {
  resource="$1"; name="$2"; shift 2
  capture_admin security acl create --allow-principal "User:$CAPTURE_USER" \
    --resource-pattern-type literal "--$resource" "$name" "$@" >/dev/null
}
capture_acl topic ndr.capture.request.v1 --operation describe
capture_acl topic ndr.capture.arm.v1 --operation read --operation describe
capture_acl topic ndr.capture.status.v1 --operation write --operation describe
capture_acl topic ndr.capture.request.v2 --operation read --operation describe
capture_acl group "ndr-capture-agent-$CAPTURE_SENSOR" --operation read
# Administrative topic creation avoids granting Create to a sensor. Existing
# topics are left intact; describe failures fail bootstrap instead of being hidden.
for topic in ndr.capture.request.v1 ndr.capture.arm.v1 ndr.capture.status.v1 ndr.capture.request.v2; do
  capture_admin topic describe "$topic" >/dev/null 2>&1 || capture_admin topic create "$topic" >/dev/null
done
