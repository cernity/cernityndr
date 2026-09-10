#!/usr/bin/env bash
# Generate the internal CA + Redpanda broker server cert + a SCRAM-SHA-512 password
# for the SECURE external bus listener (:19092). Outputs to deploy/security/secrets/
# (gitignored). Bring-your-own alternative: drop your own ca.crt / broker.crt /
# broker.key into that dir and skip this script (see README.md).
#
#   CERNITY_ADVERTISE_HOST=192.168.1.10 ./deploy/security/gen-bus-certs.sh
#   ./deploy/security/gen-bus-certs.sh --force      # regenerate over existing
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)/secrets"
HOST="${CERNITY_ADVERTISE_HOST:-127.0.0.1}"
DAYS="${CERNITY_CERT_DAYS:-825}"
FORCE="${1:-}"

mkdir -p "$DIR"; cd "$DIR"
if [ -f ca.crt ] && [ "$FORCE" != "--force" ]; then
  echo "certs already present in $DIR (use --force to regenerate)"; exit 0
fi

# Internal CA
openssl req -x509 -newkey rsa:4096 -sha256 -days "$DAYS" -nodes \
  -keyout ca.key -out ca.crt -subj "/CN=Cernity Bus CA" 2>/dev/null

# Broker server cert (SAN covers the advertised host + the in-network name)
openssl req -newkey rsa:4096 -nodes -keyout broker.key -out broker.csr \
  -subj "/CN=$HOST" 2>/dev/null
if echo "$HOST" | grep -Eq '^[0-9]+(\.[0-9]+){3}$'; then
  echo "subjectAltName = DNS:redpanda, DNS:localhost, IP:127.0.0.1, IP:$HOST" > broker.ext
else
  echo "subjectAltName = DNS:$HOST, DNS:redpanda, DNS:localhost, IP:127.0.0.1" > broker.ext
fi
openssl x509 -req -in broker.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out broker.crt -days "$DAYS" -sha256 -extfile broker.ext 2>/dev/null
rm -f broker.csr broker.ext ca.srl

# SCRAM credential for the sensor->bus path
USER="${CERNITY_BUS_USER:-cernity-sensor}"
PASS="$(openssl rand -base64 24 | tr -d '/+=' | head -c 32)"
echo "$USER" > bus_user.txt
printf '%s' "$PASS" > bus_password.txt
chmod 600 ca.key broker.key bus_password.txt

cat <<MSG

Generated in $DIR :
  ca.crt / ca.key               internal CA (distribute ca.crt to sensors)
  broker.crt / broker.key       Redpanda server cert (SAN=$HOST)
  bus_user.txt / bus_password.txt   SCRAM-SHA-512 credential

On the CENTRAL host .env:
  CERNITY_BUS_USER=$USER
  CERNITY_BUS_PASSWORD=$PASS
On each REMOTE sensor (copy ca.crt over first):
  CERNITY_BUS_SASL=1
  CERNITY_BUS_USER=$USER
  CERNITY_BUS_PASSWORD=$PASS
  CERNITY_BUS_TLS_CA=/certs/ca.crt
MSG
