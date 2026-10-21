#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="${1:-certs/mtls}"
mkdir -p "$CERT_DIR"
umask 077

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -days 1 -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
  -subj "/CN=Doorman Internal CA"

make_cert() {
  local name="$1"
  local san="$2"
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$CERT_DIR/$name.key" -out "$CERT_DIR/$name.csr" -subj "/CN=$name"
  openssl x509 -req -in "$CERT_DIR/$name.csr" -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" -CAcreateserial -days 1 -sha256 \
    -out "$CERT_DIR/$name.crt" \
    -extfile <(printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=%s\nsubjectAltName=%s\n' "$3" "$san")
  rm -f "$CERT_DIR/$name.csr"
}

make_cert proxy-client "DNS:proxy-client" "clientAuth"
make_cert backend-a "DNS:backend-a,DNS:localhost,IP:127.0.0.1" "serverAuth"
make_cert backend-b "DNS:backend-b,DNS:localhost,IP:127.0.0.1" "serverAuth"
rm -f "$CERT_DIR/ca.srl"

echo "Generated 24-hour internal CA, proxy client, and backend certificates in $CERT_DIR"
