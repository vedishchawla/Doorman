#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -f "$CERT_DIR/server.crt" ] && [ -f "$CERT_DIR/server.key" ]; then
    echo "Certs already exist in $CERT_DIR, skipping generation."
    exit 0
fi

openssl req -x509 -nodes -days 365 \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "Generated self-signed TLS certs in $CERT_DIR"
