#!/bin/bash
set -euo pipefail

CERT_DIR="/etc/nginx/ssl"
SERVER_IP="${SERVER_IP:-127.0.0.1}"
CERT_NAME="cguard-admin"

if [ -f "$CERT_DIR/${CERT_NAME}.crt" ] && [ -f "$CERT_DIR/${CERT_NAME}.key" ]; then
    echo "[SSL] C-Guard admin certificate exists. Skipping generation."
    exit 0
fi

echo "[SSL] Generating C-Guard admin self-signed certificate for ${SERVER_IP}"

mkdir -p "$CERT_DIR"

openssl req -x509 -nodes -days 365 \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/${CERT_NAME}.key" \
    -out "$CERT_DIR/${CERT_NAME}.crt" \
    -subj "/C=KR/ST=Chungbuk/L=Cheongju/O=C-Guard/OU=Admin/CN=cguard-admin.local" \
    -addext "subjectAltName=IP:${SERVER_IP},DNS:cguard-admin.local" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth"

chmod 600 "$CERT_DIR/${CERT_NAME}.key"
chmod 644 "$CERT_DIR/${CERT_NAME}.crt"

echo "[SSL] Generated $CERT_DIR/${CERT_NAME}.crt"
