#!/bin/bash
# Generate a local CA and one server cert shared by all Vault nodes (idempotent).
set -euo pipefail

TLS_DIR="${1:-.tmp/vault/tls}"
NODES="${VAULT_NODE_NAMES:-vault-primary vault-dr}"

if [[ -s "${TLS_DIR}/vault-cert.pem" && -s "${TLS_DIR}/vault-ca.pem" ]]; then
  echo "TLS material already present in ${TLS_DIR}"
  exit 0
fi

mkdir -p "$TLS_DIR"
umask 077

san="DNS:localhost,IP:127.0.0.1"
for node in $NODES; do
  san="${san},DNS:${node}"
done

openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout "${TLS_DIR}/vault-ca-key.pem" -out "${TLS_DIR}/vault-ca.pem" \
  -subj "/CN=vault-ops local CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

openssl req -newkey rsa:2048 -nodes \
  -keyout "${TLS_DIR}/vault-key.pem" -out "${TLS_DIR}/vault.csr" \
  -subj "/CN=vault" 2>/dev/null

openssl x509 -req -in "${TLS_DIR}/vault.csr" -days 365 \
  -CA "${TLS_DIR}/vault-ca.pem" -CAkey "${TLS_DIR}/vault-ca-key.pem" -CAcreateserial \
  -out "${TLS_DIR}/vault-cert.pem" \
  -extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n' "$san") 2>/dev/null

rm -f "${TLS_DIR}/vault.csr" "${TLS_DIR}/vault-ca.srl"
# Readable by the container's vault user; the key stays inside .tmp (gitignored).
chmod 644 "${TLS_DIR}/vault-ca.pem" "${TLS_DIR}/vault-cert.pem" "${TLS_DIR}/vault-key.pem"
echo "Generated CA and server cert (${san}) in ${TLS_DIR}"
