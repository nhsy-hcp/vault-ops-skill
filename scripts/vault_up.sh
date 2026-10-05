#!/bin/bash
# Start a Vault Enterprise dev server with TLS in a container (idempotent).
set -euo pipefail

CONTAINER_CLI="${CONTAINER_CLI:-docker}"
VAULT_IMAGE="${VAULT_IMAGE:?VAULT_IMAGE must be set in .env}"
VAULT_HOST_IP="${VAULT_HOST_IP:-127.0.0.1}"
VAULT_HOST_PORT="${VAULT_HOST_PORT:-8210}"
NAME="${VAULT_CONTAINER_NAME:-vault-primary}"
# Shared network so a future DR secondary can reach this node's cluster port (8201) by name.
NETWORK="${VAULT_NETWORK:-vault-ops}"
STATE_DIR="$(pwd)/.tmp/vault/${NAME}"
: "${VAULT_LICENSE:?VAULT_LICENSE must be set in .env}"

mkdir -p "${STATE_DIR}/logs" "${STATE_DIR}/tls"

if [[ "$("$CONTAINER_CLI" inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null || true)" == "true" ]]; then
  echo "Vault container ${NAME} already running"
else
  "$CONTAINER_CLI" rm -f "$NAME" >/dev/null 2>&1 || true
  "$CONTAINER_CLI" network exists "$NETWORK" 2>/dev/null || "$CONTAINER_CLI" network create "$NETWORK" >/dev/null
  "$CONTAINER_CLI" run -d --name "$NAME" --hostname "$NAME" --network "$NETWORK" \
    -p "${VAULT_HOST_IP}:${VAULT_HOST_PORT}:8200" \
    --cap-add IPC_LOCK \
    -e VAULT_LICENSE \
    -v "${STATE_DIR}/logs:/vault/logs" \
    -v "${STATE_DIR}/tls:/vault/tls" \
    "$VAULT_IMAGE" server -dev -dev-tls \
    -dev-root-token-id=root \
    -dev-listen-address=0.0.0.0:8200 \
    -dev-tls-cert-dir=/vault/tls \
    -dev-tls-san="${VAULT_HOST_IP}" \
    -dev-tls-san="${NAME}" \
    -log-file=/vault/logs/vault.log >/dev/null
  echo "Started ${NAME} (${VAULT_IMAGE})"
fi

echo -n "Waiting for ${VAULT_ADDR}"
for _ in $(seq 1 30); do
  if curl -sk "${VAULT_ADDR}/v1/sys/health" | jq -e '.initialized and (.sealed | not)' >/dev/null 2>&1; then
    echo " ready"
    curl -sk "${VAULT_ADDR}/v1/sys/health" | jq -c '{version, cluster_name, sealed}'
    exit 0
  fi
  echo -n "."
  sleep 1
done
echo " timed out; see ${STATE_DIR}/logs/vault.log or: ${CONTAINER_CLI} logs ${NAME}" >&2
exit 1
