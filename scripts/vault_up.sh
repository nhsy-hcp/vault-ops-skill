#!/bin/bash
# Start one Vault Enterprise node (raft storage, TLS) in a container; init, unseal and
# create a token with id "root" on first start. Idempotent.
#   usage: scripts/vault_up.sh [node-name] [host-port]
set -euo pipefail

NAME="${1:-${VAULT_CONTAINER_NAME:-vault-primary}}"
HOST_PORT="${2:-${VAULT_HOST_PORT:-8210}}"
PRIMARY_NAME="${VAULT_CONTAINER_NAME:-vault-primary}"
CONTAINER_CLI="${CONTAINER_CLI:-docker}"
VAULT_IMAGE="${VAULT_IMAGE:?VAULT_IMAGE must be set in .env}"
VAULT_HOST_IP="${VAULT_HOST_IP:-127.0.0.1}"
NETWORK="${VAULT_NETWORK:-vault-ops}"
ROOT_DIR="$(pwd)/.tmp/vault"
NODE_DIR="${ROOT_DIR}/${NAME}"
TLS_DIR="${ROOT_DIR}/tls"
: "${VAULT_LICENSE:?VAULT_LICENSE must be set in .env}"

export VAULT_ADDR="https://${VAULT_HOST_IP}:${HOST_PORT}"
export VAULT_CACERT="${TLS_DIR}/vault-ca.pem"
unset VAULT_SKIP_VERIFY VAULT_NAMESPACE

scripts/gen_tls.sh "$TLS_DIR"
mkdir -p "${NODE_DIR}/config" "${NODE_DIR}/data" "${NODE_DIR}/logs"

cat >"${NODE_DIR}/config/vault.hcl" <<HCL
ui            = true
disable_mlock = true
api_addr      = "https://${NAME}:8200"
cluster_addr  = "https://${NAME}:8201"
log_file      = "/vault/logs/vault.log"

storage "raft" {
  path    = "/vault/file"
  node_id = "${NAME}"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file   = "/vault/tls/vault-cert.pem"
  tls_key_file    = "/vault/tls/vault-key.pem"
}
HCL

if [[ "$("$CONTAINER_CLI" inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null || true)" == "true" ]]; then
  echo "${NAME}: container already running"
else
  "$CONTAINER_CLI" rm -f "$NAME" >/dev/null 2>&1 || true
  "$CONTAINER_CLI" network exists "$NETWORK" 2>/dev/null || "$CONTAINER_CLI" network create "$NETWORK" >/dev/null
  "$CONTAINER_CLI" run -d --name "$NAME" --hostname "$NAME" --network "$NETWORK" \
    -p "${VAULT_HOST_IP}:${HOST_PORT}:8200" \
    --cap-add IPC_LOCK \
    -e VAULT_LICENSE \
    -v "${NODE_DIR}/config:/vault/config" \
    -v "${NODE_DIR}/data:/vault/file" \
    -v "${NODE_DIR}/logs:/vault/logs" \
    -v "${TLS_DIR}:/vault/tls:ro" \
    "$VAULT_IMAGE" server >/dev/null
  echo "${NAME}: started (${VAULT_IMAGE}) on ${VAULT_ADDR}"
fi

health() {
  curl -s --cacert "$VAULT_CACERT" \
    "${VAULT_ADDR}/v1/sys/health?uninitcode=200&sealedcode=200&standbycode=200&drsecondarycode=200&perfstandbyok=true"
}

echo -n "${NAME}: waiting for API"
for _ in $(seq 1 30); do
  if health | jq -e '.initialized != null' >/dev/null 2>&1; then break; fi
  echo -n "."
  sleep 1
done
echo

if [[ "$(health | jq -r .initialized)" == "false" ]]; then
  echo "${NAME}: initialising (1 key share)"
  (umask 077 && vault operator init -key-shares=1 -key-threshold=1 -format=json >"${NODE_DIR}/init.json")
fi

if [[ "$(health | jq -r .sealed)" == "true" ]]; then
  # A DR secondary takes over the primary's unseal keys once activated, so try both.
  for keyfile in "${NODE_DIR}/init.json" "${ROOT_DIR}/${PRIMARY_NAME}/init.json"; do
    [[ -s "$keyfile" ]] || continue
    vault operator unseal "$(jq -r '.unseal_keys_b64[0]' "$keyfile")" >/dev/null 2>&1 || true
    [[ "$(health | jq -r .sealed)" == "false" ]] && break
  done
fi

echo -n "${NAME}: waiting for active node"
for _ in $(seq 1 30); do
  state="$(health)"
  if jq -e '(.sealed | not) and ((.standby | not) or .replication_dr_mode == "secondary")' >/dev/null 2>&1 <<<"$state"; then
    break
  fi
  echo -n "."
  sleep 1
done
echo

dr_mode="$(health | jq -r .replication_dr_mode)"
if [[ "$dr_mode" != "secondary" ]]; then
  # Keep VAULT_TOKEN=root working like dev mode: create a root-policy token with id "root".
  if ! VAULT_TOKEN=root vault token lookup >/dev/null 2>&1; then
    VAULT_TOKEN="$(jq -r .root_token "${NODE_DIR}/init.json")" \
      vault token create -id=root -policy=root -orphan -display-name=dev-root >/dev/null 2>&1  # custom-id SHA1 warning is expected in dev
    echo "${NAME}: created token id 'root'"
  fi
fi

health | jq -c '{node: "'"${NAME}"'", version, sealed, standby, replication_dr_mode, cluster_name}'
