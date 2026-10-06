#!/bin/bash
# Run the CE smoke tests (tests/test_ce.py) against a throwaway Community `vault server -dev`
# from compose.ce.yaml. Community edition: no namespaces, Sentinel, license, Raft or
# snapshots. In memory, no license needed; the container is removed on exit. Root is used
# only for setup and, after the first pass, to seal the server for the sealed-node pass.
set -euo pipefail

PORT="${CE_PORT:-8230}"
ROOT_TOKEN="${CE_ROOT_TOKEN:-vault-ops-ce-root}"
POLICY_DIR="skills/vault-ops/policies"
CONTAINER_CLI="${CONTAINER_CLI:-docker}"
COMPOSE=("$CONTAINER_CLI" compose -f compose.ce.yaml)
export CE_PORT="$PORT" CE_ROOT_TOKEN="$ROOT_TOKEN"

if curl -s -o /dev/null "http://127.0.0.1:${PORT}/v1/sys/health"; then
  echo "error: port ${PORT} is already in use (set CE_PORT)" >&2
  exit 1
fi

trap '"${COMPOSE[@]}" down >/dev/null 2>&1 || true' EXIT
"${COMPOSE[@]}" up -d --wait vault-ce
if curl -s "http://127.0.0.1:${PORT}/v1/sys/health" | jq -r .version | grep -q "+ent"; then
  echo "error: ${VAULT_CE_IMAGE:-the CE image} is Enterprise; test:ce needs a Community image" >&2
  exit 1
fi

export VAULT_ADDR="http://127.0.0.1:${PORT}"
unset VAULT_CACERT VAULT_NAMESPACE
audit_token="$(
  export VAULT_TOKEN="$ROOT_TOKEN"
  for policy in vault-ops-readonly vault-ops-policy-reader vault-ops-sentinel-reader; do
    vault policy write "$policy" "${POLICY_DIR}/${policy}.hcl" >/dev/null
  done
  # Just enough configuration to trip a few rules (VT-MOUNT-006, VT-POL-001).
  vault secrets enable -path=kv1 -version=1 kv >/dev/null
  vault policy write admin - >/dev/null <<<'path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }'
  vault token create -policy=vault-ops-readonly -policy=vault-ops-policy-reader -policy=vault-ops-sentinel-reader \
    -no-default-policy -orphan -ttl=15m -field=token
)"

VAULT_TOKEN="$audit_token" VAULT_OPS_CE=1 uv run pytest -q -m ce "$@"
# Then seal the throwaway server: `health` must still report it, everything else must refuse.
VAULT_TOKEN="$ROOT_TOKEN" vault operator seal >/dev/null
VAULT_TOKEN="$audit_token" VAULT_OPS_CE=sealed uv run pytest -q -m ce "$@"
