#!/bin/bash
# Run the OSS smoke tests (tests/test_oss.py) against a throwaway `vault server -dev`.
# Community edition: no namespaces, Sentinel, license, Raft or snapshots. In-memory, no
# container or license needed; the server is stopped on exit. Root is used only for setup
# and, after the first pass, to seal the server for the sealed-node pass.
set -euo pipefail

PORT="${OSS_PORT:-8230}"
ROOT_TOKEN="vault-ops-oss-root"
POLICY_DIR="skills/vault-ops/policies"
LOG=".tmp/vault-oss.log"

if ! vault version | grep -qv "+ent"; then
  echo "error: the local vault binary is Enterprise; test:oss needs a Community build" >&2
  exit 1
fi
if curl -s -o /dev/null "http://127.0.0.1:${PORT}/v1/sys/health"; then
  echo "error: port ${PORT} is already in use (set OSS_PORT)" >&2
  exit 1
fi

mkdir -p .tmp
vault server -dev -dev-listen-address="127.0.0.1:${PORT}" -dev-root-token-id="$ROOT_TOKEN" -dev-no-store-token >"$LOG" 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true' EXIT

export VAULT_ADDR="http://127.0.0.1:${PORT}"
for _ in $(seq 1 20); do
  VAULT_TOKEN="$ROOT_TOKEN" vault status >/dev/null 2>&1 && break
  sleep 0.5
done

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

VAULT_TOKEN="$audit_token" VAULT_OPS_OSS=1 uv run pytest -q -m oss "$@"
# Then seal the throwaway server: `health` must still report it, everything else must refuse.
VAULT_TOKEN="$ROOT_TOKEN" vault operator seal >/dev/null
VAULT_TOKEN="$audit_token" VAULT_OPS_OSS=sealed uv run pytest -q -m oss "$@"
