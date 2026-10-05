#!/bin/bash
# Stop and remove Vault node containers (idempotent). Raft data in .tmp/vault/<node>/ is kept.
#   usage: scripts/vault_down.sh [node-name ...]   (default: primary and DR)
set -euo pipefail

CONTAINER_CLI="${CONTAINER_CLI:-docker}"
if [[ $# -eq 0 ]]; then
  set -- "${VAULT_DR_CONTAINER_NAME:-vault-dr}" "${VAULT_CONTAINER_NAME:-vault-primary}"
fi

for name in "$@"; do
  if "$CONTAINER_CLI" rm -f "$name" >/dev/null 2>&1; then
    echo "Removed ${name}"
  else
    echo "${name} not running"
  fi
done
