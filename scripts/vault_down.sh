#!/bin/bash
# Stop and remove the Vault dev container (idempotent).
set -euo pipefail

CONTAINER_CLI="${CONTAINER_CLI:-docker}"
NAME="${VAULT_CONTAINER_NAME:-vault-primary}"

if "$CONTAINER_CLI" rm -f "$NAME" >/dev/null 2>&1; then
  echo "Removed ${NAME}"
else
  echo "${NAME} not running"
fi
