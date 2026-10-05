#!/bin/bash
# Validate the local toolchain and environment for the vault-ops dev setup.
set -euo pipefail

CONTAINER_CLI="${CONTAINER_CLI:-docker}"
VAULT_HOST_IP="${VAULT_HOST_IP:-127.0.0.1}"
VAULT_HOST_PORT="${VAULT_HOST_PORT:-8210}"
fail=0

ok() { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1" >&2; fail=1; }

echo "Tools:"
for tool in task uv vault jq gitleaks shellcheck pre-commit "$CONTAINER_CLI"; do
  if command -v "$tool" >/dev/null 2>&1; then ok "$tool"; else bad "$tool not found"; fi
done

echo "Container runtime:"
if "$CONTAINER_CLI" info >/dev/null 2>&1; then
  ok "$CONTAINER_CLI engine reachable"
else
  bad "$CONTAINER_CLI engine not reachable (podman: run 'podman machine start')"
fi

echo "Network:"
if [[ "$(uname -s)" == "Darwin" && "$VAULT_HOST_IP" != "127.0.0.1" ]] && ! ifconfig lo0 | grep -q "inet ${VAULT_HOST_IP} "; then
  bad "${VAULT_HOST_IP} is not on lo0; run once per boot: sudo ifconfig lo0 alias ${VAULT_HOST_IP}"
else
  ok "${VAULT_HOST_IP} available"
fi
if lsof -nP -iTCP:"${VAULT_HOST_PORT}" -sTCP:LISTEN 2>/dev/null | grep -qv -e COMMAND -e gvproxy; then
  bad "port ${VAULT_HOST_PORT} already in use by another process"
else
  ok "port ${VAULT_HOST_PORT} free (or held by the vault container)"
fi

echo "Environment:"
if [[ -f .env ]]; then ok ".env present"; else bad ".env missing (cp .env.template .env)"; fi
if [[ -n "${VAULT_LICENSE:-}" ]]; then ok "VAULT_LICENSE set"; else bad "VAULT_LICENSE empty in .env"; fi
if [[ -n "${VAULT_ADDR:-}" ]]; then ok "VAULT_ADDR=${VAULT_ADDR}"; else bad "VAULT_ADDR not set"; fi

exit "$fail"
