#!/bin/bash
# Write the vault-ops-readonly policy and mint a 1h orphan token into .tmp/audit-token (0600).
set -euo pipefail

: "${VAULT_ADDR:?VAULT_ADDR must be set}"
: "${VAULT_TOKEN:?VAULT_TOKEN must be set}"
POLICY_FILE=".claude/skills/vault-ops/policies/vault-ops-readonly.hcl"
TOKEN_FILE=".tmp/audit-token"

mkdir -p .tmp
vault policy write vault-ops-readonly "$POLICY_FILE" >/dev/null
umask 077
vault token create -policy=vault-ops-readonly -no-default-policy -orphan \
  -ttl=1h -explicit-max-ttl=1h -display-name=vault-ops-audit -field=token >"$TOKEN_FILE"
echo "Wrote ${TOKEN_FILE} (policy vault-ops-readonly, ttl 1h)"
