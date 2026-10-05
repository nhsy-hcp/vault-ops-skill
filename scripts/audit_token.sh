#!/bin/bash
# Write the vault-ops-readonly policy and mint a 1h orphan token into .tmp/audit-token (0600).
# POLICY_READER=1 also writes and attaches the read-only vault-ops-policy-reader add-on
# (ACL policy bodies, for the policies subcommand).
set -euo pipefail

: "${VAULT_ADDR:?VAULT_ADDR must be set}"
: "${VAULT_TOKEN:?VAULT_TOKEN must be set}"
POLICY_DIR="skills/vault-ops/policies"
TOKEN_FILE=".tmp/audit-token"
POLICIES=(vault-ops-readonly)
if [[ "${POLICY_READER:-0}" == "1" ]]; then
  POLICIES+=(vault-ops-policy-reader)
fi

mkdir -p .tmp
policy_flags=()
for policy in "${POLICIES[@]}"; do
  vault policy write "$policy" "${POLICY_DIR}/${policy}.hcl" >/dev/null
  policy_flags+=("-policy=${policy}")
done
umask 077
vault token create "${policy_flags[@]}" -no-default-policy -orphan \
  -ttl=1h -explicit-max-ttl=1h -display-name=vault-ops-audit -field=token >"$TOKEN_FILE"
echo "Wrote ${TOKEN_FILE} (policies ${POLICIES[*]}, ttl 1h)"
