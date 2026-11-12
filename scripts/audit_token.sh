#!/bin/bash
# Write the vault-ops-readonly policy and mint an orphan token (TTL, default 8h) into .tmp/audit-token (0600).
# TOKEN_FILE overrides the output file (token:pr mints on the performance secondary: tokens are
# per cluster, policy writes there are forwarded to the primary).
# POLICY_READER=1 also writes and attaches the read-only add-ons vault-ops-policy-reader
# (ACL policy bodies) and vault-ops-sentinel-reader (Sentinel EGP/RGP bodies).
# IF_MISSING=1 (task up) keeps TOKEN_FILE when it still holds a valid token (so a token minted
# by hand is never replaced) and skips in a task env shell, whose VAULT_TOKEN is the
# read-only token; otherwise it mints as usual.
set -euo pipefail
# shellcheck source=scripts/token_lib.sh
source "$(dirname "$0")/token_lib.sh"

TOKEN_FILE="${TOKEN_FILE:-.tmp/audit-token}"
if [[ "${IF_MISSING:-0}" == "1" ]]; then
  if [[ -n "${VAULT_OPS_ENV:-}" ]]; then
    echo "audit token: skipped (task env shell; run: eval \"\$(task env -- reset)\" && task token:policies)" >&2
    exit 0
  fi
  if [[ -s "$TOKEN_FILE" ]]; then
    check_env=()
    for name in VAULT_ADDR VAULT_NAMESPACE VAULT_SKIP_VERIFY VAULT_CACERT VAULT_CAPATH VAULT_CLIENT_CERT VAULT_CLIENT_KEY VAULT_TLS_SERVER_NAME; do
      if [[ -n "${!name:-}" ]]; then check_env+=("${name}=${!name}"); fi
    done
    if result="$(check_token "$TOKEN_FILE" "task token:policies" ${check_env[@]+"${check_env[@]}"} VAULT_TOKEN="$(<"$TOKEN_FILE")" 2>&1)"; then
      echo "$result" >&2
      exit 0
    fi
  fi
  echo "audit token: no valid ${TOKEN_FILE}; minting one" >&2
fi

: "${VAULT_ADDR:?VAULT_ADDR must be set}"
: "${VAULT_TOKEN:?VAULT_TOKEN must be set}"
POLICY_DIR="skills/vault-ops/policies"
TTL="${TTL:-8h}"
POLICIES=(vault-ops-readonly)
if [[ "${POLICY_READER:-0}" == "1" ]]; then
  POLICIES+=(vault-ops-policy-reader vault-ops-sentinel-reader)
fi

mkdir -p .tmp
policy_flags=()
for policy in "${POLICIES[@]}"; do
  vault policy write "$policy" "${POLICY_DIR}/${policy}.hcl" >/dev/null
  policy_flags+=("-policy=${policy}")
done
# mktemp creates the file 0600; mv replaces TOKEN_FILE whatever its old mode, and only on success.
tmp_file="$(mktemp "${TOKEN_FILE}.XXXXXX")"
trap 'rm -f "$tmp_file"' EXIT
vault token create "${policy_flags[@]}" -no-default-policy -orphan \
  -ttl="$TTL" -explicit-max-ttl="$TTL" -display-name=vault-ops-audit -field=token >"$tmp_file"
mv "$tmp_file" "$TOKEN_FILE"
echo "Wrote ${TOKEN_FILE} (policies ${POLICIES[*]}, ttl ${TTL})"
