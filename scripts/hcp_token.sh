#!/bin/bash
# Fetch tokens for the HCP Vault Dedicated cluster from terraform/hcp. Usage: hcp_token.sh [TTL]
# (default 12h, e.g. task hcp:token -- 8h):
#   .tmp/admin-token-hcp  an orphan hcp-root token in admin/ with TTL, minted with the 6h HCP admin
#                         token (which is not saved): for humans and setup only (policy writes),
#                         never for the skill or the tests
#   .tmp/audit-token-hcp  a vault-ops-readonly + add-ons token in admin/ with TTL
# Both 0600 under .tmp/ (gitignored); task clean removes them. Vault caps TTLs at the token mount's
# max_ttl without an error, so the effective TTLs are looked up and a shorter one is warned about.
set -euo pipefail

TTL="${1:-12h}"
if [[ ! "$TTL" =~ ^[1-9][0-9]*[smh]$ ]]; then
  echo "usage: task hcp:token [-- <ttl>]  (ttl like 30m, 8h or 12h; got '${TTL}')" >&2
  exit 1
fi

# shellcheck source=scripts/hcp_lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/hcp_lib.sh"

to_seconds() {
  local n="${1%[smh]}"
  case "${1: -1}" in
    s) echo "$n" ;;
    m) echo $((n * 60)) ;;
    h) echo $((n * 3600)) ;;
  esac
}

# Print the token's effective TTL (only the TTL, never the token) and warn when Vault capped it.
report_ttl() {
  local label="$1" token="$2" ttl
  ttl="$(hcp_admin_run VAULT_NAMESPACE=admin VAULT_TOKEN="$token" vault token lookup -format=json | jq -er '.data.ttl')"
  echo "${label}: ttl $((ttl / 3600))h$(((ttl % 3600) / 60))m"
  if ((ttl < $(to_seconds "$TTL") - 60)); then
    echo "warning: ${label} ttl capped below the requested ${TTL} (token mount max_ttl)" >&2
  fi
}

hcp_admin_session
mkdir -p .tmp
admin_token="$(hcp_admin_run VAULT_NAMESPACE=admin vault token create -orphan -policy=hcp-root \
  -ttl="$TTL" -explicit-max-ttl="$TTL" -display-name=vault-ops-hcp-admin -field=token)"
(
  umask 077
  printf '%s\n' "$admin_token" >.tmp/admin-token-hcp
)
echo "Wrote .tmp/admin-token-hcp (hcp-root, ${TTL}; never use it for the skill)"
report_ttl .tmp/admin-token-hcp "$admin_token"

hcp_admin_run VAULT_NAMESPACE=admin TOKEN_FILE=.tmp/audit-token-hcp POLICY_READER=1 TTL="$TTL" scripts/audit_token.sh
echo "admin" >.tmp/audit-token-hcp.namespace
report_ttl .tmp/audit-token-hcp "$(<.tmp/audit-token-hcp)"
