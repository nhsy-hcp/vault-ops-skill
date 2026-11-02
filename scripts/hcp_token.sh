#!/bin/bash
# Fetch tokens for the HCP Vault Dedicated cluster from terraform/hcp:
#   .tmp/admin-token-hcp  the HCP admin token (6h, hcp-root policy in admin/): for humans and
#                         setup only (policy writes, hcp:seed), never for the skill or the tests
#   .tmp/audit-token-hcp  a 1h vault-ops-readonly + add-ons token minted in admin/ with it
# Both 0600 under .tmp/ (gitignored); task clean removes them.
set -euo pipefail

# shellcheck source=scripts/hcp_lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/hcp_lib.sh"

hcp_admin_session
mkdir -p .tmp
(
  umask 077
  printf '%s\n' "$HCP_ADMIN_TOKEN" >.tmp/admin-token-hcp
)
echo "Wrote .tmp/admin-token-hcp (HCP admin token, 6h; never use it for the skill)"
hcp_admin_run VAULT_NAMESPACE=admin TOKEN_FILE=.tmp/audit-token-hcp POLICY_READER=1 scripts/audit_token.sh
echo "admin" >.tmp/audit-token-hcp.namespace
