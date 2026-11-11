#!/bin/bash
# Check that an HCP token file still holds a live token, for hcp:env (TOKEN=admin|audit, default
# admin). Writes to stderr only, since hcp:env's stdout is eval'd; never prints the token, its
# accessor or Vault's error text. Exit 1 when the file is missing, or the token expired or invalid.
set -euo pipefail
# shellcheck source=scripts/token_lib.sh
source "$(dirname "$0")/token_lib.sh"

require_tools vault jq terraform
file=".tmp/${TOKEN:-admin}-token-hcp"
if [[ ! -s "$file" ]]; then
  echo "error: no ${file}; run: task hcp:token" >&2
  exit 1
fi

addr="$(terraform -chdir=terraform/hcp output -raw vault_public_endpoint_url)"
check_token "$file" "task hcp:token" VAULT_ADDR="$addr" VAULT_NAMESPACE=admin VAULT_TOKEN="$(<"$file")"
