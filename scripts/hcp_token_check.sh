#!/bin/bash
# Check that an HCP token file still holds a live token, for hcp:env (TOKEN=admin|audit, default
# admin). Writes to stderr only, since hcp:env's stdout is eval'd; never prints the token, its
# accessor or Vault's error text. Exit 1 when the file is missing, or the token expired or invalid.
set -euo pipefail

file=".tmp/${TOKEN:-admin}-token-hcp"
if [[ ! -s "$file" ]]; then
  echo "error: no ${file}; run: task hcp:token" >&2
  exit 1
fi

addr="$(terraform -chdir=terraform/hcp output -raw vault_public_endpoint_url)"
if ! ttl="$(env -u VAULT_SKIP_VERIFY -u VAULT_CACERT VAULT_ADDR="$addr" VAULT_NAMESPACE=admin \
  VAULT_TOKEN="$(<"$file")" vault token lookup -format=json 2>/dev/null | jq -er '.data.ttl')" ||
  ((ttl <= 0)); then
  echo "error: ${file} expired or invalid; run: task hcp:token" >&2
  exit 1
fi
echo "${file}: token ok, ttl $((ttl / 3600))h$(((ttl % 3600) / 60))m remaining" >&2
