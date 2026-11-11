#!/bin/bash
# Start Claude Code with the local cluster env from scripts/local_env.sh (target audit|pr|ns|dr,
# default audit). Drops every variable named in .env first (root VAULT_TOKEN, VAULT_LICENSE, HCP_*,
# ...) so only the skill's VAULT_* settings reach Claude. Fails before starting Claude when the
# token is missing or expired.
set -euo pipefail

exports="$(scripts/local_env.sh "$@")"

if [[ -f .env ]]; then
  while IFS= read -r name; do
    unset "$name"
  done < <(sed -nE 's/^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=.*/\2/p' .env)
fi
unset VAULT_NAMESPACE VAULT_CACERT VAULT_SKIP_VERIFY

eval "$exports"
exec claude
