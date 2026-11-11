#!/bin/bash
# Start Claude Code with the local cluster env from scripts/local_env.sh (target audit|pr|ns|dr,
# default audit). Drops every VAULT_* and HCP_* variable and every variable named in .env first
# (root VAULT_TOKEN, VAULT_LICENSE, HCP_CLIENT_SECRET, ...), whether it came from .env or the shell,
# so only local_env.sh's VAULT_* settings reach Claude. Fails before starting Claude when the token
# is missing or expired, or the claude command can't be found (CLAUDE_BIN overrides it, e.g. when
# claude is a shell alias or function, which scripts can't see).
set -euo pipefail

claude_bin="${CLAUDE_BIN:-claude}"
if ! command -v "$claude_bin" >/dev/null 2>&1; then
  echo "error: ${claude_bin} not found on PATH; set CLAUDE_BIN to the claude executable (aliases and shell functions aren't visible here)" >&2
  exit 1
fi

if [[ "${1:-}" == reset ]]; then
  echo "error: reset is for task env only" >&2
  exit 1
fi
exports="$("$(dirname "$0")/local_env.sh" "$@")" || exit 1

names=()
while IFS= read -r name; do
  names+=("$name")
done < <(
  compgen -e | grep -E '^(VAULT|HCP)_' || true
  [[ ! -f .env ]] || sed -nE 's/^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=.*/\2/p' .env
)
for name in ${names[@]+"${names[@]}"}; do
  [[ "$name" == CLAUDE_BIN ]] || unset "$name"
done

eval "$exports"
exec "$claude_bin"
