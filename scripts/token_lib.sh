#!/bin/bash
# Shared token check for local_env.sh and hcp_token_check.sh. Source it; don't run it.
# Writes to stderr only (callers' stdout may be eval'd) and never prints the token, its accessor or
# Vault's error text.

# require_tools TOOL...: fail with one message per missing tool.
require_tools() {
  local tool missing=0
  for tool in "$@"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "error: ${tool} not found on PATH (run: task deps)" >&2
      missing=1
    fi
  done
  return "$missing"
}

# check_token LABEL FIX ENV_ASSIGNMENT...: run `vault token lookup` with exactly the given VAULT_*
# assignments (every inherited VAULT_* variable is dropped first). Accepts a token that never
# expires. On failure, an unauthenticated `vault status` tells an unreachable or sealed node apart
# from a bad token.
check_token() {
  local label="$1" fix="$2" rc=0 info ttl expire name
  shift 2
  local scrub=() status_env=()
  while IFS= read -r name; do
    scrub+=(-u "$name")
  done < <(compgen -e | grep '^VAULT_' || true)
  for name in "$@"; do
    [[ "$name" == VAULT_TOKEN=* || "$name" == VAULT_NAMESPACE=* ]] || status_env+=("$name")
  done

  if ! info="$(env ${scrub[@]+"${scrub[@]}"} "$@" vault token lookup -format=json 2>/dev/null |
    jq -er '[.data.ttl, (.data.expire_time // "never")] | @tsv')"; then
    env ${scrub[@]+"${scrub[@]}"} ${status_env[@]+"${status_env[@]}"} vault status >/dev/null 2>&1 || rc=$?
    case "$rc" in
      0) echo "error: ${label}: token expired or invalid; run: ${fix}" >&2 ;;
      2) echo "error: ${label}: Vault is sealed or not initialised" >&2 ;;
      *) echo "error: ${label}: Vault unreachable (node down, wrong address or TLS settings)" >&2 ;;
    esac
    return 1
  fi
  IFS=$'\t' read -r ttl expire <<<"$info"
  if [[ "$expire" == never ]]; then
    echo "${label}: token ok, no expiry" >&2
  elif ((ttl <= 0)); then
    echo "error: ${label}: token expired; run: ${fix}" >&2
    return 1
  else
    echo "${label}: token ok, ttl $((ttl / 3600))h$(((ttl % 3600) / 60))m remaining" >&2
  fi
}
