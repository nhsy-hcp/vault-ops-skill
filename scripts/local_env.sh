#!/bin/bash
# Print eval-safe shell exports for the local compose cluster, for `eval "$(task env)"`.
# Target (one positional argument, e.g. task env -- pr): audit (default, primary), pr (performance
# secondary), ns (child namespace from token:ns), dr (DR secondary: health only, a placeholder token
# since DR takes no client tokens) or reset (unset everything this prints, so the root token and
# addresses from .env apply to tasks again).
# Addresses and TLS settings come from .env, never from the inherited shell, so a previous
# eval "$(task env -- pr)" or hcp:env can't redirect the primary's token to another cluster.
# Checks the token with `vault token lookup` first. On any failure stdout is the reset line plus
# `false`, so the eval drops a root or HCP admin token from the shell and returns non-zero.
# Diagnostics go to stderr only; never prints a token, its accessor or Vault's error text.
set -euo pipefail
# shellcheck source=scripts/token_lib.sh
source "$(dirname "$0")/token_lib.sh"

# Variables this script exports; reset (and every failure) unsets them all.
managed=(VAULT_ADDR VAULT_TOKEN VAULT_NAMESPACE VAULT_SKIP_VERIFY VAULT_CACERT VAULT_CAPATH
  VAULT_CLIENT_CERT VAULT_CLIENT_KEY VAULT_TLS_SERVER_NAME VAULT_OPS_ENV)
tls_vars=(VAULT_SKIP_VERIFY VAULT_CACERT VAULT_CAPATH VAULT_CLIENT_CERT VAULT_CLIENT_KEY VAULT_TLS_SERVER_NAME)
reset_line="unset ${managed[*]};"
succeeded=0
# Each statement ends in ";" so both eval "$(task env)" and an unquoted eval $(task env) work.
trap '((succeeded)) || echo "${reset_line} false;"' EXIT

# dotenv_get NAME: the last value assigned to NAME in .env (surrounding quotes removed), or "".
dotenv_get() {
  [[ -f .env ]] || return 0
  sed -nE "s/^[[:space:]]*(export[[:space:]]+)?$1=(.*)$/\2/p" .env | tail -n 1 |
    sed -E "s/^\"(.*)\"\$/\1/; s/^'(.*)'\$/\1/"
}

root_dir="$PWD"
if (($# > 1)); then
  echo "error: one target at most: audit, pr, ns, dr or reset" >&2
  exit 1
fi
kind="${1:-audit}"
if [[ "$kind" == reset ]]; then
  echo "$reset_line"
  succeeded=1
  exit 0
fi

addr="$(dotenv_get VAULT_ADDR)"
addr="${addr:-https://127.0.0.1:8210}"
namespace=""
case "$kind" in
  audit) file=".tmp/audit-token"; fix="task token:audit" ;;
  pr)
    file=".tmp/audit-token-pr"; fix="task token:pr"
    addr="$(dotenv_get VAULT_PR_ADDR)"; addr="${addr:-https://127.0.0.1:8240}" ;;
  ns) file=".tmp/audit-token-ns"; fix="task seed:ns token:ns" ;;
  dr)
    file=""; fix=""
    addr="$(dotenv_get VAULT_DR_ADDR)"; addr="${addr:-https://127.0.0.1:8220}" ;;
  *) echo "error: target must be audit, pr, ns, dr or reset" >&2; exit 1 ;;
esac

if [[ -n "$file" && ! -s "$file" ]]; then
  echo "error: no ${file}; run: ${fix}" >&2
  exit 1
fi
if [[ "$kind" == ns ]]; then
  if [[ ! -s "${file}.namespace" ]]; then
    echo "error: no ${file}.namespace; run: ${fix}" >&2
    exit 1
  fi
  namespace="$(<"${file}.namespace")"
fi

# TLS settings: .env first, then the inherited environment; relative paths resolve from the repo root.
tls_env=()
for name in "${tls_vars[@]}"; do
  value="$(dotenv_get "$name")"
  value="${value:-${!name:-}}"
  [[ -n "$value" ]] || continue
  if [[ "$name" =~ ^VAULT_(CACERT|CAPATH|CLIENT_CERT|CLIENT_KEY)$ && "$value" != /* ]]; then
    value="${root_dir}/${value}"
  fi
  tls_env+=("${name}=${value}")
done

if [[ "$kind" == dr ]]; then
  echo "${addr}: DR secondary, health only (unauthenticated reads); placeholder token, not checked" >&2
else
  require_tools vault jq
  check_token "$file" "$fix" VAULT_ADDR="$addr" ${namespace:+VAULT_NAMESPACE="$namespace"} \
    ${tls_env[@]+"${tls_env[@]}"} VAULT_TOKEN="$(<"$file")"
fi

echo "$reset_line"
echo "export VAULT_ADDR=$(printf '%q' "$addr");"
if [[ -n "$namespace" ]]; then
  echo "export VAULT_NAMESPACE=$(printf '%q' "$namespace");"
fi
for setting in ${tls_env[@]+"${tls_env[@]}"}; do
  echo "export ${setting%%=*}=$(printf '%q' "${setting#*=}");"
done
if [[ "$kind" == dr ]]; then
  # The skill needs VAULT_TOKEN set; DR secondaries ignore it for the unauthenticated health reads.
  echo "export VAULT_TOKEN=dr-health-only;"
else
  echo "export VAULT_TOKEN=\"\$(cat $(printf '%q' "${root_dir}/${file}"))\";"
fi
# Marks a shell (or a task claude session) holding these exports: setup tasks refuse to run there.
echo "export VAULT_OPS_ENV=$(printf '%q' "$kind");"
# shellcheck disable=SC2034 # read by the EXIT trap
succeeded=1
