#!/bin/bash
# Print eval-safe shell exports for the local compose cluster, for `eval "$(task env)"`.
# Target (positional, e.g. task env -- pr; or TOKEN=pr): audit (default, primary), pr (performance
# secondary), ns (child namespace from token:ns) or dr (DR secondary: health only, primary's audit
# token, no lookup since DR takes no client tokens). Otherwise checks the token with `vault token
# lookup`. Diagnostics go to stderr only, since stdout is eval'd; never prints the token, its
# accessor or Vault's error text. Root is not offered: .env has it.
set -euo pipefail

root_dir="$PWD"
if (($# > 1)); then
  echo "error: one target at most: audit, pr, ns or dr" >&2
  exit 1
fi
if [[ -n "${1:-}" && -n "${TOKEN:-}" && "$1" != "$TOKEN" ]]; then
  echo "error: target '${1}' conflicts with TOKEN=${TOKEN}" >&2
  exit 1
fi
kind="${1:-${TOKEN:-audit}}"
addr="${VAULT_ADDR:-https://127.0.0.1:8210}"
namespace=""
case "$kind" in
  audit) file=".tmp/audit-token"; fix="task token:audit" ;;
  pr) file=".tmp/audit-token-pr"; fix="task token:pr"; addr="${VAULT_PR_ADDR:-https://127.0.0.1:8240}" ;;
  ns) file=".tmp/audit-token-ns"; fix="task seed:ns token:ns" ;;
  dr) file=".tmp/audit-token"; fix="task token:audit"; addr="${VAULT_DR_ADDR:-https://127.0.0.1:8220}" ;;
  *) echo "error: target must be audit, pr, ns or dr (got '${kind}')" >&2; exit 1 ;;
esac

if [[ ! -s "$file" ]]; then
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

cacert="${VAULT_CACERT:-}"
if [[ -n "$cacert" && "$cacert" != /* ]]; then
  cacert="${root_dir}/${cacert}"
fi

if [[ "$kind" == dr ]]; then
  echo "${addr}: DR secondary, health only (unauthenticated reads); token not checked" >&2
elif ! ttl="$(env -u VAULT_NAMESPACE VAULT_ADDR="$addr" ${namespace:+VAULT_NAMESPACE="$namespace"} \
  VAULT_TOKEN="$(<"$file")" vault token lookup -format=json 2>/dev/null | jq -er '.data.ttl')" ||
  ((ttl <= 0)); then
  echo "error: ${file} expired or invalid, or ${addr} unreachable; run: ${fix}" >&2
  exit 1
else
  echo "${file}: token ok, ttl $((ttl / 3600))h$(((ttl % 3600) / 60))m remaining" >&2
fi

# Each statement ends in ";" so both eval "$(task env)" and an unquoted eval $(task env) work.
echo "export VAULT_ADDR=$(printf '%q' "$addr");"
if [[ -n "$namespace" ]]; then
  echo "export VAULT_NAMESPACE=$(printf '%q' "$namespace");"
else
  echo "unset VAULT_NAMESPACE;"
fi
if [[ -n "${VAULT_SKIP_VERIFY:-}" ]]; then
  echo "export VAULT_SKIP_VERIFY=$(printf '%q' "$VAULT_SKIP_VERIFY");"
fi
if [[ -n "$cacert" ]]; then
  echo "export VAULT_CACERT=$(printf '%q' "$cacert");"
fi
echo "export VAULT_TOKEN=\"\$(cat $(printf '%q' "${root_dir}/${file}"))\";"
