#!/bin/bash
# Seed a child namespace for child-namespace token tests (task token:ns mints a token inside it).
# NS (default admin) can be any Vault Enterprise namespace path, nested or not. Below it: a chain
# down to depth 5 from root, the deepest level vault-ops-readonly.hcl covers, plus a few mounts.
# Idempotent; needs a root token.
set -euo pipefail

: "${VAULT_ADDR:?VAULT_ADDR must be set}"
: "${VAULT_TOKEN:?VAULT_TOKEN must be set}"
NS="${NS:-admin}"
NS="${NS#/}"
NS="${NS%/}"
MAX_DEPTH=5

step() { printf '  [+] %s\n' "$1"; }

# vault CLI exits non-zero when a path is already in use; treat that as success.
try() {
  local out
  if ! out="$("$@" 2>&1)"; then
    if [[ "$out" == *"already in use"* || "$out" == *"existing mount"* || "$out" == *"already exists"* ]]; then
      return 0
    fi
    echo "$out" >&2
    return 1
  fi
}

IFS=/ read -r -a segments <<<"$NS"
depth=${#segments[@]}
if ((depth > MAX_DEPTH)); then
  echo "NS=${NS} is deeper than ${MAX_DEPTH} levels, which vault-ops-readonly.hcl does not cover" >&2
  exit 1
fi

echo "Seeding child namespace ${NS}/"
parent=""
if vault secrets list -namespace="$NS" >/dev/null 2>&1; then
  # Already there (e.g. admin/ on HCP Vault Dedicated, where the token can't write to root).
  step "namespace ${NS}/ exists"
  segments=()
  parent="$NS"
fi
for segment in ${segments[@]+"${segments[@]}"}; do
  step "namespace ${parent:+${parent}/}${segment}/"
  if [[ -n "$parent" ]]; then
    try vault namespace create -namespace="$parent" "$segment"
  else
    try vault namespace create "$segment"
  fi
  parent="${parent:+${parent}/}${segment}"
done

first_child=""
for ((level = depth + 1; level <= MAX_DEPTH; level++)); do
  child="l${level}"
  step "namespace ${parent}/${child}/"
  try vault namespace create -namespace="$parent" "$child"
  parent="${parent}/${child}"
  first_child="${first_child:-$parent}"
done

step "${NS}/: userpass auth, kv-v2 secret/"
try vault auth enable -namespace="$NS" userpass
try vault secrets enable -namespace="$NS" -path=secret kv-v2

if [[ -n "$first_child" ]]; then
  step "${first_child}/: approle auth, kv-v2 apps/"
  try vault auth enable -namespace="$first_child" approle
  try vault secrets enable -namespace="$first_child" -path=apps kv-v2
fi

step "${parent}/: transit"
try vault secrets enable -namespace="$parent" transit

echo "Seeded ${NS}/ (deepest: ${parent}/)"
