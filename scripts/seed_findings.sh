#!/bin/bash
# Seed configuration that trips the vault-ops audit rules (run after seed_vault.py).
# Idempotent: existing mounts/policies are left as they are. Needs a root token.
set -euo pipefail

: "${VAULT_ADDR:?VAULT_ADDR must be set}"
: "${VAULT_TOKEN:?VAULT_TOKEN must be set}"
NS="${FINDINGS_NAMESPACE:-tn009/soc2/dev}"
SENTINEL_NS="${SENTINEL_NAMESPACE:-tn009}"
EMPTY_PARENT="${EMPTY_PARENT:-tn010/prototypes}"
SENTINEL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/sentinel" && pwd)"

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

echo "Seeding audit findings in ${NS}"
step "VT-AUTH-001 userpass-public (listing_visibility=unauth)"
try vault auth enable -namespace="$NS" -path=userpass-public -listing-visibility=unauth userpass

step "VT-MOUNT-002 kv-long-ttl (max-lease-ttl above the cluster ceiling)"
try vault secrets enable -namespace="$NS" -path=kv-long-ttl kv-v2
vault secrets tune -namespace="$NS" -max-lease-ttl=87600h kv-long-ttl >/dev/null

step "VT-MOUNT-003 kv-local (local mount)"
try vault secrets enable -namespace="$NS" -path=kv-local -local kv-v2

step "VT-NS-002 ${EMPTY_PARENT}/empty-leaf (unused leaf namespace)"
try vault namespace create -namespace="$EMPTY_PARENT" empty-leaf

# Entities are upserted by name, so rerunning these is harmless.
step "VT-ID-001 entity vault-ops-orphan (no aliases)"
vault write -namespace="$NS" identity/entity name=vault-ops-orphan metadata=team=platform >/dev/null
step "VT-ID-002 entity vault-ops-direct (policy attached directly)"
vault write -namespace="$NS" identity/entity name=vault-ops-direct policies=default metadata=owner=vault-ops >/dev/null
step "VT-ID-003 entity vault-ops-disabled (disabled)"
vault write -namespace="$NS" identity/entity name=vault-ops-disabled disabled=true >/dev/null

if vault list -namespace="$SENTINEL_NS" sys/policies/egp 2>&1 | grep -q "unsupported path"; then
  echo "  [skip] Sentinel not available on this cluster"
  exit 0
fi

echo "Seeding Sentinel policies in ${SENTINEL_NS}"
step "VT-SNT-001 egp vault-ops-advisory"
vault write -namespace="$SENTINEL_NS" sys/policies/egp/vault-ops-advisory \
  enforcement_level=advisory paths="secret/data/*" policy=@"${SENTINEL_DIR}/noop.sentinel" >/dev/null
step "VT-SNT-002 rgp vault-ops-soft"
vault write -namespace="$SENTINEL_NS" sys/policies/rgp/vault-ops-soft \
  enforcement_level=soft-mandatory policy=@"${SENTINEL_DIR}/noop.sentinel" >/dev/null
step "VT-SNT-003 egp vault-ops-wildcard (hard-mandatory, paths=*)"
vault write -namespace="$SENTINEL_NS" sys/policies/egp/vault-ops-wildcard \
  enforcement_level=hard-mandatory paths="*" policy=@"${SENTINEL_DIR}/noop.sentinel" >/dev/null
step "VT-SNT-004 rgp vault-ops-always-true"
vault write -namespace="$SENTINEL_NS" sys/policies/rgp/vault-ops-always-true \
  enforcement_level=hard-mandatory policy=@"${SENTINEL_DIR}/always-true.sentinel" >/dev/null
step "control: rgp vault-ops-hard (must produce no finding)"
vault write -namespace="$SENTINEL_NS" sys/policies/rgp/vault-ops-hard \
  enforcement_level=hard-mandatory policy=@"${SENTINEL_DIR}/noop.sentinel" >/dev/null
echo "Done."
