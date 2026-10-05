#!/bin/bash
# Seed configuration that trips the vault-ops audit rules (run after seed_vault.py).
# Idempotent: existing mounts/policies are left as they are. Needs a root token.
set -euo pipefail

: "${VAULT_ADDR:?VAULT_ADDR must be set}"
: "${VAULT_TOKEN:?VAULT_TOKEN must be set}"
NS="${FINDINGS_NAMESPACE:-tn009/soc2/dev}"
SENTINEL_NS="${SENTINEL_NAMESPACE:-tn009}"
SENTINEL_DRIFT_NS="${SENTINEL_DRIFT_NAMESPACE:-tn009/gdpr}"
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

step "VT-MOUNT-004 kv-long-default (default-lease-ttl above 768h)"
try vault secrets enable -namespace="$NS" -path=kv-long-default kv-v2
vault secrets tune -namespace="$NS" -max-lease-ttl=87600h -default-lease-ttl=1000h kv-long-default >/dev/null

step "VT-MOUNT-003 kv-local (local mount)"
try vault secrets enable -namespace="$NS" -path=kv-local -local kv-v2

step "VT-MOUNT-006 kv-v1 (KV version 1)"
try vault secrets enable -namespace="$NS" -path=kv-v1 -version=1 kv

step "VT-MOUNT-005 sprawl-01..21 (more than 20 kv mounts in one namespace)"
for i in $(seq -w 1 21); do
  try vault secrets enable -namespace="$NS" -path="sprawl-${i}" kv-v2
done

step "VT-NS-002 ${EMPTY_PARENT}/empty-leaf (unused leaf namespace)"
try vault namespace create -namespace="$EMPTY_PARENT" empty-leaf

# Entities are upserted by name, so rerunning these is harmless.
step "VT-ID-001 entity vault-ops-orphan (no aliases)"
vault write -namespace="$NS" identity/entity name=vault-ops-orphan metadata=team=platform >/dev/null
step "VT-ID-002 entity vault-ops-direct (policy attached directly)"
vault write -namespace="$NS" identity/entity name=vault-ops-direct policies=default metadata=owner=vault-ops >/dev/null
step "VT-ID-003 entity vault-ops-disabled (disabled)"
vault write -namespace="$NS" identity/entity name=vault-ops-disabled disabled=true >/dev/null

step "VT-ID-005 entities vault-ops-dup-a/-b (same alias name on two userpass mounts)"
try vault auth enable -namespace="$NS" -path=userpass-dup userpass
for pair in "a:userpass-public" "b:userpass-dup"; do
  entity="vault-ops-dup-${pair%%:*}"
  vault write -namespace="$NS" identity/entity name="$entity" >/dev/null
  entity_id="$(vault read -namespace="$NS" -field=id "identity/entity/name/${entity}")"
  accessor="$(vault auth list -namespace="$NS" -format=json | jq -r --arg m "${pair#*:}/" '.[$m].accessor')"
  try vault write -namespace="$NS" identity/entity-alias name=vault-ops-dup canonical_id="$entity_id" mount_accessor="$accessor"
done

# ACL policies (policies subcommand). The base seed's admin, rbac-policy-manager,
# oauth2-token-manager and service-account-creator already trip VT-POL-001/002/003.
step "VT-POL-004 drifted read-only policy (differs from every other copy)"
vault policy write -namespace="$NS" read-only - >/dev/null <<'HCL'
path "secret/data/*" { capabilities = ["read", "list"] }
path "secret/metadata/*" { capabilities = ["list"] }
HCL

# Audit devices and snapshots are cluster-wide: root namespace only.
echo "Seeding audit devices and automated snapshots (root namespace)"
step "audit device vault-ops-file (dummy file in the node's logs dir)"
try vault audit enable -path=vault-ops-file file file_path=/vault/logs/vault-ops-audit.log
step "VT-AUD-003 audit device vault-ops-stdout (stdout, hmac_accessor=false)"
try vault audit enable -path=vault-ops-stdout file file_path=stdout hmac_accessor=false

if vault list sys/storage/raft/snapshot-auto/config 2>&1 | grep -qE "unsupported path|enterprise-only feature"; then
  echo "  [skip] automated snapshots not available on this cluster"
else
  # The first snapshot runs one interval after the config is written, and the status is
  # empty until then: start at 30s, wait for a completed run, then settle on 24h.
  step "VT-SNAP-003 snapshot config vault-ops-local (local storage, 24h)"
  snap_config() {
    vault write sys/storage/raft/snapshot-auto/config/vault-ops-local \
      storage_type=local interval="$1" retain=2 \
      path_prefix=/vault/file/snapshots local_max_space=104857600 >/dev/null
  }
  if ! vault read -format=json sys/storage/raft/snapshot-auto/status/vault-ops-local 2>/dev/null | jq -e '.data.last_snapshot_end' >/dev/null; then
    snap_config 30s
    for _ in $(seq 1 18); do
      vault read -format=json sys/storage/raft/snapshot-auto/status/vault-ops-local 2>/dev/null | jq -e '.data.last_snapshot_end' >/dev/null && break
      sleep 5
    done
  fi
  snap_config 24h
fi

if vault list -namespace="$SENTINEL_NS" sys/policies/egp 2>&1 | grep -qE "unsupported path|enterprise-only feature"; then
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
step "control: rgp vault-ops-hard (must produce no audit finding)"
vault write -namespace="$SENTINEL_NS" sys/policies/rgp/vault-ops-hard \
  enforcement_level=hard-mandatory policy=@"${SENTINEL_DIR}/noop.sentinel" >/dev/null
step "VT-SNT-005 rgp vault-ops-hard drifted copy in ${SENTINEL_DRIFT_NS}"
vault write -namespace="$SENTINEL_DRIFT_NS" sys/policies/rgp/vault-ops-hard \
  enforcement_level=hard-mandatory policy=@"${SENTINEL_DIR}/noop-drift.sentinel" >/dev/null
step "VT-SNT-007 egp vault-ops-http (advisory, narrow path)"
vault write -namespace="$SENTINEL_NS" sys/policies/egp/vault-ops-http \
  enforcement_level=advisory paths="secret/data/vault-ops-http/*" policy=@"${SENTINEL_DIR}/http-import.sentinel" >/dev/null
# VT-SNT-006 (hard-mandatory, always false) is not seeded: it would lock out the dev cluster. Unit-tested only.
echo "Done."
