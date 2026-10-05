# vault-ops-readonly: least-privilege policy for the vault-ops Claude skill.
#
# Read/list only; nothing here can change Vault. Derived from vault-tools'
# audit-policy.hcl, plus the cluster-status reads the health subcommand needs.
# ACL and Sentinel (EGP/RGP) policy bodies are NOT readable (list only): names are
# enough for the inventory and bodies would expose the cluster's whole access model.
# Body reads live in the opt-in add-ons vault-ops-policy-reader (ACL) and
# vault-ops-sentinel-reader (Sentinel).
#
# Namespace-local rules repeat per nesting level ("+" = exactly one segment);
# root plus five levels are covered. Create the token in the ROOT namespace:
#   vault policy write vault-ops-readonly vault-ops-readonly.hcl
#   vault token create -policy=vault-ops-readonly -ttl=1h -explicit-max-ttl=1h -orphan

# --- token self-check (validate) ---
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# --- cluster-wide status (root only) ---
path "sys/config/state/sanitized" {
  capabilities = ["read"]
}

path "sys/license/status" {
  capabilities = ["read"]
}

path "sys/replication/status" {
  capabilities = ["read"]
}

path "sys/internal/counters/activity" {
  capabilities = ["read"]
}

path "sys/internal/counters/activity/monthly" {
  capabilities = ["read"]
}

# --- integrated storage (raft peers, autopilot) ---
path "sys/storage/raft/configuration" {
  capabilities = ["read"]
}

path "sys/storage/raft/autopilot/configuration" {
  capabilities = ["read"]
}

path "sys/storage/raft/autopilot/state" {
  capabilities = ["read"]
}

# --- runtime metrics of the queried node (JSON; the script keeps an allowlist) ---
path "sys/metrics" {
  capabilities = ["read"]
}

# --- audit devices (root only) ---
# Listing devices is a sudo-protected endpoint. The exact path (no glob) grants
# no access to sys/audit/<path>, so devices can't be enabled or disabled.
path "sys/audit" {
  capabilities = ["read", "sudo"]
}

# --- automated raft snapshots (Enterprise) ---
# Config names and per-config status only. Listing is sudo-protected; the exact
# path (no glob) still leaves snapshot-auto/config/<name> unreadable. Never grant
# read on snapshot-auto/config/*: it returns storage credentials in plaintext.
path "sys/storage/raft/snapshot-auto/config" {
  capabilities = ["list", "sudo"]
}

path "sys/storage/raft/snapshot-auto/status/*" {
  capabilities = ["read"]
}

# sys/health, sys/seal-status and sys/leader are unauthenticated: no rule needed.

# --- auth methods ---
path "sys/auth" {
  capabilities = ["read"]
}

path "+/sys/auth" {
  capabilities = ["read"]
}

path "+/+/sys/auth" {
  capabilities = ["read"]
}

path "+/+/+/sys/auth" {
  capabilities = ["read"]
}

path "+/+/+/+/sys/auth" {
  capabilities = ["read"]
}

path "+/+/+/+/+/sys/auth" {
  capabilities = ["read"]
}

# --- secrets engines ---
path "sys/mounts" {
  capabilities = ["read"]
}

path "+/sys/mounts" {
  capabilities = ["read"]
}

path "+/+/sys/mounts" {
  capabilities = ["read"]
}

path "+/+/+/sys/mounts" {
  capabilities = ["read"]
}

path "+/+/+/+/sys/mounts" {
  capabilities = ["read"]
}

path "+/+/+/+/+/sys/mounts" {
  capabilities = ["read"]
}

# --- child namespaces ---
path "sys/namespaces" {
  capabilities = ["list"]
}

path "+/sys/namespaces" {
  capabilities = ["list"]
}

path "+/+/sys/namespaces" {
  capabilities = ["list"]
}

path "+/+/+/sys/namespaces" {
  capabilities = ["list"]
}

path "+/+/+/+/sys/namespaces" {
  capabilities = ["list"]
}

path "+/+/+/+/+/sys/namespaces" {
  capabilities = ["list"]
}

# --- ACL policy names (never bodies) ---
path "sys/policies/acl" {
  capabilities = ["list"]
}

path "+/sys/policies/acl" {
  capabilities = ["list"]
}

path "+/+/sys/policies/acl" {
  capabilities = ["list"]
}

path "+/+/+/sys/policies/acl" {
  capabilities = ["list"]
}

path "+/+/+/+/sys/policies/acl" {
  capabilities = ["list"]
}

path "+/+/+/+/+/sys/policies/acl" {
  capabilities = ["list"]
}

# --- Sentinel EGP list ---
path "sys/policies/egp" {
  capabilities = ["list"]
}

path "+/sys/policies/egp" {
  capabilities = ["list"]
}

path "+/+/sys/policies/egp" {
  capabilities = ["list"]
}

path "+/+/+/sys/policies/egp" {
  capabilities = ["list"]
}

path "+/+/+/+/sys/policies/egp" {
  capabilities = ["list"]
}

path "+/+/+/+/+/sys/policies/egp" {
  capabilities = ["list"]
}

# --- Sentinel RGP list ---
path "sys/policies/rgp" {
  capabilities = ["list"]
}

path "+/sys/policies/rgp" {
  capabilities = ["list"]
}

path "+/+/sys/policies/rgp" {
  capabilities = ["list"]
}

path "+/+/+/sys/policies/rgp" {
  capabilities = ["list"]
}

path "+/+/+/+/sys/policies/rgp" {
  capabilities = ["list"]
}

path "+/+/+/+/+/sys/policies/rgp" {
  capabilities = ["list"]
}

# --- identity entities (entities subcommand) ---
# Reading an entity returns its metadata and aliases; the script writes them only with --list.
path "identity/entity/id" {
  capabilities = ["list"]
}

path "+/identity/entity/id" {
  capabilities = ["list"]
}

path "+/+/identity/entity/id" {
  capabilities = ["list"]
}

path "+/+/+/identity/entity/id" {
  capabilities = ["list"]
}

path "+/+/+/+/identity/entity/id" {
  capabilities = ["list"]
}

path "+/+/+/+/+/identity/entity/id" {
  capabilities = ["list"]
}

path "identity/entity/id/*" {
  capabilities = ["read"]
}

path "+/identity/entity/id/*" {
  capabilities = ["read"]
}

path "+/+/identity/entity/id/*" {
  capabilities = ["read"]
}

path "+/+/+/identity/entity/id/*" {
  capabilities = ["read"]
}

path "+/+/+/+/identity/entity/id/*" {
  capabilities = ["read"]
}

path "+/+/+/+/+/identity/entity/id/*" {
  capabilities = ["read"]
}
