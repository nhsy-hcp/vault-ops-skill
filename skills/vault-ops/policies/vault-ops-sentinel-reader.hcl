# vault-ops-sentinel-reader: add-on policy for Sentinel checks in the vault-ops
# `audit` and `policies` subcommands.
#
# Grants READ on Sentinel EGP and RGP policy bodies and nothing else: no list, no
# sudo, no write. vault-ops-readonly already lists EGP/RGP names; this add-on lets
# the script read each body for its enforcement level, EGP paths and checks. The
# script hashes and scans the source in memory and writes only policy names,
# enforcement levels, EGP paths, import names, a body hash and flagged rules:
# Sentinel source and comments never reach its output files.
#
# Attach it next to vault-ops-readonly, only for a policy review, in the ROOT namespace:
#   vault policy write vault-ops-sentinel-reader vault-ops-sentinel-reader.hcl
#   vault token create -policy=vault-ops-readonly -policy=vault-ops-sentinel-reader \
#     -no-default-policy -orphan -ttl=1h -explicit-max-ttl=1h
#
# Namespace-local rules repeat per nesting level ("+" = exactly one segment);
# root plus five levels are covered, matching vault-ops-readonly.

path "sys/policies/egp/*" {
  capabilities = ["read"]
}

path "+/sys/policies/egp/*" {
  capabilities = ["read"]
}

path "+/+/sys/policies/egp/*" {
  capabilities = ["read"]
}

path "+/+/+/sys/policies/egp/*" {
  capabilities = ["read"]
}

path "+/+/+/+/sys/policies/egp/*" {
  capabilities = ["read"]
}

path "+/+/+/+/+/sys/policies/egp/*" {
  capabilities = ["read"]
}

path "sys/policies/rgp/*" {
  capabilities = ["read"]
}

path "+/sys/policies/rgp/*" {
  capabilities = ["read"]
}

path "+/+/sys/policies/rgp/*" {
  capabilities = ["read"]
}

path "+/+/+/sys/policies/rgp/*" {
  capabilities = ["read"]
}

path "+/+/+/+/sys/policies/rgp/*" {
  capabilities = ["read"]
}

path "+/+/+/+/+/sys/policies/rgp/*" {
  capabilities = ["read"]
}
