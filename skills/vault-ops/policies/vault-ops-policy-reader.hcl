# vault-ops-policy-reader: add-on policy for the vault-ops `policies` subcommand.
#
# Grants READ on ACL policy bodies and nothing else: no list, no sudo, no write.
# vault-ops-readonly already lists policy names; this add-on lets the script read
# each body so it can assess permissions. The script parses bodies in memory and
# writes only policy names, a body hash and flagged rules (path + capabilities):
# bodies and allowed/denied parameter values never reach its output files.
#
# Attach it next to vault-ops-readonly, only for a policy review, in the ROOT namespace:
#   vault policy write vault-ops-policy-reader vault-ops-policy-reader.hcl
#   vault token create -policy=vault-ops-readonly -policy=vault-ops-policy-reader \
#     -no-default-policy -orphan -ttl=1h -explicit-max-ttl=1h
#
# Namespace-local rules repeat per nesting level ("+" = exactly one segment);
# root plus five levels are covered, matching vault-ops-readonly.

path "sys/policies/acl/*" {
  capabilities = ["read"]
}

path "+/sys/policies/acl/*" {
  capabilities = ["read"]
}

path "+/+/sys/policies/acl/*" {
  capabilities = ["read"]
}

path "+/+/+/sys/policies/acl/*" {
  capabilities = ["read"]
}

path "+/+/+/+/sys/policies/acl/*" {
  capabilities = ["read"]
}

path "+/+/+/+/+/sys/policies/acl/*" {
  capabilities = ["read"]
}
