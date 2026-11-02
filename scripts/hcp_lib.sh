#!/bin/bash
# Shared by hcp_token.sh and hcp_seed.sh (sourced, not run): reads the cluster from terraform/hcp
# outputs and requests a fresh HCP admin token (6h). Never put it in Terraform state or give it to
# the skill. Sets HCP_VAULT_ADDR and HCP_ADMIN_TOKEN.

HCP_TF_DIR="terraform/hcp"
HCP_API="https://api.cloud.hashicorp.com/vault/2020-11-25"

hcp_admin_session() {
  local cluster_id org_id project_id bearer
  cluster_id="$(terraform -chdir="$HCP_TF_DIR" output -raw cluster_id)"
  org_id="$(terraform -chdir="$HCP_TF_DIR" output -raw organization_id)"
  project_id="$(terraform -chdir="$HCP_TF_DIR" output -raw project_id)"
  HCP_VAULT_ADDR="$(terraform -chdir="$HCP_TF_DIR" output -raw vault_public_endpoint_url)"

  if ! bearer="$(hcp auth print-access-token 2>/dev/null)" || [[ -z "$bearer" ]]; then
    echo "error: no HCP credentials; run: hcp auth login" >&2
    return 1
  fi
  HCP_ADMIN_TOKEN="$(
    curl -fsS -H "Authorization: Bearer ${bearer}" \
      "${HCP_API}/organizations/${org_id}/projects/${project_id}/clusters/${cluster_id}/admintoken" |
      jq -er '.token'
  )"
  export HCP_VAULT_ADDR HCP_ADMIN_TOKEN
}

# Run a command against the HCP cluster as the admin token. .env (loaded by Taskfile) points at
# the local dev primary with skip-verify and VAULT_NAMESPACE: override all of it.
hcp_admin_run() {
  env -u VAULT_SKIP_VERIFY -u VAULT_CACERT -u VAULT_NAMESPACE \
    VAULT_ADDR="$HCP_VAULT_ADDR" VAULT_TOKEN="$HCP_ADMIN_TOKEN" "$@"
}
