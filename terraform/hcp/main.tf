resource "hcp_hvn" "main" {
  hvn_id         = var.hvn_id
  cloud_provider = var.cloud_provider
  region         = var.region
  cidr_block     = var.hvn_cidr
}

# No hcp_vault_cluster_admin_token here: it would store the admin token in state.
# task hcp:token requests one at run time and writes it to .tmp/admin-token-hcp (0600).
resource "hcp_vault_cluster" "main" {
  cluster_id      = var.cluster_id
  hvn_id          = hcp_hvn.main.hvn_id
  tier            = var.tier
  public_endpoint = true

  timeouts {
    create = "40m"
  }
}
