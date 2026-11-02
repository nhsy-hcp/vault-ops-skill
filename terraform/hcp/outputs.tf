output "cluster_id" {
  description = "ID of the HCP Vault Dedicated cluster"
  value       = hcp_vault_cluster.main.cluster_id
}

output "organization_id" {
  description = "HCP organization that owns the cluster"
  value       = hcp_vault_cluster.main.organization_id
}

output "project_id" {
  description = "HCP project that owns the cluster"
  value       = hcp_vault_cluster.main.project_id
}

output "tier" {
  description = "Tier of the cluster"
  value       = hcp_vault_cluster.main.tier
}

output "vault_public_endpoint_url" {
  description = "Public URL of the cluster's Vault API"
  value       = hcp_vault_cluster.main.vault_public_endpoint_url
}

output "vault_version" {
  description = "Vault version running on the cluster"
  value       = hcp_vault_cluster.main.vault_version
}
