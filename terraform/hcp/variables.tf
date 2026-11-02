variable "cloud_provider" {
  description = "Cloud provider for the HVN"
  type        = string
  default     = "aws"
}

variable "cluster_id" {
  description = "ID of the HCP Vault Dedicated cluster"
  type        = string
  default     = "vault-ops-hcp"
}

variable "hvn_cidr" {
  description = "CIDR block of the HVN; must not overlap other HVNs in the project"
  type        = string
  default     = "172.25.80.0/20"
}

variable "hvn_id" {
  description = "ID of the HashiCorp Virtual Network created for the cluster"
  type        = string
  default     = "vault-ops-hvn"
}

variable "project_id" {
  description = "HCP project to create the HVN and cluster in"
  type        = string
}

variable "region" {
  description = "Cloud region for the HVN and cluster"
  type        = string
  default     = "us-west-2"
}

variable "tier" {
  description = "HCP Vault Dedicated tier; dev is a single node billed hourly"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "standard_small", "standard_medium", "standard_large", "plus_small", "plus_medium", "plus_large"], var.tier)
    error_message = "Tier must be dev, standard_small, standard_medium, standard_large, plus_small, plus_medium or plus_large."
  }
}
