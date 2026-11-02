terraform {
  required_version = ">= 1.9"

  required_providers {
    hcp = {
      source  = "hashicorp/hcp"
      version = "~> 0.115"
    }
  }
}
