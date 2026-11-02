# Credentials: the `hcp auth login` session, or HCP_CLIENT_ID/HCP_CLIENT_SECRET (service principal) when set.
provider "hcp" {
  project_id = var.project_id
}
