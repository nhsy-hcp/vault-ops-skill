#!/bin/bash
# Seed the HCP Vault Dedicated cluster from terraform/hcp with the child-namespace test layout
# (scripts/seed_child_ns.sh with NS=admin: a chain under admin/ down to depth 5 and a few mounts),
# as a freshly requested HCP admin token. Idempotent.
set -euo pipefail

# shellcheck source=scripts/hcp_lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/hcp_lib.sh"

hcp_admin_session
hcp_admin_run NS=admin scripts/seed_child_ns.sh
