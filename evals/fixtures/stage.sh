#!/bin/bash
# Scaffold for eval cases: copy saved vault-ops results into the run's working
# directory (the agent's cwd) where the skill looks for "the last audit".
set -euo pipefail

src="$(cd "$(dirname "$(realpath "${BASH_SOURCE[0]}")")" && pwd)/vault-ops"
mkdir -p .tmp/vault-ops
cp "$src"/*.json .tmp/vault-ops/
echo '*' > .tmp/vault-ops/.gitignore
