#!/bin/bash
# Scaffold for eval cases: copy saved vault-ops results into the run's working
# directory (the agent's cwd) where the skill looks for "the last audit".
# Usage: stage.sh [fixture-dir]  (default: the shared fixtures/vault-ops/ set).
# Cases on the shared set symlink this as their scaffold.sh; cases with their
# own fixtures/ use a scaffold.sh that passes that directory.
set -euo pipefail

src="${1:-$(cd "$(dirname "$(realpath "${BASH_SOURCE[0]}")")" && pwd)/vault-ops}"
mkdir -p .tmp/vault-ops
cp "$src"/*.json .tmp/vault-ops/
echo '*' >.tmp/vault-ops/.gitignore
