#!/bin/bash
# Full end-to-end check from scratch: wipes .tmp/vault (all node data, unseal keys, TLS),
# rebuilds primary + DR + performance secondary, enables replication, seeds, mints the
# audit tokens and runs every test suite and lint. Local only (needs a licence and podman).
set -euo pipefail

steps=(
  down clean up:all
  dr:enable pr:enable  # before seed: enabling replication restarts the primary and drops unsaved client activity
  seed seed:findings
  token:policies token:pr
  test:all test:ce lint
)

start=$SECONDS
for step in "${steps[@]}"; do
  echo "==> task ${step}"
  task "$step"
done
echo "e2e passed in $((SECONDS - start))s"
