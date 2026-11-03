#!/bin/bash
# Full end-to-end check from scratch: wipes .tmp/vault (all node data, unseal keys, TLS),
# rebuilds primary + DR + performance secondary, enables replication, seeds, mints the
# audit tokens and runs every test suite and lint. Local only (needs a licence and podman).
set -euo pipefail

steps=(
  down clean up:all
  dr:enable pr:enable  # before seed: enabling replication restarts the primary and drops unsaved client activity
  seed seed:findings seed:ns
  token:policies token:pr token:ns
  test:all test:ce lint
)

# Log to .tmp/e2e/, which `task clean` keeps (it removes .tmp/*.log, so a redirect there is lost mid-run).
log_dir=.tmp/e2e
mkdir -p "$log_dir"
log="${log_dir}/e2e-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$log") 2>&1
echo "e2e log: ${log}"

start=$SECONDS
for step in "${steps[@]}"; do
  echo "==> task ${step}"
  task "$step"
done
echo "e2e passed in $((SECONDS - start))s (log: ${log})"
