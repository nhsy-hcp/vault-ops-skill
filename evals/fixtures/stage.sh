#!/bin/bash
# Scaffold for eval cases: copy saved vault-ops results into the run's working
# directory (the agent's cwd) where the skill looks for "the last audit".
# Usage: stage.sh [fixture-dir]  (default: the shared fixtures/vault-ops/ set).
# Cases on the shared set symlink this as their scaffold.sh; cases with their
# own fixtures/ use a scaffold.sh that passes that directory.
# Every licence expiry in the staged copies is moved to today + days_remaining
# (VT-LIC-001 evidence) or today + 365 days (no VT-LIC-001 finding), so fixture
# licences never look expired as the calendar moves on. Only licence
# fields change (run timestamps and filenames stay: graders name them), and
# every file gets the same date, so diffs between fixtures are unchanged.
set -euo pipefail

src="${1:-$(cd "$(dirname "$(realpath "${BASH_SOURCE[0]}")")" && pwd)/vault-ops}"
mkdir -p .tmp/vault-ops
cp "$src"/*.json .tmp/vault-ops/
echo '*' >.tmp/vault-ops/.gitignore

python3 -I - .tmp/vault-ops/*.json <<'EOF'
import datetime as dt
import json
import sys

today = dt.datetime.now(dt.UTC).replace(hour=0, minute=0, second=0, microsecond=0)
for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    lic_findings = [f for f in doc.get("findings") or [] if f.get("rule_id") == "VT-LIC-001"]
    lic = (doc.get("health") or {}).get("license")
    if not lic_findings and not lic:
        continue
    # With a VT-LIC-001 finding keep its days_remaining; without one, stay well clear of its 90-day window.
    days = next((f["evidence"].get("days_remaining") for f in lic_findings if f.get("evidence")), None) or 365
    expiry = today + dt.timedelta(days=days)
    stamp = expiry.strftime("%Y-%m-%dT%H:%M:%SZ")
    for f in lic_findings:
        old = f["evidence"]["expiration_time"][:10]
        f["evidence"]["expiration_time"] = stamp
        f["detail"] = f["detail"].replace(old, stamp[:10])
    if lic:
        for key in ("expiration_time", "termination_time"):
            if lic.get(key):
                lic[key] = stamp
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
EOF
