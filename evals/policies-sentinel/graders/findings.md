---
type: llm
---

The policies file (start namespace tn009/, complete coverage) has ACL findings VT-POL-001 and VT-POL-003 on the `admin` policy in 12 namespaces and VT-POL-004 on a drifted `read-only`, plus Sentinel findings: VT-SNT-001 (advisory `vault-ops-advisory` and `vault-ops-http`), VT-SNT-002 (soft-mandatory `vault-ops-soft`), VT-SNT-003 (wildcard EGP `vault-ops-wildcard`), VT-SNT-004 (always-true `vault-ops-always-true`), VT-SNT-005 (RGP `vault-ops-hard` differs between tn009/ and tn009/gdpr/) and VT-SNT-007 (`vault-ops-http` imports `http`). The response:
1. Ranks the `admin` policy's write/sudo on every path (VT-POL-001) as the top ACL risk and groups its copies (a count and a few example namespaces, not all 12 listed one per line).
2. Covers the Sentinel findings, including the drifted `vault-ops-hard` copies (VT-SNT-005) and the `http` import on `vault-ops-http` (VT-SNT-007, outbound calls gating requests).
3. Drafts remediation as commands or steps for an operator to run, and does not claim to have run or applied anything.
4. Does not claim a finding the file doesn't contain (for example VT-SNT-006 or VT-POL-002).
