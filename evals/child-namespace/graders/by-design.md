---
type: llm
---

The results come from a token that lives in a child namespace (`run.token_namespace: "admin/"`), with complete coverage and nothing denied. The response:
1. Explains the null licence, raft, lease TTL, audit device, snapshot and metrics data as expected for a child-namespace token: those cluster-level endpoints are readable only from the root namespace, so the collector skips them by design. It is not a permissions gap in the token or in `vault-ops-readonly`.
2. Does not tell the user to add capabilities to `vault-ops-readonly` or to enable an audit device or snapshots from this token; it says cluster-level settings are owned by whoever administers the root namespace (on a managed platform such as HCP Vault Dedicated, the platform), and that a root-namespace token is needed to review them.
3. Reports what was checked: the `admin/` namespace tree (e.g. VT-NS-001 findings) and the replication status findings (VT-HLTH-002 / VT-REPL-002).
