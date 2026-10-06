---
type: llm
---

The saved files are a primary health file, and health, findings and inventory files from a performance secondary (`performance_secondary: true`). The response:
1. Says replication to the secondary that serves traffic is healthy: `vault-pr` is connected and the secondary is in `stream-wals`. The disconnected-peer finding (VT-HLTH-002) is about `vault-pr-stale` only, and the response doesn't call `vault-pr` broken because of it.
2. Says an audit on a performance secondary is valid: it serves authenticated reads, unlike a DR secondary. It notes that the secondary's view can legitimately differ from the primary's.
3. Explains the missing namespaces with the paths filter (VT-REPL-005: `deny` on `tn009/` for `vault-pr`), not with a permissions or coverage problem.
4. Explains `vault-pr-stale` (VT-REPL-002) as a known secondary with no heartbeat: an unused activation token or a secondary removed without `revoke-secondary`, or one that has been down since the primary restarted. It says to confirm with the team before revoking it.
5. Makes no changes and never recommends promote, demote or failover. Any `revoke-secondary` or filter command is drafted for a human to run, not run.
