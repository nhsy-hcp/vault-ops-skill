---
type: llm
---

The health file is from the node at http://127.0.0.1:8230 (Vault 2.1.1, Community) and has `health.sealed: true`, finding VT-HLTH-001, `health.seal` = Shamir, unseal threshold 1 of 1 key share, progress 0, and complete coverage. Leader, license, replication, Raft, audit device, snapshot and metrics blocks are `null`, and `cluster_name` is the placeholder `vault` because a sealed node doesn't report its name. The response:
1. Says plainly that the node is not healthy because it is sealed (VT-HLTH-001), so it can't serve requests until it is unsealed.
2. Reports the unseal state from `health.seal`: Shamir, 1 of 1 key share needed, no unseal in progress (progress 0).
3. Explains that the other blocks are empty because the node is sealed (only unauthenticated status is readable), not because of missing permissions, an expired token or a coverage gap.
4. Identifies the node by its address (127.0.0.1:8230) and does not present `vault` as the real cluster name.
5. Does not claim license, replication, Raft or audit details it can't see, and does not call the cluster healthy.
