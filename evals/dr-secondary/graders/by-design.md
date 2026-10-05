---
type: llm
---

The health file is from a DR secondary (`dr_secondary: true`), where only unauthenticated status is readable. The response:
1. Explains the null licence, raft, lease, audit device and snapshot data as expected on a DR secondary (it rejects authenticated requests by design), not as a permissions problem with the token.
2. Advises against running audit / inventory / usage / entities on the DR node and says to run them against the primary instead.
3. Reports what is available: DR secondary replication mode/state and the node being unsealed.
