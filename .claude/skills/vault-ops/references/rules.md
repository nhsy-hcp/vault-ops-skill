# Rule catalogue and remediation

Each rule ID is permanent. Remediation is **drafted for a human to run** — never execute it. Replace `<ns>`, `<path>`, `<name>` from the finding's `namespace` and `object`. For a child namespace, prefix commands with `VAULT_NAMESPACE=<ns>` (or `-namespace=<ns>`).

| rule_id | Sev | What it means | Draft remediation | Watch out for |
| --- | --- | --- | --- | --- |
| VT-MOUNT-001 | medium | Mount runs a plugin marked `deprecated` / `pending-removal` / `removed` (`evidence.deprecation_status`). | Plan migration to the replacement engine; enable it alongside, migrate clients, then `vault secrets disable <path>` / `vault auth disable <path>` in a change window. | `removed` plugins stop working on upgrade — check before any Vault upgrade. |
| VT-AUTH-001 | low | Auth mount is listed in the UI login page for unauthenticated callers. | `vault auth tune -listing-visibility=hidden <path>` | Harmless for public login methods (e.g. OIDC) that users must see; confirm intent before changing. |
| VT-MOUNT-002 | low | Mount `max_lease_ttl` exceeds the cluster ceiling (`evidence.baseline_source`: `cluster` or `fallback` 768h). | `vault secrets tune -max-lease-ttl=<baseline> <path>` (auth: `vault auth tune -max-lease-ttl=<baseline> <path>`) | Existing leases keep their TTL; lowering it affects new leases/renewals only. If `baseline_source=fallback`, the token could not read `sys/config/state/sanitized` — say so. |
| VT-MOUNT-003 | info | Mount is `local`: not replicated to performance secondaries / DR. | Usually intentional (per-cluster data). If not, data must be recreated on a replicated mount — `local` cannot be changed after enable. | Only meaningful when replication is in use (see health). |
| VT-NS-001 | info | Namespace has only the token auth backend. | If users/apps should log in here, enable an auth method (`vault auth enable -namespace=<ns> oidc`); otherwise accept — child namespaces often rely on parent auth + entity groups. | Normal for admin-boundary namespaces (e.g. tenant roots). |
| VT-NS-002 | info | Leaf namespace with only built-in engines and no children — appears unused. | Confirm with the owner; if unused, `vault namespace delete -namespace=<parent> <name>` in a change window. | Deletion is irreversible and removes everything inside; never suggest without owner confirmation. |
| VT-SNT-001 | low | Sentinel policy is `advisory`: logs, never blocks. | `vault write sys/policies/<egp\|rgp>/<name> enforcement_level=soft-mandatory policy=@<file> [paths=...]` after testing. | Raising enforcement can block traffic; test in a lower environment first. |
| VT-SNT-002 | info | Sentinel policy is `soft-mandatory`: a sudo token can override. | Consider `hard-mandatory` if overrides are not part of the operating model. | Same blocking risk as above. |
| VT-SNT-003 | info | EGP path is `*` — applies to every request in the namespace. | Narrow `paths` to the endpoints the policy governs. | A hard-mandatory wildcard EGP that can evaluate false locks out everyone, including admins. |
| VT-SNT-004 | low | Sentinel policy body always evaluates true (`main = rule { true }`). | Replace with a real rule or delete the policy (`vault delete sys/policies/<kind>/<name>`). | It looks like a control in policy lists but enforces nothing. |
| VT-LIC-001 | medium | License expires within 90 days (`evidence.days_remaining`). | Obtain a renewed license, update it on every node (`license_path` / `VAULT_LICENSE_PATH` / `VAULT_LICENSE`), then run `vault license reload` (or restart). | After expiry there is a grace period before termination; check `termination_time` in health output. |
| VT-HLTH-001 | medium | Node sealed, or HA enabled with no active leader. | Sealed: unseal per runbook (auto-unseal: check KMS reachability). No leader: check raft peers `vault operator raft list-peers` and logs. | Run checks against each node; one sealed standby may be fine behind a load balancer. |
| VT-HLTH-002 | medium | DR/performance replication enabled but state not healthy (`evidence.state`). | `vault read sys/replication/<dr\|performance>/status` on both clusters; check network, secondary tokens, WAL gaps. | Read-only investigation only; never suggest `demote`/`promote` without an incident runbook. |
| VT-HLTH-003 | info | Vault version older than the supported window (`evidence.min_supported`). | Plan an upgrade path following HashiCorp's upgrade guides (step through required intermediate versions). | `min_supported` is a constant in the script — may be stale. |

## Severity ranking guidance

Rank for the environment, not just by severity label:

1. `coverage.complete == false` comes first — every conclusion is partial.
2. VT-HLTH-001/002 and VT-LIC-001 (cluster-wide availability and lifecycle).
3. VT-MOUNT-001 (breaks on upgrade), VT-SNT-004/001 (controls that don't control).
4. VT-AUTH-001, VT-MOUNT-002 grouped by mount type.
5. Info rules — summarise counts, list examples, don't enumerate hundreds.

Group repetitive findings (same rule, same mount type across many namespaces) into one item with a count and three examples.
