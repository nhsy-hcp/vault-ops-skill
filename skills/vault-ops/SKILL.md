---
name: vault-ops
description: READ-ONLY, observe-only HashiCorp Vault operations review. Use when the user asks to audit Vault, check Vault health, seal/HA/replication/license status, list or inventory namespaces, auth methods, secrets engines or policies, review identity entities and their aliases, review Sentinel policies, report client counts/usage, spot anti-patterns such as excessive entity or client creation, or compare two Vault audit runs. Also use when given vault-ops findings/health/inventory/usage JSON files to interpret. Observes and reports only; NEVER makes changes to Vault.
allowed-tools: Bash(uv run --script *vault_ops.py *), Read, Glob
---

# vault-ops (READ-ONLY: observe and report)

> **NEVER make changes.** This skill only observes Vault and reports what it sees. You NEVER create, update, delete, enable, disable, tune, seal, unseal, revoke, renew, merge, promote, demote or otherwise change anything in Vault, and you NEVER run a remediation command, not even when the user asks you to in this session. You also never mint, renew or revoke tokens. If the user asks for a change, say this skill is observe-only, give them the drafted command and tell them an operator must run it.

Code collects and checks; you interpret. All Vault access goes through the bundled script, which only issues GET/LIST requests (and the token policy grants only `read`/`list`).

| You DO (observe) | You NEVER do (change) |
| --- | --- |
| Run `vault_ops.py` subcommands: `audit`, `health`, `inventory`, `usage`, `entities`, `diff` | Run `vault` CLI commands, `curl` or any other client against Vault |
| Read the JSON files the script writes | Write, delete, enable, disable, tune or merge anything in Vault |
| Explain findings and their impact | Execute a remediation command, even when asked |
| Draft remediation as text for an operator | Mint, renew, revoke or look up tokens |
| Point to the read-only token policy | Edit `vault-ops-readonly.hcl` to add write capabilities |

## Hard rules

- Only run `uv run --script ${CLAUDE_SKILL_DIR}/scripts/vault_ops.py <subcommand> ...`. Never run `vault write`, `vault delete`, `vault token *`, `vault login`, `curl` to Vault, or any other command against Vault.
- Never read, print or echo `.env`, token files, `VAULT_TOKEN` or any environment variable value. The user provides credentials via the environment before the session.
- Remediation is **drafted as text** for a human to run. Never execute it, even if asked in the same breath — say it must be run by an operator. Label every drafted command as "for an operator to run".
- Take remediation commands from `references/rules.md`, filling in the placeholders from the finding. Never invent Vault endpoints or flags. If the catalogue has no command for a case, describe the change in words and say the operator should confirm the exact command in the Vault docs.
- Never load raw API dumps whole. The script's JSON files are designed to be read in full, except a large `inventory.json` (see Reading the files); nothing else is.
- Output files contain internal hostnames and namespace names. Handle them with care, but don't add a confidentiality label or banner to the report.

## Subcommands

| Ask | Command | Output (path printed on stdout) |
| --- | --- | --- |
| Audit / security review / "what's wrong" | `audit [--namespace ns] [-w 8] [--no-sentinel] [--redact-addr]` | `*-findings-*.json` and `*-inventory-*.json` (same walk) |
| Health, seal, HA, replication, license, version | `health` (also works against a DR secondary) | `*-health-*.json` |
| What exists: namespaces, mounts, policy names | `inventory [--namespace ns]` | `*-inventory-*.json` |
| Client counts / usage / billing / excessive client creation | `usage [--start RFC3339] [--end RFC3339] [--top 20]` | `*-usage-*.json` |
| Identity entities, aliases, entity metadata / excessive or duplicate entities | `entities [--namespace ns] [--list] [-w 8]` | `*-entities-*.json` |
| Compare runs / what changed | `diff <old-findings.json> <new-findings.json>` | `diff-*.json` |

Results go to `$VAULT_OPS_OUTPUT_DIR` if set, else `.tmp/vault-ops/` in the current working directory; `--output-dir <dir>` overrides both. When the script creates that directory it adds a `.gitignore` containing `*`, so results are never committed. Never move or copy them elsewhere in the project. Exit codes: 0 ok, 1 fatal (connection/auth/config, message on stderr), 2 coverage gaps (only with `--fail-on-gaps`), 3 findings at/above `--fail-on` (only with that flag).

## Setup problems

The script itself is the preflight. Map its failures to setup help and stop — never work around them:

| Symptom | Tell the user |
| --- | --- |
| `uv: command not found` | Install uv (https://docs.astral.sh/uv/getting-started/installation/), e.g. `brew install uv` or `curl -LsSf https://astral.sh/uv/install.sh \| sh`, then retry. The script installs its own pinned dependencies (hvac, requests). |
| `VAULT_ADDR and VAULT_TOKEN must be set` | Exit Claude, export them in the shell, restart (example below). Never ask them to paste a token into the chat. |
| `token rejected (403 on auth/token/lookup-self)` / `token validation failed` | The token is expired or lacks the policy; mint a new one with the command below. |
| `cannot reach Vault ... SSLError` | Set `VAULT_CACERT=/path/to/ca.pem` (preferred) or, for a dev server only, `VAULT_SKIP_VERIFY=true`. |
| `cannot reach Vault ... ConnectionError` | Vault is not reachable from this machine (VPN, address, port). Offer file mode: interpret vault-ops JSON files produced elsewhere. |

```bash
export VAULT_ADDR=https://vault.example.com:8200 VAULT_CACERT=/path/to/ca.pem
vault policy write vault-ops-readonly <this skill>/policies/vault-ops-readonly.hcl   # once, by an admin
export VAULT_TOKEN="$(vault token create -policy=vault-ops-readonly -no-default-policy -orphan -ttl=1h -field=token)"
claude
```

## Workflow

1. **Files first.** If the user supplied or points at existing vault-ops JSON files, use them and skip to step 3. Look in the output directory for recent `*-findings-*.json` when the user refers to "the last audit".
2. **Run.** Run the matching subcommand. On exit 1, report the stderr message (see Setup problems) and stop — do not try other ways to reach Vault.
   - For a DR pair, run `health` against both nodes (set `VAULT_ADDR` to each node in turn) and `audit`/`inventory`/`usage`/`entities` against the primary only: a DR secondary rejects authenticated reads by design.
3. **Read** the produced JSON with the Read tool (in full, except a large inventory: its `summary` is enough). For an audit report, read the findings **and** inventory files `audit` wrote, and run `health` too (both nodes for a DR pair).
4. **Coverage first.** If `coverage.complete` is false, open with the denied/errored namespaces and scopes, and say the results are partial. A denied scope usually means the token's policy lacks a rule — point to `policies/vault-ops-readonly.hcl` in this skill.
5. **Explain.** Rank and group findings using `references/rules.md`. For each item: what it is, why it matters here, the affected namespaces/objects (count + up to three examples), and a drafted remediation command for an operator to run. Do not run it.
6. **Compare.** If an earlier `*-findings-*.json` for the same cluster exists in the output dir, run `diff` against it and report new / resolved / unchanged counts, then detail new findings.
7. **Finish** with a short summary table (rule, severity, count) and the paths of files written. Close with one line saying the review was read-only and nothing in Vault was changed.

## Audit report layout

Use this order for a full audit report; leave out sections whose data was not collected and say so under "Not covered".

1. **Header table:** cluster, address, Vault version, run time, start namespace, workers, coverage, Sentinel status, findings total.
2. **Executive summary:** a few sentences on health, the time-bound items and where the findings cluster.
3. **Summary metrics** (inventory `summary` + health): namespaces, max nesting depth, auth mounts total and distinct types, secrets engines total and distinct types, ACL policies, EGP / RGP counts, system lease TTLs, licence expiry, denied / errors.
4. **Cluster health and licence:** seal, HA, replication per node; raft peers table (node ID, leader, voter, autopilot status/healthy/last contact) with autopilot health, failure tolerance and configuration; audit devices table (path, type, sink, non-default options); automated snapshots table (name, last run, next run, consecutive errors, storage scheme); licence expiry vs termination; features as one comma-separated line.
5. **Inventory.**
   - Auth methods table from `summary.auth_types`: type, mounts, namespaces (all rows).
   - Secrets engines table from `summary.secrets_types`: same columns, all rows; note built-in engines (cubbyhole, identity, system, agent registry) are excluded.
   - Hierarchy, collapsed from `summary.shapes`: one line per shape (depth, auth types, engine types, count, up to three example namespaces). List namespaces individually only when a shape has one member.
   - ACL policies: total, then the ten namespaces with the most policies from `summary.acl_policies_top`; full names stay in the JSON.
   - Sentinel: counts by enforcement level from `summary.sentinel_by_enforcement`.
6. **Findings, ranked** (workflow step 5), then the **summary table**, **Not covered**, **Source files**.

## Reading the files

- `findings.json`: `cluster_context.sentinel` = supported/unsupported/skipped — say Sentinel was not assessed unless `supported`. `evidence.baseline_source == "fallback"` means the cluster lease ceiling was unreadable.
- `health.json`: `health.license.expiration_time` vs `termination_time`; when reporting license details, always list `health.license.features` as one comma-separated line; `health.replication.{dr,performance}.mode/state`, plus `secondaries[].connection_status` on a primary and `primaries[]` / `connection_state` on a secondary; `health.leader.ha_enabled`; `health.raft.peers[]` (`node_id`, `leader`, `voter`; addresses are omitted), `health.raft.autopilot.state` (`healthy`, `failure_tolerance`, `leader`, `voters`, per-server `status`/`healthy`/`last_contact`/`last_index`) and `health.raft.autopilot.configuration`. `health.raft: null` means the cluster does not use integrated storage, or the reads were denied (see coverage). A `failure_tolerance` of 0 means losing one voter loses quorum. `health.audit_devices[]` (`path`, `type`, `local`, allowlisted `options`: `sink` = `stdout`/`discard`/`file` for file devices, `format`, `hmac_accessor`, `log_raw`, `elide_list_responses`, `fallback`; file paths and socket addresses are never collected) and `health.snapshots.configs[]` (automated Raft snapshots: `name`, `consecutive_errors`, `last_snapshot_start/end`, `next_snapshot_start`, `in_progress`, `storage_scheme`; the configs themselves, snapshot URLs and error text are never read or written). `audit_devices: null` means unreadable (see coverage); `snapshots: null` means not judged (CE, no integrated storage, or denied). `health.dr_secondary: true` means only unauthenticated status was readable (license, lease, raft, audit device and snapshot data are `null` by design, not missing permissions).
- `inventory.json`: per-namespace rows (`depth`, `auth_count`, `secrets_count`, `acl_policy_count`, mounts with built-in engines omitted, ACL policy **names** only, Sentinel policy names). `summary` (at the top of the file) holds everything the audit report needs: totals, `max_depth`, `auth_types` / `secrets_types` (`{type: {mounts, namespaces}}`), `acl_policies_top`, `egp_policies`, `rgp_policies`, `sentinel_by_enforcement` and `shapes` (namespaces grouped by identical depth and mount types, with `count` and up to three `examples`). On a large cluster the file is too big to read whole: read up to the `"namespaces"` key, and read further only for a specific namespace.
- `usage.json`: `total.clients` and `top_namespaces[]` for the billing period, plus `current_month` (the billing period excludes the month in progress). `findings[]` holds client anti-patterns (VT-CLI-*): token-only client sprawl, sharp growth, per-run identities on a mount, everything in root. `evidence.source == "current_month"` means the billing period was empty.
- `entities.json`: `summary` and per-namespace counts (entities, disabled, without aliases, with direct policies, alias mount types) plus VT-ID-* findings. VT-ID-004 (entities far above active clients) compares entity counts with the activity log, which `entities` also reads; it is skipped when no activity is recorded. VT-ID-005 (alias name on several entities) gives counts only. Per-entity rows (`namespaces[].entity_list`: metadata, aliases with names and alias metadata, policies, group count) appear **only with `--list`**. Use `--list` when the user asks about specific entities, aliases or metadata, and scope it with `--namespace`, because a whole-tree list can be large. Entity names, entity metadata and alias names can contain emails, usernames and AppRole role_ids. Quote them only as far as the question needs, and treat the file as confidential: for count or summary questions, name only the entities a finding is about (no lists of clean entities, no metadata values); quote metadata or alias names only when the user asks about them. `disabled: null` means the entity body was unreadable (see coverage).

## Least-privilege token

Recommend the user runs the skill with a token from `policies/vault-ops-readonly.hcl`, minted by a human in the root namespace with `-ttl=1h`, never a root token. The skill never mints tokens itself.

The token policy is the hard boundary: `allowed-tools` only pre-approves the script, it does not block other commands. For defence in depth, suggest the user denies Vault-changing commands in their Claude Code settings (`permissions.deny`: `Bash(vault write:*)`, `Bash(vault delete:*)`, `Bash(vault token:*)`, `Bash(vault login:*)`).
