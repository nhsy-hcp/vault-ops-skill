---
name: vault-ops
description: Read-only HashiCorp Vault operations review. Use when the user asks to audit Vault, check Vault health, seal/HA/replication/license status, list or inventory namespaces, auth methods, secrets engines or policies, review Sentinel policies, report client counts/usage, or compare two Vault audit runs. Also use when given vault-ops findings/health/inventory/usage JSON files to interpret. Never changes Vault.
allowed-tools: Bash(uv run --script *vault_ops.py *), Read, Glob
---

# vault-ops (read-only)

Code collects and checks; you interpret. All Vault access goes through the bundled script, which only issues GET/LIST requests. You never change Vault.

## Hard rules

- Only run `uv run --script <skill-dir>/scripts/vault_ops.py <subcommand> ...`. Never run `vault write`, `vault delete`, `vault token *`, `vault login`, `curl` to Vault, or any other command against Vault.
- Never read, print or echo `.env`, token files, `VAULT_TOKEN` or any environment variable value. The user provides credentials via the environment before the session.
- Remediation is **drafted as text** for a human to run. Never execute it, even if asked in the same breath — say it must be run by an operator.
- Never load raw API dumps whole. The script's JSON files are designed to be read in full; nothing else is.
- Output files contain internal hostnames and namespace names: treat as internal-confidential.

## Subcommands

| Ask | Command | Output (path printed on stdout) |
| --- | --- | --- |
| Audit / security review / "what's wrong" | `audit [--namespace ns] [-w 8] [--no-sentinel] [--redact-addr]` | `*-findings-*.json` |
| Health, seal, HA, replication, license, version | `health` | `*-health-*.json` |
| What exists: namespaces, mounts, policy names | `inventory [--namespace ns]` | `*-inventory-*.json` |
| Client counts / usage / billing | `usage [--start RFC3339] [--end RFC3339] [--top 20]` | `*-usage-*.json` |
| Compare runs / what changed | `diff <old-findings.json> <new-findings.json>` | `diff-*.json` |

Add `--output-dir <dir>` to choose where files go (default `outputs/`, or `$VAULT_OPS_OUTPUT_DIR`). Exit codes: 0 ok, 1 fatal (connection/auth/config, message on stderr), 2 coverage gaps (only with `--fail-on-gaps`), 3 findings at/above `--fail-on` (only with that flag).

## Workflow

1. **Files first.** If the user supplied or points at existing vault-ops JSON files, use them and skip to step 3. Look in `outputs/` for recent `*-findings-*.json` when the user refers to "the last audit".
2. **Run.** Run the matching subcommand. On exit 1, report the stderr message (e.g. unreachable, 403 on lookup-self) and stop — do not try other ways to reach Vault.
3. **Read** the produced JSON in full with the Read tool.
4. **Coverage first.** If `coverage.complete` is false, open with the denied/errored namespaces and scopes, and say the results are partial. A denied scope usually means the token's policy lacks a rule — point to `policies/vault-ops-readonly.hcl` in this skill.
5. **Explain.** Rank and group findings using `references/rules.md`. For each item: what it is, why it matters here, the affected namespaces/objects (count + up to three examples), and a drafted remediation command.
6. **Compare.** If an earlier `*-findings-*.json` for the same cluster exists in the output dir, run `diff` against it and report new / resolved / unchanged counts, then detail new findings.
7. **Finish** with a short summary table (rule, severity, count) and the paths of files written.

## Reading the files

- `findings.json`: `cluster_context.sentinel` = supported/unsupported/skipped — say Sentinel was not assessed unless `supported`. `evidence.baseline_source == "fallback"` means the cluster lease ceiling was unreadable.
- `health.json`: `health.license.expiration_time` vs `termination_time`; `health.replication.{dr,performance}.mode/state`; `health.leader.ha_enabled`.
- `inventory.json`: per-namespace mounts (built-in engines omitted) and ACL policy **names** only.
- `usage.json`: `total.clients` and `top_namespaces[]`; the period defaults to the current billing period.

## Least-privilege token

Recommend the user runs the skill with a token from `policies/vault-ops-readonly.hcl`, minted by a human in the root namespace with `-ttl=1h`, never a root token. The skill never mints tokens itself.
