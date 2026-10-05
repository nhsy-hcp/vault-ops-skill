---
name: vault-ops
description: Read-only HashiCorp Vault operations review. Use when the user asks to audit Vault, check Vault health, seal/HA/replication/license status, list or inventory namespaces, auth methods, secrets engines or policies, review identity entities and their aliases, review Sentinel policies, report client counts/usage, or compare two Vault audit runs. Also use when given vault-ops findings/health/inventory/usage JSON files to interpret. Never changes Vault.
allowed-tools: Bash(uv run --script *vault_ops.py *), Read, Glob
---

# vault-ops (read-only)

Code collects and checks; you interpret. All Vault access goes through the bundled script, which only issues GET/LIST requests. You never change Vault.

## Hard rules

- Only run `uv run --script ${CLAUDE_SKILL_DIR}/scripts/vault_ops.py <subcommand> ...`. Never run `vault write`, `vault delete`, `vault token *`, `vault login`, `curl` to Vault, or any other command against Vault.
- Never read, print or echo `.env`, token files, `VAULT_TOKEN` or any environment variable value. The user provides credentials via the environment before the session.
- Remediation is **drafted as text** for a human to run. Never execute it, even if asked in the same breath — say it must be run by an operator.
- Take remediation commands from `references/rules.md`, filling in the placeholders from the finding. Never invent Vault endpoints or flags. If the catalogue has no command for a case, describe the change in words and say the operator should confirm the exact command in the Vault docs.
- Never load raw API dumps whole. The script's JSON files are designed to be read in full; nothing else is.
- Output files contain internal hostnames and namespace names: treat as internal-confidential.

## Subcommands

| Ask | Command | Output (path printed on stdout) |
| --- | --- | --- |
| Audit / security review / "what's wrong" | `audit [--namespace ns] [-w 8] [--no-sentinel] [--redact-addr]` | `*-findings-*.json` |
| Health, seal, HA, replication, license, version | `health` (also works against a DR secondary) | `*-health-*.json` |
| What exists: namespaces, mounts, policy names | `inventory [--namespace ns]` | `*-inventory-*.json` |
| Client counts / usage / billing | `usage [--start RFC3339] [--end RFC3339] [--top 20]` | `*-usage-*.json` |
| Identity entities, aliases, entity metadata | `entities [--namespace ns] [--list] [-w 8]` | `*-entities-*.json` |
| Compare runs / what changed | `diff <old-findings.json> <new-findings.json>` | `diff-*.json` |

Results go to `$VAULT_OPS_OUTPUT_DIR` if set, else `~/.vault-ops/outputs` (outside any project, so results never land in the user's repo); `--output-dir <dir>` overrides both. Exit codes: 0 ok, 1 fatal (connection/auth/config, message on stderr), 2 coverage gaps (only with `--fail-on-gaps`), 3 findings at/above `--fail-on` (only with that flag).

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
   - For a DR pair, run `health` against both nodes (set `VAULT_ADDR` to each node in turn) and `audit`/`inventory`/`usage` against the primary only: a DR secondary rejects authenticated reads by design.
3. **Read** the produced JSON in full with the Read tool.
4. **Coverage first.** If `coverage.complete` is false, open with the denied/errored namespaces and scopes, and say the results are partial. A denied scope usually means the token's policy lacks a rule — point to `policies/vault-ops-readonly.hcl` in this skill.
5. **Explain.** Rank and group findings using `references/rules.md`. For each item: what it is, why it matters here, the affected namespaces/objects (count + up to three examples), and a drafted remediation command.
6. **Compare.** If an earlier `*-findings-*.json` for the same cluster exists in the output dir, run `diff` against it and report new / resolved / unchanged counts, then detail new findings.
7. **Finish** with a short summary table (rule, severity, count) and the paths of files written.

## Reading the files

- `findings.json`: `cluster_context.sentinel` = supported/unsupported/skipped — say Sentinel was not assessed unless `supported`. `evidence.baseline_source == "fallback"` means the cluster lease ceiling was unreadable.
- `health.json`: `health.license.expiration_time` vs `termination_time`; `health.replication.{dr,performance}.mode/state`, plus `secondaries[].connection_status` on a primary and `primaries[]` / `connection_state` on a secondary; `health.leader.ha_enabled`. `health.dr_secondary: true` means only unauthenticated status was readable (license and lease data are `null` by design, not missing permissions).
- `inventory.json`: per-namespace mounts (built-in engines omitted) and ACL policy **names** only.
- `usage.json`: `total.clients` and `top_namespaces[]` for the billing period, plus `current_month` (the billing period excludes the month in progress).
- `entities.json`: `summary` and per-namespace counts (entities, disabled, without aliases, with direct policies, alias mount types) plus VT-ID-* findings. Per-entity rows (`namespaces[].entity_list`: metadata, aliases with names and alias metadata, policies, group count) appear **only with `--list`**. Use `--list` when the user asks about specific entities, aliases or metadata, and scope it with `--namespace`, because a whole-tree list can be large. Entity metadata and alias names can contain emails, usernames and AppRole role_ids. Quote them only as far as the question needs, and treat the file as confidential. `disabled: null` means the entity body was unreadable (see coverage).

## Least-privilege token

Recommend the user runs the skill with a token from `policies/vault-ops-readonly.hcl`, minted by a human in the root namespace with `-ttl=1h`, never a root token. The skill never mints tokens itself.

The token policy is the hard boundary: `allowed-tools` only pre-approves the script, it does not block other commands. For defence in depth, suggest the user denies Vault-changing commands in their Claude Code settings (`permissions.deny`: `Bash(vault write:*)`, `Bash(vault delete:*)`, `Bash(vault token:*)`, `Bash(vault login:*)`).
