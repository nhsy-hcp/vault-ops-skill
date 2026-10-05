# vault-ops skill

> **READ-ONLY. Observe and report only: this skill NEVER makes changes to Vault.** It never writes, deletes, enables, tunes or merges anything, never mints or revokes tokens, and never runs the fixes it drafts. An operator runs them.

A read-only HashiCorp Vault operations review for Claude Code. Ask Claude to audit Vault, check health and DR status, inventory namespaces and mounts, review identity entities, assess ACL policy permissions, count clients, or compare two audits. A bundled script reads Vault (GET/LIST only) and writes small JSON files. Claude reads those files, explains them and drafts fixes as text. It never changes Vault.

## Prerequisites

- [Claude Code](https://code.claude.com)
- [uv](https://docs.astral.sh/uv/getting-started/installation/): the script runs with `uv run --script` and installs its pinned dependencies (`hvac`, `requests`) on first use
- Network access from your machine to Vault (Enterprise for namespaces, Sentinel and DR; Community works with fewer checks)
- A short-lived token from the bundled read-only policy, never a root token

## Install

```text
/plugin marketplace add nhsy-hcp/vault-ops-skill
/plugin install vault-ops@vault-ops-skill
```

## Setup

An admin loads the policy once (root namespace):

```bash
vault policy write vault-ops-readonly policies/vault-ops-readonly.hcl
```

For a policy permission review, also load the read-only add-on and add `-policy=vault-ops-policy-reader` to the token below:

```bash
vault policy write vault-ops-policy-reader policies/vault-ops-policy-reader.hcl
```

Each session, export the environment and start Claude:

```bash
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_CACERT=/path/to/ca.pem
export VAULT_TOKEN="$(vault token create -policy=vault-ops-readonly -no-default-policy -orphan -ttl=1h -field=token)"
claude
```

| Variable | Required | Purpose |
| --- | --- | --- |
| `VAULT_ADDR` | yes | Vault address |
| `VAULT_TOKEN` | yes | Token from `vault-ops-readonly` (1h TTL recommended) |
| `VAULT_CACERT` | recommended | CA bundle for TLS verification |
| `VAULT_SKIP_VERIFY` | dev only | `true` disables TLS verification |
| `VAULT_NAMESPACE` | no | Namespace to start `audit` / `inventory` / `entities` from (default: root) |
| `VAULT_OPS_OUTPUT_DIR` | no | Where results are written (default `.tmp/vault-ops/` in the working directory) |

Credentials only ever come from the environment. The skill never asks for a token, never reads `.env` or token files, and never mints tokens.

## Permissions

When Claude first runs the script, approve the prompt, or allow it permanently in your settings: `"permissions": {"allow": ["Bash(uv run --script *vault_ops.py *)"]}`.

For non-interactive runs (`claude -p`, CI), grant the skill and its script explicitly:

```bash
claude -p "Is my vault healthy?" \
  --allowedTools "Skill(vault-ops:vault-ops)" "Bash(uv run --script *vault_ops.py *)" "Read"
```

## Example prompts

- "Audit my vault"
- "Is the cluster healthy? Check DR on both nodes." (set the DR node address when asked)
- "What's configured in tn001?"
- "How many clients this month?"
- "Show the entities and their aliases in team-a/prod"
- "What changed since the last audit?"
- "Are we creating too many entities or clients?"
- "Are there any policies with excessive permissions?" (needs the policy-reader add-on)

## Safety

- **Hard boundary:** the token policy. It grants `read`/`list` only and never exposes ACL policy bodies. The two exact list paths, `sys/audit` and `sys/storage/raft/snapshot-auto/config`, also get `sudo` because Vault protects them; neither grants writes, and snapshot configs (which hold storage credentials) stay unreadable.
- **`allowed-tools` doesn't block:** it pre-approves the bundled script but doesn't block other commands. For defence in depth, add deny rules to your Claude Code settings:
  ```json
  { "permissions": { "deny": ["Bash(vault write:*)", "Bash(vault delete:*)", "Bash(vault token:*)", "Bash(vault login:*)"] } }
  ```
- **Results files:** written 0600 under `.tmp/vault-ops/` in the working directory (directory 0700). A directory the script creates gets a `.gitignore` containing `*`, so results are never committed. They contain internal hostnames and namespace names. `entities --list` adds entity metadata and alias names (emails, usernames, AppRole role_ids). Treat them as confidential.
- **Fixes:** remediation is drafted for an operator to run, never executed, even when you ask Claude to apply it.

## What's inside

| Path | Contents |
| --- | --- |
| `SKILL.md` | Instructions Claude follows |
| `scripts/vault_ops.py` | Read-only collector (`audit`, `health`, `inventory`, `usage`, `entities`, `policies`, `diff`) |
| `policies/vault-ops-readonly.hcl` | Least-privilege policy |
| `policies/vault-ops-policy-reader.hcl` | Optional add-on for `policies`: read-only access to ACL policy bodies |
| `references/rules.md` | Rule catalogue (VT-*) with remediation |
| `schemas/findings.schema.json` | JSON Schema for findings files |

License: MPL-2.0.
