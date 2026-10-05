# vault-ops-skill

A read-only HashiCorp Vault operations skill for Claude Code. It audits a namespace tree, checks cluster health, inventories mounts and policies, reports client usage, and compares audit runs. All Vault access goes through one bundled script that only issues GET/LIST requests; Claude interprets the JSON it writes and drafts remediation as text for a human to run.

Check logic is ported from [nhsy-hcp/vault-tools](https://github.com/nhsy-hcp/vault-tools) `namespace-audit`.

## Using the skill

Open Claude Code in this repo with `VAULT_ADDR` and a least-privilege `VAULT_TOKEN` in the environment, then ask, for example:

- "Audit my Vault" / "what's wrong with our namespaces?"
- "Is the cluster healthy? When does the license expire?"
- "Inventory namespaces and auth methods under tn001"
- "How many clients did we have this month?"
- "Show the entities and their aliases in tn001"
- "What changed since the last audit?"

The skill reports coverage gaps first, ranks and groups findings, and drafts remediation commands without running them.

### Script subcommands

```bash
uv run --script .claude/skills/vault-ops/scripts/vault_ops.py <command> [--output-dir outputs]
```

| Command | Output | Notes |
| --- | --- | --- |
| `audit` | `{cluster}-findings-{ts}.json` | `--namespace`, `-w/--workers`, `--no-sentinel`, `--redact-addr`, `--fail-on {medium,low,info}`, `--fail-on-gaps` |
| `health` | `{cluster}-health-{ts}.json` | seal, HA leader, version, license, replication, lease ceilings |
| `inventory` | `{cluster}-inventory-{ts}.json` | namespaces, non-built-in mounts, ACL policy **names** |
| `usage` | `{cluster}-usage-{ts}.json` | billing-period client counts plus `current_month` |
| `entities` | `{cluster}-entities-{ts}.json` | per-namespace entity counts and findings; `--list` adds metadata, aliases and policies per entity |
| `diff OLD NEW` | `diff-{ts}.json` | new / resolved / unchanged findings by fingerprint |

Environment: `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, `VAULT_SKIP_VERIFY`, `VAULT_CACERT`, `VAULT_OPS_OUTPUT_DIR`. Files are written 0600; stdout carries only their paths.

### Rules

| Rule | Severity | Checks |
| --- | --- | --- |
| VT-MOUNT-001 | medium | Plugin deprecated / pending removal |
| VT-AUTH-001 | low | Auth mount listed to unauthenticated callers |
| VT-MOUNT-002 | low | Mount max lease TTL above the cluster ceiling |
| VT-MOUNT-003 | info | Local (non-replicated) mount |
| VT-NS-001 | info | Namespace with no auth beyond token |
| VT-NS-002 | info | Unused leaf namespace |
| VT-SNT-001..004 | low/info | Sentinel advisory, soft-mandatory, wildcard EGP, always-true |
| VT-LIC-001 | medium | License expires within 90 days |
| VT-HLTH-001..003 | medium/info | Sealed / no leader, unhealthy replication, unsupported version |
| VT-ID-001..003 | low/info | Entity without aliases, policies attached directly to an entity, disabled entity |

Details and remediation: [`references/rules.md`](.claude/skills/vault-ops/references/rules.md). Schema: [`findings.schema.json`](.claude/skills/vault-ops/schemas/findings.schema.json).

### Least-privilege token

```bash
vault policy write vault-ops-readonly .claude/skills/vault-ops/policies/vault-ops-readonly.hcl
vault token create -policy=vault-ops-readonly -no-default-policy -orphan -ttl=1h -explicit-max-ttl=1h
```

The policy is read/list only and never grants reading ACL policy bodies.

## Local development

Requires [task](https://taskfile.dev), [uv](https://docs.astral.sh/uv/), the `vault` CLI, podman or Docker, `jq`, `openssl`, `gitleaks`, `shellcheck` and `pre-commit`, plus a Vault Enterprise license in `.env`.

```bash
task init && task deps    # one-time setup, then validate the environment
task up:all               # primary https://127.0.0.1:8210 + DR node https://127.0.0.1:8220 (raft, TLS)
task seed && task seed:findings && task token:audit
task dr:enable            # DR replication primary -> secondary
task skill:run -- audit   # run the skill script with the read-only token
task test:all && task lint
```

- DR setup, node lifecycle and failure drills: [docs/dr.md](docs/dr.md)
- All tasks and repo conventions: [AGENTS.md](AGENTS.md)
