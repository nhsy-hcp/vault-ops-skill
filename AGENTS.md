# AGENTS.md — vault-ops-skill

Project rules for AI agents. Global rules in `~/.bob/AGENTS.md` still apply; this file adds what is specific to this repo.

## What this repo is

A **read-only** HashiCorp Vault ops Claude skill (`.claude/skills/vault-ops/`) plus a local Vault Enterprise dev environment to build and test it against.

| Path | Purpose |
| --- | --- |
| `.claude/skills/vault-ops/SKILL.md` | Skill workflow and guardrails (what Claude does when the skill triggers) |
| `.claude/skills/vault-ops/scripts/vault_ops.py` | PEP 723 single-file collector: `audit`, `health`, `inventory`, `usage`, `diff` |
| `.claude/skills/vault-ops/schemas/findings.schema.json` | JSON Schema (draft 2020-12) for findings files, `schema_version` 1.1.0 |
| `.claude/skills/vault-ops/references/rules.md` | Rule catalogue (VT-*) with drafted remediation |
| `.claude/skills/vault-ops/policies/vault-ops-readonly.hcl` | Least-privilege Vault policy for the skill's token |
| `scripts/` | Dev-env automation (bash, called from `Taskfile.yml`) and `seed_vault.py` |
| `tests/` | Unit tests (no Vault) and `test_integration.py` (`-m integration`, needs the dev Vault) |
| `.tmp/spec.md` | Options analysis and spec (gitignored working doc) |

## Hard rules

- **Read-only, always.** `vault_ops.py` may only issue GET/LIST requests. Never add a code path that writes to Vault, and never add write capabilities to `vault-ops-readonly.hcl`. ACL policy **bodies** stay unreadable (`list` only).
- **Never use the root token for the skill or the integration tests.** Use `task token:audit` (a 1h token from `vault-ops-readonly.hcl`); `test_integration.py` fails when `VAULT_TOKEN=root`. Root is only for `seed`, `seed:findings` and `token:audit`.
- **`~/Projects/vault-tools` is reference-only.** Port logic from it; never modify it.
- **No secrets in outputs.** Findings and other outputs must never contain tokens, accessors, Sentinel policy source, namespace `custom_metadata` or raw error text. Errors go through `sanitise_error()` (class + HTTP status). Output files are written 0600.
- **Rule IDs are permanent.** Never renumber or reuse a `VT-*` ID. A new rule means adding it to `RULES`, the schema `category` enum if needed, `references/rules.md`, and a fixture that fires it. Adding optional fields is a minor `SCHEMA_VERSION` bump; renaming or removing is a major bump.
- **Script stays single-file with PEP 723 deps** (`hvac`, `requests` only), so the skill runs anywhere with `uv run --script`. Keep the inline deps and `pyproject.toml` in sync.
- **Stdout = written file paths only**; diagnostics go to stderr. Exit codes: 0 ok, 1 fatal, 2 gaps (`--fail-on-gaps`), 3 findings (`--fail-on`), 130 interrupted.

## Task interface

| Task | What it does |
| --- | --- |
| `task init` | `uv sync`, install pre-commit hooks, create `.env` from `.env.template` |
| `task deps` | Check tools, container engine (podman: `podman machine start`), host IP/port, `.env` |
| `task up` / `task down` | Start/stop `vault-primary` (Enterprise `-dev -dev-tls`) at `https://127.0.0.1:8210` |
| `task status` / `task logs` | `vault status`; tail `.tmp/vault/vault-primary/logs/vault.log` |
| `task seed` | `scripts/seed_vault.py`: 132 namespaces, mounts, KV data, client activity (root) |
| `task seed:findings` | Configuration that trips every live-testable rule, plus Sentinel EGP/RGPs (root) |
| `task token:audit` | Write `vault-ops-readonly` policy, mint 1h token to `.tmp/audit-token` (0600) |
| `task skill:run -- <cmd>` | Run `vault_ops.py` with the audit token, e.g. `task skill:run -- audit` |
| `task lint` | pre-commit on tracked + untracked files: ruff, ruff-format, shellcheck, gitleaks, yaml/json |
| `task test` | Unit tests with coverage ≥ 80% |
| `task test:integration` | Integration tests (audit token, live Vault) |
| `task test:all` | Unit + integration with coverage ≥ 80% |
| `task test:ci` | `lint` + `test` (no Vault needed) |
| `task clean` | Remove caches, `outputs/`, `.tmp/vault`, `.tmp/audit-token`, `.tmp/*.log` |

Full end-to-end check: `task down && task up && task seed && task seed:findings && task token:audit && task test:all && task lint`.

## Environment notes

- The container engine is **podman** behind the `docker` CLI (`CONTAINER_CLI` in `.env`). Use fully qualified image names (`docker.io/...`).
- Ports: primary `127.0.0.1:8210`; **`8220` is reserved for the planned DR secondary**. Avoid 8300–8302 (Consul) and 127.0.0.x aliases other than 127.0.0.1 (macOS needs sudo for them).
- Dev mode uses in-memory storage, so `sys/replication/status` returns `{"mode":"unsupported"}`. The DR phase must use Raft storage with a config file, not `-dev`.
- TLS: `VAULT_SKIP_VERIFY=true` by default. For verified TLS, set `VAULT_CACERT=.tmp/vault/vault-primary/tls/vault-ca.pem` (the cert has SANs for 127.0.0.1 and the container name).
- hvac quirk: a `requests.Session` passed to `hvac.Client` overrides its `verify=`. `VaultReader` sets `session.verify`, and a regression test covers it.
- The default activity-log billing period excludes the current month. `usage` adds `current_month` from `sys/internal/counters/activity/monthly`.

## Coding conventions

- Python 3.12+, ruff (line length 200, enforced by E501 and ruff format), pure check functions (`mount_findings`, `namespace_findings`, `sentinel_findings`, `health_findings`) kept free of I/O so they can be unit-tested with fixtures.
- Bash in `scripts/`: `#!/bin/bash`, `set -euo pipefail`, shellcheck-clean, idempotent.
- New env vars go in `.env.template` too. Never commit `.env`.
