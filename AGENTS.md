# AGENTS.md — vault-ops-skill

Project rules for AI agents. Global rules in `~/.bob/AGENTS.md` still apply; this file adds what is specific to this repo.

## What this repo is

A **read-only** HashiCorp Vault ops Claude skill (`skills/vault-ops/`) plus a local Vault Enterprise dev environment to build and test it against.

| Path | Purpose |
| --- | --- |
| `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json` | Plugin manifest and single-plugin marketplace (source `.`); validated by `task plugin:validate` |
| `.claude/skills/vault-ops` | Symlink to `skills/vault-ops`, so sessions in this repo load the skill |
| `skills/vault-ops/SKILL.md` | Skill workflow and guardrails (what Claude does when the skill triggers) |
| `skills/vault-ops/scripts/vault_ops.py` | PEP 723 single-file collector: `audit` (findings + inventory), `health`, `inventory`, `usage`, `entities`, `diff` |
| `skills/vault-ops/schemas/findings.schema.json` | JSON Schema (draft 2020-12) for findings files, `schema_version` 1.4.0 |
| `skills/vault-ops/references/rules.md` | Rule catalogue (VT-*) with drafted remediation |
| `skills/vault-ops/policies/vault-ops-readonly.hcl` | Least-privilege Vault policy for the skill's token |
| `scripts/` | Dev-env automation (bash, called from `Taskfile.yml`) and `seed_vault.py` |
| `docs/dr.md` | DR pair design, node lifecycle, failure drills |
| `tests/` | Unit tests (no Vault); `test_integration.py` and `test_dr.py` (`-m integration`, need the dev nodes; `test_dr.py` skips unless DR is active) |
| `.tmp/spec.md` | Options analysis and spec (gitignored working doc) |

## Hard rules

- **Read-only, always.** `vault_ops.py` may only issue GET/LIST requests. Never add a code path that writes to Vault, and never add write capabilities to `vault-ops-readonly.hcl`. ACL policy **bodies** stay unreadable (`list` only).
- **Never use the root token for the skill or the integration tests.** Use `task token:audit` (a 1h token from `vault-ops-readonly.hcl`); `test_integration.py` fails when `VAULT_TOKEN=root`. Root is only for `seed`, `seed:findings` and `token:audit`.
- **`~/Projects/vault-tools` is reference-only.** Port logic from it; never modify it.
- **No secrets in outputs.** Findings and other outputs must never contain tokens, accessors, Sentinel policy source, namespace `custom_metadata` or raw error text. Entity `metadata` and alias names (emails, usernames, AppRole role_ids) are written **only** in `entities --list` rows, never in the default output or in findings; tests enforce both. Errors go through `sanitise_error()` (class + HTTP status). Output files are written 0600.
- **Rule IDs are permanent.** Never renumber or reuse a `VT-*` ID. A new rule means adding it to `RULES`, the schema `category` enum if needed, `references/rules.md`, and a fixture that fires it. Adding optional fields is a minor `SCHEMA_VERSION` bump; renaming or removing is a major bump.
- **Script stays single-file with PEP 723 deps** (`hvac==2.4.0`, `requests>=2.32,<3`, uv `exclude-newer`), so the published skill runs anywhere with `uv run --script` and no Taskfile. Keep the inline deps and `pyproject.toml` in sync; bump `exclude-newer` deliberately with a dependency update.
- **The published skill must not depend on this repo.** Nothing under `skills/vault-ops/` may reference `task`, `.env`, `.tmp/` or repo paths. SKILL.md calls the script via `${CLAUDE_SKILL_DIR}`. Output defaults to `~/.vault-ops/outputs`; the Taskfile sets `VAULT_OPS_OUTPUT_DIR=outputs` for local dev.
- **DR secondaries: `health` only.** A DR secondary rejects authenticated requests. `connect()` probes unauthenticated `sys/health` first: `health` reads only unauthenticated endpoints there, and `audit`/`inventory`/`usage` exit 1. Never add authenticated reads to the DR-secondary path.
- **Stdout = written file paths only**; diagnostics go to stderr. Exit codes: 0 ok, 1 fatal, 2 gaps (`--fail-on-gaps`), 3 findings (`--fail-on`), 130 interrupted.

## Task interface

| Task | What it does |
| --- | --- |
| `task init` | `uv sync`, install pre-commit hooks, create `.env` from `.env.template` |
| `task deps` | Check tools, container engine (podman: `podman machine start`), host IP/port, `.env` |
| `task up` / `task up:dr` / `task up:all` | Start, init and unseal `vault-primary` (`https://127.0.0.1:8210`) and/or `vault-dr` (`https://127.0.0.1:8220`): Enterprise, Raft, TLS |
| `task down` / `task down:dr` | Remove both containers / only the DR one (Raft data kept) |
| `task dr:enable` / `task dr:status` | Enable DR replication primary → secondary (idempotent, waits for `stream-wals`); show status on both |
| `task status` / `task logs` | `vault status` (primary); tail `.tmp/vault/<node>/logs/vault.log` (`NODE=vault-dr task logs`) |
| `task seed` | `scripts/seed_vault.py`: 132 namespaces, mounts, KV data, client activity (root) |
| `task seed:findings` | Configuration that trips every live-testable rule, plus Sentinel EGP/RGPs (root) |
| `task token:audit` | Write `vault-ops-readonly` policy, mint 1h token to `.tmp/audit-token` (0600) |
| `task skill:run -- <cmd>` | Run `vault_ops.py` with the audit token, e.g. `task skill:run -- audit` |
| `task lint` | pre-commit on tracked + untracked files: ruff, ruff-format, shellcheck, gitleaks, yaml/json |
| `task test` | Unit tests with coverage ≥ 80% |
| `task test:integration` | Integration tests (audit token, live Vault) |
| `task test:all` | Unit + integration with coverage ≥ 80% |
| `task test:ci` | `lint` + `plugin:validate` + `test` (no Vault needed) |
| `task plugin:validate` | `claude plugin validate --strict` on the marketplace and plugin manifests |
| `task clean` | Remove caches, `outputs/`, `.tmp/vault` (all node data, unseal keys, TLS), `.tmp/audit-token`, `.tmp/*.log` |

Full end-to-end check: `task down && task clean && task up:all && task dr:enable && task seed && task seed:findings && task token:audit && task test:all && task lint`. Keep `dr:enable` before `seed`: enabling DR briefly restarts the primary and drops unsaved client activity (see `docs/dr.md`).

## Environment notes

- The container engine is **podman** behind the `docker` CLI (`CONTAINER_CLI` in `.env`). Use fully qualified image names (`docker.io/...`).
- Ports: primary `127.0.0.1:8210`, DR `127.0.0.1:8220`. Replication uses 8201 on the `vault-ops` podman network (never published). Avoid 8300–8302 (Consul) and 127.0.0.x aliases other than 127.0.0.1 (macOS needs sudo for them).
- Nodes run in server mode on Raft, not `-dev`: dev-mode in-memory storage can't replicate. Node state lives in `.tmp/vault/<node>/` (`config/vault.hcl`, `data/`, `logs/`, `init.json` with the unseal key and initial root token, 0600).
- Each node gets a root-policy token with ID `root`, so `VAULT_TOKEN=root` works as in dev mode. After `dr:enable` the secondary uses the primary's storage and unseal key; `vault_up.sh` tries both keys.
- TLS: one local CA and one shared server cert from `scripts/gen_tls.sh` in `.tmp/vault/tls/` (SANs: localhost, 127.0.0.1, vault-primary, vault-dr). `VAULT_SKIP_VERIFY=true` by default; for verified TLS set `VAULT_CACERT=.tmp/vault/tls/vault-ca.pem`. Details: [docs/dr.md](docs/dr.md).
- hvac quirk: a `requests.Session` passed to `hvac.Client` overrides its `verify=`. `VaultReader` sets `session.verify`, and a regression test covers it.
- The default activity-log billing period excludes the current month. `usage` adds `current_month` from `sys/internal/counters/activity/monthly`.

## Coding conventions

- Python 3.12+, ruff (line length 200, enforced by E501 and ruff format), pure check functions (`mount_findings`, `namespace_findings`, `sentinel_findings`, `health_findings`) kept free of I/O so they can be unit-tested with fixtures.
- Bash in `scripts/`: `#!/bin/bash`, `set -euo pipefail`, shellcheck-clean, idempotent.
- New env vars go in `.env.template` too. Never commit `.env`.
