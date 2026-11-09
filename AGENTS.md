# AGENTS.md — vault-ops-skill

A **read-only** HashiCorp Vault ops Claude skill (`skills/vault-ops/`) plus a local Vault Enterprise dev environment (compose: primary, DR secondary, performance secondary) to build and test it against.

**Full detail** (every path, rule mechanics, every task, env notes): [docs/development.md](docs/development.md). Read the matching section before changing an area. Replication/compose: [docs/replication.md](docs/replication.md). Test walkthrough: [docs/testing.md](docs/testing.md).

## Key paths

- `skills/vault-ops/`: the published skill. `SKILL.md`; `scripts/vault_ops.py`, `schemas/`, `references/`, `policies/`.
- `.claude-plugin/`: plugin + marketplace manifests. `.claude/skills/vault-ops` symlinks the skill.
- `compose.yaml`, `compose/vault.hcl`, `compose.ce.yaml`: dev nodes and the CE test server.
- `scripts/`: dev-env automation, `seed_vault.py`, `export_rules.py`, `gepa_eval.py`.
- `tests/`: unit tests; `-m integration` (`test_integration`, `test_dr`, `test_pr`, `test_child_ns`); `-m ce` for `test:ce`.
- `evals/`: `claude plugin eval` cases (offline only; fixtures staged by `evals/fixtures/stage.sh`; fixtures never contain tokens or real personal data).
- `terraform/hcp/`: HCP Vault Dedicated test cluster (local only, gitignored state).
- `docs/architecture.dot`: edit it, then `task docs:diagram`, commit `.dot` and `.svg`.

## Hard rules

- **Read-only, always.** `vault_ops.py` issues GET/LIST only. Never add write capabilities to `vault-ops-readonly.hcl` (names only). ACL bodies only via `vault-ops-policy-reader.hcl`, Sentinel bodies only via `vault-ops-sentinel-reader.hcl`: `read` only, never merged into the readonly policy, bodies never leave the script (outputs: names, hash, flagged rules). `sudo` only on exactly `sys/audit` and `sys/storage/raft/snapshot-auto/config`. Never read `snapshot-auto/config/<name>` (plaintext credentials); use `snapshot-auto/status/<name>`.
- **Never use a root token for the skill or the tests.** Use `task token:audit` / `token:policies`. Root is for setup tasks only (`up*`, `seed*`, `token:*`, `*:enable`, `test:ce` policy setup); the HCP admin token only for `hcp:token` and `hcp:seed`. Never read or print `.tmp/admin-token-hcp`, never put it in Terraform state, never pass it to the skill or a test.
- **No secrets in outputs:** no tokens, accessors, Sentinel source, ACL bodies, `allowed/denied_parameters` values, namespace `custom_metadata` or raw error text (use `sanitise_error()`). Entity metadata and alias names only in `entities --list` rows. Output files 0600.
- **Rule IDs are permanent.** Never renumber or reuse a `VT-*` ID. New rule checklist: [docs/development.md § Rules in detail](docs/development.md#rules-in-detail). Then `task rules:export`; never hand-edit the generated blocks of `rules.md`. Adding optional output fields is a minor `SCHEMA_VERSION` bump; renaming or removing is major.
- **Script stays single-file with PEP 723 deps**, kept in sync with `pyproject.toml`; bump uv `exclude-newer` only deliberately.
- **The published skill must not depend on this repo:** nothing under `skills/vault-ops/` references `task`, `.env` or repo paths; SKILL.md uses `${CLAUDE_SKILL_DIR}`. Output defaults to `.tmp/vault-ops/` in the user's working directory; a directory the script creates gets a catch-all `.gitignore`.
- **Target types:** child-namespace tokens and performance secondaries are normal targets (PR needs a token minted there). With a child-namespace token, skipped root-only reads are `null`, not coverage gaps. DR secondaries and sealed/uninitialized nodes: `health` only, unauthenticated reads only (every other subcommand exits 1 naming the state); never add authenticated reads there. Never branch scoping or rules on `run.platform` beyond the existing HCP profile.
- **HCP is local only:** never in CI, `lint`, `test:all` or `test:e2e`. An agent may run only `hcp:plan`, `hcp:seed`, `hcp:token`, `test:hcp`, `skill:run:hcp`; `hcp:apply`/`hcp:destroy` are the user's (never `-y`/`-auto-approve`). Never commit HCP outputs or state.
- **Running the skill: follow SKILL.md exactly.** Only `uv run --script <skill dir>/scripts/vault_ops.py ...` with `VAULT_ADDR`/`VAULT_TOKEN` already in the environment. If unset, stop and give the "Setup problems" answer from `references/setup.md`; never use `task skill:run*`, `task hcp:env`, `.env` or token files (those are for humans).
- **`~/Projects/vault-tools` is reference-only.** Port from it; never modify it.
- **Ask before bumping the version** (minor or maintenance). A bump touches `.claude-plugin/plugin.json`, `pyproject.toml`, `TOOL_VERSION`, `uv.lock` (`uv lock`); commit it separately as `chore: bump version to X.Y.Z`. `SCHEMA_VERSION` is separate and follows the output-format rule above.
- **Stdout = written file paths only;** diagnostics to stderr. Exit codes: 0 ok, 1 fatal, 2 gaps, 3 findings, 130 interrupted.

## Tasks

`task --list` for all; details in [docs/development.md § Tasks](docs/development.md#tasks).

- Checks: `task lint`, `task test` (unit, coverage ≥ 80%), `task test:all` (+ integration, needs dev nodes), `task test:ci` (lint + plugin:validate + test; matches CI).
- Destructive: `task test:e2e` (full rebuild), `task clean` (volumes + unseal keys; never Terraform state).
- Local only, never CI: `test:ce`, `hcp:*`, and `eval`/`eval:gepa` (API credits).
- Run `dr:enable` and `pr:enable` before `seed` (enabling replication drops unsaved client activity).

## Gotchas

- Container engine is podman behind the `docker` CLI; use fully qualified image names. Ports: primary 8210, DR 8220, CE 8230, PR 8240 on 127.0.0.1.
- Client counts appear ~10 min after a node starts; tests never assert counts.

## Coding conventions

- Python 3.12+, ruff (line length 200). Check functions (`mount_findings`, `namespace_findings`, `sentinel_findings`, `sentinel_policy_findings`, `health_findings`) stay I/O-free.
- `VaultReader` is GET-only `requests` (no hvac); error classes keep hvac names because `sanitise_error()` records them.
- `references/rules.json` is the catalogue for other tools; never make a consumer parse `rules.md`.
- Bash in `scripts/`: `#!/bin/bash`, `set -euo pipefail`, shellcheck-clean, idempotent.
- New env vars go in `.env.template` too; never commit `.env`.
