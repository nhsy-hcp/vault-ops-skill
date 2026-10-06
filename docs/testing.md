# Testing

An end-to-end manual test of the dev environment, DR and performance replication and the vault-ops skill. Run every command from the repo root.

The automated version is one destructive command: `task test:e2e` ([`scripts/e2e.sh`](../scripts/e2e.sh)). It runs `down`, `clean`, `up:all`, `dr:enable`, `pr:enable`, `seed`, `seed:findings`, `token:policies`, `token:pr`, `test:all`, `test:ce` and `lint`, and stops at the first failure.

## 1. Start from scratch

```bash
task clean      # deletes node volumes, unseal keys, TLS, the audit tokens and results
task deps       # should be all "ok" (if podman is down: podman machine start)
task up:all     # all three nodes: init, unseal, create the 'root' token
```

`task down` keeps the node data volumes and `.tmp/vault/` (unseal keys, TLS), so `task up:all` alone resumes the existing replicated nodes. Run `task clean` first for a clean test.

## 2. Enable replication, then seed the primary

```bash
task dr:enable          # should end: primary running/connected, secondary stream-wals
task dr:status
task pr:enable          # performance secondary: stream-wals, then token 'root' restored on vault-pr
task pr:status
task seed               # about 1–2 min, 132 namespaces
task seed:findings
task token:policies     # 1h read-only token (+ policy/Sentinel readers), saved to .tmp/audit-token
task token:pr           # same policies, minted on vault-pr: .tmp/audit-token-pr
```

Enable DR and performance replication **before** seeding. Both enables briefly restart the primary and drops client activity Vault hasn't saved yet, so seeding first leaves the client count at 1 instead of about 841. See [replication.md](replication.md#behaviour-to-know).

## 3. Run the tests

```bash
task test:all           # unit + integration (incl. DR and PR); expect all passed, coverage >= 80%
task test:ce           # Community dev server from compose.ce.yaml
task lint
task test:ci            # what CI runs: lint, plugin manifests, unit tests (no Vault)
```

To run the GitHub Actions workflow locally (podman socket shown):

```bash
DOCKER_HOST=unix://$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}') \
  act push -P ubuntu-latest=catthehacker/ubuntu:act-latest --container-daemon-socket -
```

## 4. Run the skill script by hand

Results are written to `.tmp/vault-ops/` (0600, git-ignored); stdout carries only the file paths.

```bash
task skill:run -- audit                                       # prints the findings and inventory file paths
task skill:run -- health                                      # primary: dr primary, secondary connected
VAULT_ADDR=https://127.0.0.1:8220 task skill:run -- health    # DR secondary health
VAULT_ADDR=https://127.0.0.1:8220 task skill:run -- audit     # should refuse: "is a DR secondary"
task skill:run:pr -- health                                   # PR secondary: performance_secondary: true
task skill:run:pr -- audit                                    # works; tn009 is filtered off vault-pr
task skill:run -- usage                                       # billing period + current month client counts
task skill:run -- entities                                    # counts + VT-ID findings, no metadata
task skill:run -- entities --namespace tn001 --list           # adds metadata, aliases, policies per entity
```

To read a result, pipe it through `jq`, for example:

```bash
task skill:run -- health | xargs jq .health.replication
task skill:run -- audit | tail -1 | xargs jq '.summary | {namespaces, max_depth, auth_types, secrets_types}'
```

## 5. Failure drill

```bash
task down:dr
sleep 20 && task skill:run -- health | xargs jq '[.findings[].rule_id]'   # includes VT-HLTH-002
task up:dr && task dr:status                                              # back to stream-wals
task down:pr
sleep 20 && task skill:run -- health | xargs jq '[.findings[].rule_id]'   # includes VT-HLTH-002 for vault-pr
task up:pr && task pr:status
```

## 6. Try the skill in Claude Code

Open a new session in this repo with the read-only token in the environment:

```bash
set -a; source .env; set +a; export VAULT_TOKEN="$(cat .tmp/audit-token)"; claude
```

Then ask "audit my vault", "check replication health on all nodes" or "show the entities and their aliases in tn001". The skill should:

- run only the bundled script
- report coverage first
- draft remediation without applying it

VT-LIC-001 will fire if the dev license expires within 90 days.

## Clean up

```bash
task down     # remove containers, keep node data
task clean    # also delete node volumes, keys, TLS, the tokens and results
```

The podman machine keeps running until you run `podman machine stop`.
