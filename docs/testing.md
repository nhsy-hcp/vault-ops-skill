# Testing

An end-to-end manual test of the dev environment, DR replication and the vault-ops skill. Run every command from the repo root.

## 1. Start from scratch

```bash
task clean      # deletes node data, unseal keys, TLS and the audit token
task deps       # should be all "ok" (if podman is down: podman machine start)
task up:all     # both nodes: init, unseal, create the 'root' token
```

`task down` keeps node data in `.tmp/vault/`, so `task up:all` alone resumes the existing replicated pair. Run `task clean` first for a clean test.

## 2. Seed the primary and enable DR

```bash
task seed               # about 1–2 min, 132 namespaces
task seed:findings
task token:audit        # 1h read-only token, saved to .tmp/audit-token
task dr:enable          # should end: primary running/connected, secondary stream-wals
task dr:status
```

## 3. Run the tests

```bash
task test:all           # unit + integration (incl. DR); expect all passed, coverage >= 80%
task lint
```

## 4. Run the skill script by hand

```bash
task skill:run -- audit                                       # prints the path to the findings file
task skill:run -- health                                      # primary: dr primary, secondary connected
VAULT_ADDR=https://127.0.0.1:8220 task skill:run -- health    # DR secondary health
VAULT_ADDR=https://127.0.0.1:8220 task skill:run -- audit     # should refuse: "is a DR secondary"
task skill:run -- entities                                    # counts + VT-ID findings, no metadata
task skill:run -- entities --namespace tn001 --list           # adds metadata, aliases, policies per entity
```

To read a result, pipe it through `jq`, for example:

```bash
task skill:run -- health | xargs jq .health.replication
```

## 5. Failure drill

```bash
task down:dr
sleep 20 && task skill:run -- health | xargs jq '[.findings[].rule_id]'   # includes VT-HLTH-002
task up:dr && task dr:status                                              # back to stream-wals
```

## 6. Try the skill in Claude Code

Open a new session in this repo with the read-only token in the environment:

```bash
set -a; source .env; set +a; export VAULT_TOKEN="$(cat .tmp/audit-token)"; claude
```

Then ask "audit my vault", "check DR health on both nodes" or "show the entities and their aliases in tn001". The skill should:

- run only the bundled script
- report coverage first
- draft remediation without applying it

VT-LIC-001 will fire if the dev license expires within 90 days.

## Clean up

```bash
task down     # remove containers, keep node data
task clean    # also delete node data, keys, TLS and the token
```

The podman machine keeps running until you run `podman machine stop`.
