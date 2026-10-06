# Local replication: DR and performance

Three Vault Enterprise nodes, defined in [`compose.yaml`](../compose.yaml), each a one-node Raft cluster with TLS. `vault-primary` replicates to `vault-dr` (DR) and to `vault-pr` (performance).

| Node | API (host) | Service / hostname | Role |
| --- | --- | --- | --- |
| primary | `https://127.0.0.1:8210` | `vault-primary` | DR primary and performance primary. Seeding and the skill's `audit` run here |
| DR | `https://127.0.0.1:8220` | `vault-dr` (profile `dr`) | DR secondary. Rejects client requests by design |
| PR | `https://127.0.0.1:8240` | `vault-pr` (profile `pr`) | Performance secondary. Serves reads with its own tokens |

Replication runs over the cluster port (8201) on the `vault-ops` network, addressed by hostname. 8201 is never published to the host. Containers are named `vault-ops_<service>`. Port 8230 belongs to the throwaway Community server in [`compose.ce.yaml`](../compose.ce.yaml) (`task test:ce`).

## Quickstart

```bash
task up:all        # start, init and unseal all three nodes
task dr:enable     # DR: primary enable -> secondary token -> secondary enable; waits for stream-wals
task pr:enable     # performance: same, then restores token `root` on vault-pr
task seed          # seed the primary AFTER both enables (see "Behaviour to know")
task seed:findings # adds a paths filter on vault-pr and a stale secondary (VT-REPL-005, VT-REPL-002)
task dr:status && task pr:status
```

`dr:enable` and `pr:enable` are idempotent: rerunning them on an active pair only prints the status.

| Task | Effect |
| --- | --- |
| `task up` / `up:dr` / `up:pr` / `up:all` | Start the primary, one secondary, or all three nodes |
| `task down` | `docker compose --profile '*' down`: remove every container and the network. The named data volumes are kept |
| `task down:dr` / `task down:pr` | Remove one secondary (for failure drills) |
| `task token:pr` | Read-only token minted **on vault-pr** into `.tmp/audit-token-pr` (tokens are per cluster) |
| `task skill:run:pr -- <cmd>` | Run the skill script against vault-pr with that token |
| `task logs` / `NODE=vault-pr task logs` | Follow a node's log (`docker compose logs -f`) |
| `task clean` | `compose down --volumes`, then delete unseal keys and TLS. The next `up` starts from scratch |

## How the nodes are built

- **Compose:** `compose.yaml` holds one service per node. They share a YAML anchor (image, `cap_add: [IPC_LOCK, SETFCAP]`, which Vault 2.x needs to start, and a healthcheck) and one config file, [`compose/vault.hcl`](../compose/vault.hcl). Per-node values come from `VAULT_API_ADDR`, `VAULT_CLUSTER_ADDR` and `VAULT_RAFT_NODE_ID`. The network is named `${COMPOSE_PROJECT_NAME}` (`vault-ops`), so it never collides with other compose projects. `scripts/vault_up.sh <service>` runs `docker compose up -d --wait <service>`, then initialises and unseals the node.
- **Storage:** Raft in a named volume per node (`vault-ops_<node>-data`); logs go to stdout. Dev mode can't be used: in-memory storage reports replication as `unsupported`. TLS is the one bind mount (below), because the host generates it.
- **TLS:** `scripts/gen_tls.sh` creates one local CA and one server cert, shared by every node, in `.tmp/vault/tls/`. SANs: `localhost`, `127.0.0.1`, `vault-primary`, `vault-dr`, `vault-pr`. A leaf that is missing a node's SAN is reissued from the same CA, so existing trust is kept. Secondaries trust the primary through `ca_file=/vault/tls/vault-ca.pem`. For verified TLS from the host, set `VAULT_CACERT=.tmp/vault/tls/vault-ca.pem`.
- **Init/unseal:** first start runs `operator init` with 1 key share and stores the output on the host in `.tmp/vault/<node>/init.json` (0600, gitignored). `task clean` removes it together with the volumes, because data without its unseal key can't be unsealed. Every start unseals automatically.
- **`root` token:** each node gets a root-policy token with ID `root`, so `VAULT_TOKEN=root` keeps working as in dev mode. This is a local-dev convenience only.
- **`generate-root`:** Vault 2.0 authenticates `sys/generate-root` by default (CVE-2026-5807). `compose/vault.hcl` sets `enable_unauthenticated_access = ["generate-root"]` (dev only) so `pr:enable` can restore `root` on vault-pr with the primary's unseal key.

## Behaviour to know

- **A secondary's storage is replaced.** Enabling either secondary replaces its storage with the primary's. A performance secondary keeps no tokens: they are per cluster and never replicate. `pr:enable` restores `root` with `generate-root`, and `task token:pr` mints the skill's token there. Policies replicate, so `vault-ops-readonly` already exists on vault-pr.
- **Unseal keys switch to the primary's.** After activation a secondary unseals with the primary's key. `vault_up.sh` tries the node's own key, then the primary's.
- **Enabling replication can drop unsaved client activity.** Vault holds new client activity in memory and writes it to storage periodically. `dr:enable` and `pr:enable` briefly restart the primary, and any activity not yet written is lost. Run both before `seed`. If you already seeded, run `task seed` again (it is idempotent).
- **DR secondary: client requests are disabled.** It rejects authenticated requests (`path disabled in replication DR secondary mode`). Only unauthenticated status endpoints answer.
- **Performance secondary: client requests work.** Every skill subcommand runs there with a token minted on that cluster. What it sees differs from the primary: local mounts (`VT-MOUNT-003`) stay per cluster, and a paths filter hides namespaces or mounts. `seed:findings` denies `tn009/`, so vault-pr has one fewer top-level namespace subtree.

## Checking replication with the skill

```bash
task skill:run -- health                              # primary: dr + performance primary, secondaries[], paths_filters
VAULT_ADDR=$VAULT_DR_ADDR task skill:run -- health    # DR secondary: unauthenticated status only
task skill:run:pr -- health                           # PR secondary: performance_secondary: true, full health
task skill:run:pr -- audit                            # works on a PR secondary (refused on DR)
```

- `health` against the DR secondary reads only the unauthenticated endpoints. It sets `dr_secondary: true` and leaves licence and lease data as `null`.
- `audit`, `inventory`, `usage` and `entities` refuse a DR secondary (exit 1). On a performance secondary they run normally.
- **VT-HLTH-002** fires when replication is enabled but unhealthy, or any peer is disconnected, including one with no heartbeat. After a primary restart a down secondary has no heartbeat either, so it is never left out.
- **VT-REPL-001..005**: lag (canary age or stale heartbeat), a known secondary with no heartbeat (unused activation token, or down since the primary restarted), clock skew, a corrupted Merkle tree, and a performance paths filter in use. Details are in [`rules.md`](../skills/vault-ops/references/rules.md).

Failure drills:

```bash
task down:dr && sleep 20 && task skill:run -- health   # VT-HLTH-002: vault-dr disconnected
task up:dr && task dr:status                           # unseals with the primary key, back to stream-wals
task down:pr && sleep 20 && task skill:run -- health   # VT-HLTH-002: vault-pr disconnected
task up:pr && task pr:status
```

Out of scope here: promote, demote, failover and filter changes. These are write operations. Run them by hand from a runbook, never through the skill.
