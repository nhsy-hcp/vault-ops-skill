# Local DR replication

Two Vault Enterprise nodes in podman containers, with DR replication from `vault-primary` to `vault-dr`.

| Node | API (host) | Container name | Role |
| --- | --- | --- | --- |
| primary | `https://127.0.0.1:8210` | `vault-primary` | DR primary; everything (seed, skill audit) runs here |
| DR | `https://127.0.0.1:8220` | `vault-dr` | DR secondary; rejects client requests by design |

Replication runs over the cluster port (8201) on the private `vault-ops` podman network, addressed by container name. 8201 is never published to the host.

## Quickstart

```bash
task up:all        # start, init and unseal both nodes (raft storage, TLS)
task seed          # seed the primary (optional, before or after DR)
task dr:enable     # primary enable -> secondary token -> secondary enable; waits for stream-wals
task dr:status     # mode/state/connection on both nodes
```

`task dr:enable` is idempotent: rerunning it on an active pair only prints status.

| Task | Effect |
| --- | --- |
| `task up` / `task up:dr` / `task up:all` | Start the primary, the DR node, or both |
| `task down` | Remove both containers; Raft data in `.tmp/vault/<node>/data` is kept |
| `task down:dr` | Remove only the DR container (useful for failure drills) |
| `task logs` / `NODE=vault-dr task logs` | Tail a node's `vault.log` |
| `task clean` | Delete all node state (data, unseal keys, TLS); next `up` starts from scratch |

## How the nodes are built

- **Storage:** Raft at `/vault/file`, one node per cluster. Dev mode can't be used, because in-memory storage reports replication as `unsupported`.
- **TLS:** `scripts/gen_tls.sh` creates one local CA and one server cert, shared by both nodes, in `.tmp/vault/tls/`. SANs: `localhost`, `127.0.0.1`, `vault-primary`, `vault-dr`. The secondary trusts the primary through `ca_file=/vault/tls/vault-ca.pem`. For verified TLS from the host, set `VAULT_CACERT=.tmp/vault/tls/vault-ca.pem`.
- **Init/unseal:** first start runs `operator init` with 1 key share and stores the output in `.tmp/vault/<node>/init.json` (0600, gitignored). Every start unseals automatically.
- **`root` token:** each node gets a root-policy token with ID `root`, so `VAULT_TOKEN=root` in `.env` keeps working as in dev mode. This is a local-dev convenience only (Vault warns that custom IDs use SHA1 hashing).
- **Config:** generated per node at `.tmp/vault/<node>/config/vault.hcl`. `api_addr` and `cluster_addr` use the container name.

## Behaviour to know

- **The secondary's storage is replaced.** Enabling the DR secondary replaces its storage with the primary's. Its own `root` token and data are gone; the primary's (including token `root`) replicate in.
- **Unseal keys switch to the primary's.** After activation the secondary unseals with the primary's key. `vault_up.sh` tries the node's own key, then the primary's.
- **Client requests are disabled on the secondary.** It rejects authenticated requests (`path disabled in replication DR secondary mode`). Only unauthenticated status endpoints answer: `sys/health`, `sys/seal-status`, `sys/leader`, `sys/replication/*status`.

## Checking DR with the skill

```bash
task skill:run -- health                              # primary: dr primary/running, secondaries[].connection_status
VAULT_ADDR=$VAULT_DR_ADDR task skill:run -- health    # secondary: dr secondary/stream-wals, primaries[]
```

- `health` against the DR secondary reads only the unauthenticated endpoints. It sets `dr_secondary: true` and leaves license and lease data as `null`.
- `audit`, `inventory` and `usage` refuse a DR secondary (exit 1) and tell you to use the primary.
- **VT-HLTH-002** fires when replication is enabled but its state is unhealthy, or a peer is not `connected`.

Failure drill:

```bash
task down:dr && sleep 20 && task skill:run -- health   # VT-HLTH-002: vault-dr disconnected
task up:dr && task dr:status                           # unseals with the primary key, back to stream-wals
```

Out of scope here: promote, demote and failover. These are write operations; run them by hand from a runbook, never through the skill.
