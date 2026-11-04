# Setup problems and the least-privilege token

Read this when the script exits 1, or when coverage denies a scope that names an add-on.

## Setup problems

The script itself is the preflight. Map its failures to setup help and stop — never work around them:

| Symptom | Tell the user |
| --- | --- |
| `uv: command not found` | Install uv (https://docs.astral.sh/uv/getting-started/installation/), e.g. `brew install uv` or `curl -LsSf https://astral.sh/uv/install.sh \| sh`, then retry. The script installs its own pinned dependency (requests). |
| `VAULT_ADDR and VAULT_TOKEN must be set` | Exit Claude, export them in the shell, restart (example below). Never ask them to paste a token into the chat. If they keep the values in a file such as `.env`, the user loading it in their own shell before starting Claude (`set -a; source .env; set +a`) is the right fix: only you reading the file is forbidden, so present it as their step, not as a workaround. |
| `token rejected (403 on auth/token/lookup-self in namespace /)` and the token was created in a child namespace | Set `VAULT_NAMESPACE` to the namespace the token lives in (or one below it) before starting Claude, e.g. `VAULT_NAMESPACE=admin` on HCP Vault Dedicated, where tokens live in `admin/`. |
| `token rejected (403 on auth/token/lookup-self ...)` / `token validation failed` | The token is expired or lacks the policy; mint a new one with the command below. |
| `<addr> is sealed` / `is not initialized, so it rejects authenticated reads` | The node can't serve authenticated reads, so only `health` works there: run it and report the seal state (VT-HLTH-001, `health.seal`). Unsealing or initializing is an operator task: never run it or offer to. For a cluster, run `health` against the other nodes too. |
| `cannot reach Vault ... SSLError` | Set `VAULT_CACERT=/path/to/ca.pem` (preferred) or, for a dev server only, `VAULT_SKIP_VERIFY=true`. |
| `policies` coverage denies `ACL policy bodies (attach vault-ops-policy-reader)` | The token can list policy names but not read their contents. An admin attaches the read-only add-on: `vault policy write vault-ops-policy-reader <this skill>/policies/vault-ops-policy-reader.hcl` and mints the token with `-policy=vault-ops-readonly -policy=vault-ops-policy-reader`. Never suggest adding anything else to either policy. |
| Coverage denies `sentinel EGP/RGP policy bodies (attach vault-ops-sentinel-reader)` (`audit`, `inventory`, `policies`) | The token can list Sentinel policy names but not read them, so no VT-SNT rule was judged. An admin attaches the read-only add-on: `vault policy write vault-ops-sentinel-reader <this skill>/policies/vault-ops-sentinel-reader.hcl` and adds `-policy=vault-ops-sentinel-reader` to the token. Never suggest adding anything else to any of the policies. |
| `cannot reach Vault ... ConnectionError` | Vault is not reachable from this machine (VPN, address, port). Offer file mode: interpret vault-ops JSON files produced elsewhere. |

```bash
export VAULT_ADDR=https://vault.example.com:8200 VAULT_CACERT=/path/to/ca.pem
# export VAULT_NAMESPACE=admin   # only for a token created in a child namespace (HCP Vault Dedicated: admin)
vault policy write vault-ops-readonly <this skill>/policies/vault-ops-readonly.hcl   # once, by an admin
export VAULT_TOKEN="$(vault token create -policy=vault-ops-readonly -no-default-policy -orphan -ttl=1h -field=token)"
claude
```

## Least-privilege token

Recommend the user runs the skill with a token from `policies/vault-ops-readonly.hcl`, minted by a human with `-ttl=1h`, never a root token. Mint it in the root namespace for a full review; where users can only reach a child namespace (e.g. `admin` on HCP Vault Dedicated), write the policies and mint the token there with `-namespace=<ns>` and set `VAULT_NAMESPACE=<ns>`: cluster-level checks are then skipped (see Reading the files). The skill never mints tokens itself. For a policy review (`policies`), the admin also attaches `policies/vault-ops-policy-reader.hcl`, which only adds `read` on ACL policies; recommend dropping it again afterwards. Sentinel checks (VT-SNT-*, in `audit` and `policies`) need `policies/vault-ops-sentinel-reader.hcl`, which only adds `read` on EGP/RGP policies.

The token policy is the hard boundary: `allowed-tools` only pre-approves the script, it does not block other commands. For defence in depth, suggest the user denies Vault-changing commands in their Claude Code settings (`permissions.deny`: `Bash(vault write:*)`, `Bash(vault delete:*)`, `Bash(vault token:*)`, `Bash(vault login:*)`).
