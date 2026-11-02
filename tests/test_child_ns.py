"""Child-namespace token integration tests: a token created in a Vault Enterprise child namespace.

Locally: `task seed:ns token:ns` (NS defaults to admin; `NS=team-x task seed:ns token:ns` for any
other namespace). Cluster-agnostic: runs unchanged against any cluster with a child-namespace token.
Reads only VAULT_NS_TOKEN (+ VAULT_NS_TOKEN_NAMESPACE), never VAULT_TOKEN (`.env` sets it to root),
and asserts nothing about replication, raft, metrics or client counts, which differ between clusters.
"""

import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import requests
import vault_ops as vo

pytestmark = pytest.mark.integration

NAMESPACE = (os.getenv("VAULT_NS_TOKEN_NAMESPACE") or "admin").strip("/")
# Cluster blocks a child-namespace token can't read: the run must skip them, never record them as denied.
ROOT_ONLY_SCOPES = {
    "sys/license/status",
    "sys/config/state/sanitized",
    "sys/storage/raft/configuration",
    "sys/audit",
    "sys/metrics",
    "sys/leader",
    "sys/replication/status",
    "sys/internal/counters/config",
}


@pytest.fixture(scope="module")
def ns_token():
    addr, token = os.getenv("VAULT_ADDR"), os.getenv("VAULT_NS_TOKEN")
    if not addr or not token:
        pytest.skip("VAULT_ADDR/VAULT_NS_TOKEN not set (run: task seed:ns token:ns)")
    verify = False if os.getenv("VAULT_SKIP_VERIFY", "").lower() in ("1", "true") else (os.getenv("VAULT_CACERT") or True)
    try:
        response = requests.get(
            f"{addr.rstrip('/')}/v1/auth/token/lookup-self",
            headers={"X-Vault-Token": token, "X-Vault-Namespace": NAMESPACE},
            verify=verify,
            timeout=5,
        )
    except requests.RequestException:
        pytest.skip(f"Vault not reachable at {addr}")
    if response.status_code != 200:
        pytest.skip(f"VAULT_NS_TOKEN rejected in {NAMESPACE}/ (HTTP {response.status_code}); run: task token:ns")
    data = response.json().get("data") or {}
    if token == "root" or {"root", "hcp-root"} & set(data.get("policies") or []):
        pytest.fail("child-namespace tests must use the vault-ops audit token (task token:ns), never root or hcp-root")
    if (data.get("namespace_path") or "").strip("/") != NAMESPACE:
        pytest.skip(f"VAULT_NS_TOKEN lives in {data.get('namespace_path')!r}, not {NAMESPACE}/")
    return token


@pytest.fixture
def scoped_env(ns_token, monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", ns_token)
    monkeypatch.setenv("VAULT_NAMESPACE", NAMESPACE)


def run(capsys, *args):
    code = vo.main(list(args))
    out = capsys.readouterr()
    assert code in (vo.EXIT_OK, vo.EXIT_FINDINGS), out.err
    return [json.loads(Path(p).read_text()) for p in out.out.split()]


def check_run(doc):
    assert doc["run"]["token_namespace"] == f"{NAMESPACE}/"
    # Same tests run locally and against HCP Vault Dedicated (task test:hcp).
    hcp = (urlsplit(os.environ["VAULT_ADDR"]).hostname or "").endswith(".hashicorp.cloud")
    assert doc["run"]["platform"] == ("hcp" if hcp else "enterprise")
    denied = {d["scope"] for d in doc["coverage"]["denied"]}
    assert not denied & ROOT_ONLY_SCOPES, denied
    assert doc["coverage"]["errors"] == [], doc["coverage"]["errors"]


@pytest.mark.parametrize(
    "command",
    [["audit"], ["health"], ["inventory"], ["usage"], ["entities"], ["policies"]],
)
def test_every_subcommand_runs_with_a_child_namespace_token(scoped_env, capsys, tmp_path, command):
    docs = run(capsys, *command, "--output-dir", str(tmp_path))
    for doc in docs:
        check_run(doc)


def test_audit_paths_are_full_and_cluster_blocks_skipped(scoped_env, capsys, tmp_path):
    findings, inventory = run(capsys, "audit", "--output-dir", str(tmp_path))
    assert findings["run"]["start_namespace"] == f"{NAMESPACE}/"
    # Walk findings carry full paths; only replication findings (from the unauthenticated sys/replication/status) sit at root.
    at_root = {f["rule_id"] for f in findings["findings"] if not f["namespace"].startswith(f"{NAMESPACE}/")}
    assert all(rule.startswith(("VT-HLTH-002", "VT-REPL-")) for rule in at_root), at_root
    names = [r["namespace"] for r in inventory["namespaces"]]
    assert names[0] == f"{NAMESPACE}/" and all(n.startswith(f"{NAMESPACE}/") for n in names)
    assert findings["cluster_context"]["system_max_lease_ttl_seconds"] is None


def test_usage_rows_are_full_paths(scoped_env, capsys, tmp_path):
    (usage,) = run(capsys, "usage", "--output-dir", str(tmp_path))
    assert all(r["namespace"].startswith(f"{NAMESPACE}/") for r in usage["top_namespaces"])


def test_health_reads_hcp_endpoints_only_on_hcp(scoped_env, capsys, tmp_path):
    (doc,) = run(capsys, "health", "--output-dir", str(tmp_path))
    health = doc["health"]
    assert all(health[k] is None for k in ("license", "raft", "lease_ttls", "audit_devices", "snapshots"))
    assert health["metrics"] is None  # skipped on HCP; root-only for other child-namespace tokens
    if doc["run"]["platform"] == "hcp":
        assert health["seal"] and health["seal"]["type"] != "shamir"  # HashiCorp-managed auto-unseal
    else:
        assert health["seal"] is None
