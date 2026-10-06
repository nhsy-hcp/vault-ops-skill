"""Performance replication integration tests: need `task up:all && task pr:enable`, then
`task seed:findings` (paths filter + stale secondary) and `task token:policies && task token:pr`.

Skipped unless the node at VAULT_PR_ADDR answers as a performance secondary. Tokens are per
cluster, so secondary-side tests use VAULT_PR_TOKEN (minted on vault-pr), never root.
"""

import json
import os
from pathlib import Path

import pytest
import requests
import vault_ops as vo

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def pr_addr():
    addr = os.getenv("VAULT_PR_ADDR")
    if not addr or not os.getenv("VAULT_TOKEN"):
        pytest.skip("VAULT_PR_ADDR/VAULT_TOKEN not set")
    if os.getenv("VAULT_TOKEN") == "root":
        pytest.fail("integration tests must use the audit token (task token:policies), not root")
    try:
        health = requests.get(f"{addr}/v1/sys/health", verify=False, timeout=3).json()
    except (requests.RequestException, ValueError):
        pytest.skip(f"PR node not reachable at {addr}")
    if health.get("replication_performance_mode") != "secondary":
        pytest.skip("PR node is not an active performance secondary (run: task pr:enable)")
    return addr


@pytest.fixture
def on_secondary(pr_addr, monkeypatch):
    token = os.getenv("VAULT_PR_TOKEN")
    if not token:
        pytest.skip("VAULT_PR_TOKEN not set (run: task token:pr)")
    if token == "root":
        pytest.fail("integration tests must use the audit token (task token:pr), not root")
    monkeypatch.setenv("VAULT_ADDR", pr_addr)
    monkeypatch.setenv("VAULT_TOKEN", token)


def run(capsys, *args):
    code = vo.main(list(args))
    out = capsys.readouterr()
    if code not in (0, vo.EXIT_FINDINGS):
        return code, out.err
    path = Path(out.out.split()[0])
    return code, json.loads(path.read_text())


def rules(doc, rule_id):
    return [f for f in doc["findings"] if f["rule_id"] == rule_id]


def test_primary_reports_connected_pr_secondary(pr_addr, capsys, tmp_path):
    code, doc = run(capsys, "health", "--output-dir", str(tmp_path))
    assert code == 0
    perf = doc["health"]["replication"]["performance"]
    assert perf["mode"] == "primary" and perf["state"] == "running"
    assert "vault-pr" in perf["known_secondaries"]
    (pr,) = [s for s in perf["secondaries"] if s["node_id"] == "vault-pr"]
    assert pr["connection_status"] == "connected" and pr["last_heartbeat"]
    assert isinstance(pr["replication_primary_canary_age_ms"], int)
    assert perf["corrupted_merkle_tree"] is False
    assert doc["health"]["performance_secondary"] is False
    assert not any("vault-pr" in f["evidence"]["disconnected_peers"] for f in rules(doc, "VT-HLTH-002")) and not rules(doc, "VT-REPL-004")
    assert doc["coverage"]["complete"] is True


def test_primary_seeded_replication_findings(pr_addr, capsys, tmp_path):
    code, doc = run(capsys, "health", "--output-dir", str(tmp_path))
    assert code == 0
    filters = doc["health"]["replication"]["performance"]["paths_filters"]
    if not any(f["secondary_id"] == "vault-pr" for f in filters):
        pytest.skip("no paths filter on vault-pr (run: task seed:findings)")
    assert {"secondary_id": "vault-pr", "mode": "deny", "paths": ["tn009/"]}.items() <= next(f for f in filters if f["secondary_id"] == "vault-pr").items()
    assert [f["evidence"]["secondary_id"] for f in rules(doc, "VT-REPL-005")] == ["vault-pr"]
    stale = rules(doc, "VT-REPL-002")
    assert any("vault-pr-stale" in json.dumps(f) for f in stale)
    # A heartbeat-less secondary still counts as disconnected (it may be down since a primary restart).
    assert any(f["evidence"]["disconnected_peers"] == ["vault-pr-stale"] for f in rules(doc, "VT-HLTH-002"))


def test_no_addresses_in_output(pr_addr, capsys, tmp_path):
    code, doc = run(capsys, "health", "--output-dir", str(tmp_path))
    assert code == 0
    raw = json.dumps(doc)
    for leaked in ("https://vault-", ":8201", "cluster_id", "merkle_root"):
        assert leaked not in raw


def test_secondary_health(on_secondary, capsys, tmp_path):
    code, doc = run(capsys, "health", "--output-dir", str(tmp_path))
    assert code == 0
    h = doc["health"]
    assert h["performance_secondary"] is True and h["dr_secondary"] is False
    perf = h["replication"]["performance"]
    assert perf["mode"] == "secondary" and perf["state"] == "stream-wals"
    assert [p["connection_status"] for p in perf["primaries"]] == ["connected"]
    assert h["license"] is not None  # unlike a DR secondary, authenticated reads work
    assert doc["coverage"]["complete"] is True
    assert not [f for f in doc["findings"] if f["rule_id"] in ("VT-HLTH-001", "VT-HLTH-002")]


def test_secondary_audit_sees_filtered_namespaces(on_secondary, capsys, tmp_path, monkeypatch):
    code, doc = run(capsys, "audit", "--output-dir", str(tmp_path / "pr"), "-w", "8")
    assert code == 0, doc
    assert not doc["coverage"]["errors"]
    pr_namespaces = doc["coverage"]["namespaces_processed"]
    # The same audit on the primary sees the tn009 subtree that the paths filter keeps off vault-pr.
    monkeypatch.undo()  # back to the primary's VAULT_ADDR/VAULT_TOKEN
    code, primary = run(capsys, "audit", "--output-dir", str(tmp_path / "primary"), "-w", "8")
    assert code == 0
    assert primary["coverage"]["namespaces_processed"] > pr_namespaces
    assert not any(f["namespace"].startswith("tn009") for f in doc["findings"])
