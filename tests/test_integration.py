"""Integration tests: need `task up && task seed && task seed:findings && task token:audit`.

Run with `task test:integration` (uses the least-privilege audit token, never root).
"""

import json
import os
from pathlib import Path

import jsonschema
import pytest
import requests
import vault_ops as vo

pytestmark = pytest.mark.integration

# Rules the dev seed can trip; MOUNT-001/LIC-001/HLTH-* depend on cluster state, and AUD-001/002 and
# SNAP-001/002 contradict the seeded devices and snapshot config: all are unit-tested.
SEEDED_RULES = {
    "VT-AUD-003",
    "VT-SNAP-003",
    "VT-AUTH-001",
    "VT-MOUNT-002",
    "VT-MOUNT-003",
    "VT-MOUNT-004",
    "VT-MOUNT-005",
    "VT-MOUNT-006",
    "VT-NS-001",
    "VT-NS-002",
    "VT-SNT-001",
    "VT-SNT-002",
    "VT-SNT-003",
    "VT-SNT-004",
}


@pytest.fixture(scope="module", autouse=True)
def vault_reachable():
    addr = os.getenv("VAULT_ADDR")
    if not addr or not os.getenv("VAULT_TOKEN"):
        pytest.skip("VAULT_ADDR/VAULT_TOKEN not set")
    try:
        requests.get(f"{addr}/v1/sys/health", verify=False, timeout=3)
    except requests.RequestException:
        pytest.skip(f"Vault not reachable at {addr}")
    if os.getenv("VAULT_TOKEN") == "root":
        pytest.fail("integration tests must use the audit token (task token:audit), not root")


def run(capsys, *args):
    code = vo.main(list(args))
    path = capsys.readouterr().out.split()[0]  # audit also writes inventory on the next line
    return code, json.loads(Path(path).read_text())


def test_audit_full_coverage_and_rules(capsys, tmp_path, schema):
    code, doc = run(capsys, "audit", "--output-dir", str(tmp_path), "-w", "8")
    assert code == 0
    jsonschema.validate(doc, schema)
    assert doc["coverage"]["complete"] is True, doc["coverage"]
    assert doc["coverage"]["namespaces_processed"] > 100
    assert doc["cluster_context"]["sentinel"] == "supported"
    assert doc["cluster_context"]["enterprise"] is True
    assert set(doc["summary"]["by_rule"]) >= SEEDED_RULES
    assert not any(f["object"]["path"] == "vault-ops-hard" for f in doc["findings"])
    (inv_path,) = tmp_path.glob("*-inventory-*.json")
    inv = json.loads(inv_path.read_text())
    assert inv["summary"]["namespaces"] == doc["coverage"]["namespaces_processed"]
    assert {"approle", "userpass", "jwt"} <= set(inv["summary"]["auth_types"])
    assert inv["summary"]["max_depth"] >= 3 and inv["summary"]["shapes"]


def test_health(capsys, tmp_path):
    code, doc = run(capsys, "health", "--output-dir", str(tmp_path))
    assert code == 0
    assert doc["health"]["sealed"] is False
    assert doc["health"]["license"]["expiration_time"]
    raft = doc["health"]["raft"]
    assert any(p["leader"] for p in raft["peers"])
    assert raft["autopilot"]["configuration"] and raft["autopilot"]["state"]["healthy"] is True
    devices = {d["path"]: d for d in doc["health"]["audit_devices"]}
    assert devices["vault-ops-file/"]["options"] == {"sink": "file"}
    assert devices["vault-ops-stdout/"]["options"] == {"hmac_accessor": False, "sink": "stdout"}
    (snap,) = [c for c in doc["health"]["snapshots"]["configs"] if c["name"] == "vault-ops-local"]
    assert snap["storage_scheme"] == "file" and snap["last_snapshot_end"] and snap["consecutive_errors"] == 0
    metrics = doc["health"]["metrics"]  # needs sys/metrics in vault-ops-readonly.hcl (task token:audit)
    assert metrics["node_scope"] is True and metrics["goroutines"] > 0 and metrics["leases"] is not None
    assert "/vault/" not in json.dumps(doc)  # audit file path and snapshot URL are never written
    assert doc["coverage"]["complete"] is True, doc["coverage"]


def test_inventory_and_usage(capsys, tmp_path):
    _, inv = run(capsys, "inventory", "--output-dir", str(tmp_path))
    assert inv["summary"]["namespaces"] > 100
    assert inv["coverage"]["complete"] is True
    _, usage = run(capsys, "usage", "--output-dir", str(tmp_path))
    assert usage["coverage"]["complete"] is True, usage["coverage"]


def test_subtree_and_diff(capsys, tmp_path):
    _, full = run(capsys, "audit", "--output-dir", str(tmp_path))
    _, sub = run(capsys, "audit", "--output-dir", str(tmp_path), "--namespace", "tn009")
    assert sub["run"]["start_namespace"] == "tn009/"
    assert all(f["namespace"].startswith("tn009/") or f["namespace"] == "/" for f in sub["findings"])
    d = vo.diff_documents(full, sub)
    assert d["summary"]["new"] == 0 and d["summary"]["resolved"] > 0


def test_entities_tree_and_seeded_rules(capsys, tmp_path):
    code, doc = run(capsys, "entities", "--output-dir", str(tmp_path), "-w", "8")
    assert code == 0
    assert doc["coverage"]["complete"] is True, doc["coverage"]
    assert doc["summary"]["entities"] > 100
    assert "entity_list" not in json.dumps(doc)  # no metadata/alias names without --list

    code, scoped = run(capsys, "entities", "--output-dir", str(tmp_path), "--namespace", "tn009/soc2/dev", "--list")
    assert code == 0 and scoped["coverage"]["complete"] is True
    rows = {e["name"]: e for r in scoped["namespaces"] for e in r.get("entity_list", [])}
    assert {"vault-ops-orphan", "vault-ops-direct", "vault-ops-disabled"} <= set(rows)
    assert rows["vault-ops-direct"]["metadata"] == {"owner": "vault-ops"}
    assert rows["vault-ops-disabled"]["disabled"] is True
    assert any(e["aliases"] for e in rows.values())  # seeded userpass/approle aliases are listed with names
    fired = {(f["rule_id"], f["object"]["path"]) for f in scoped["findings"]}
    assert {("VT-ID-001", "vault-ops-orphan"), ("VT-ID-002", "vault-ops-direct"), ("VT-ID-003", "vault-ops-disabled")} <= fired
    shared = next(f for f in scoped["findings"] if f["rule_id"] == "VT-ID-005")  # vault-ops-dup-a/-b
    assert shared["evidence"]["shared_alias_names"] >= 1 and "vault-ops-dup" not in json.dumps(shared)
