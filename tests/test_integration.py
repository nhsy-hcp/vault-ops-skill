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

# Rules the dev seed can trip; MOUNT-001/LIC-001/HLTH-* depend on cluster state and are unit-tested.
SEEDED_RULES = {
    "VT-AUTH-001",
    "VT-MOUNT-002",
    "VT-MOUNT-003",
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
    path = capsys.readouterr().out.strip()
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


def test_health(capsys, tmp_path):
    code, doc = run(capsys, "health", "--output-dir", str(tmp_path))
    assert code == 0
    assert doc["health"]["sealed"] is False
    assert doc["health"]["license"]["expiration_time"]
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
