"""DR integration tests: need `task up:all && task dr:enable` (and `task token:audit`).

Skipped unless the DR secondary at VAULT_DR_ADDR answers as a DR secondary.
"""

import json
import os
from pathlib import Path

import pytest
import requests
import vault_ops as vo

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def dr_addr():
    addr = os.getenv("VAULT_DR_ADDR")
    if not addr or not os.getenv("VAULT_TOKEN"):
        pytest.skip("VAULT_DR_ADDR/VAULT_TOKEN not set")
    try:
        health = requests.get(f"{addr}/v1/sys/health", params={"drsecondarycode": "200"}, verify=False, timeout=3).json()
    except (requests.RequestException, ValueError):
        pytest.skip(f"DR node not reachable at {addr}")
    if health.get("replication_dr_mode") != "secondary":
        pytest.skip("DR node is not an active DR secondary (run: task dr:enable)")
    return addr


def run(capsys, *args):
    code = vo.main(list(args))
    out = capsys.readouterr()
    return code, (json.loads(Path(out.out.strip()).read_text()) if code == 0 else out.err)


def test_primary_reports_connected_dr_secondary(dr_addr, capsys, tmp_path):
    code, doc = run(capsys, "health", "--output-dir", str(tmp_path))
    assert code == 0
    dr = doc["health"]["replication"]["dr"]
    assert dr["mode"] == "primary" and dr["state"] == "running"
    assert {"node_id": "vault-dr", "connection_status": "connected"} in [{k: s[k] for k in ("node_id", "connection_status")} for s in dr["secondaries"]]
    assert not [f for f in doc["findings"] if f["rule_id"] == "VT-HLTH-002" and f["object"]["type"] == "dr"]
    assert doc["coverage"]["complete"] is True


def test_secondary_health_without_token_endpoints(dr_addr, capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", dr_addr)
    code, doc = run(capsys, "health", "--output-dir", str(tmp_path))
    assert code == 0
    h = doc["health"]
    assert h["dr_secondary"] is True and h["sealed"] is False
    assert h["replication"]["dr"]["mode"] == "secondary"
    assert h["replication"]["dr"]["state"] == "stream-wals"
    assert [p["connection_status"] for p in h["replication"]["dr"]["primaries"]] == ["connected"]
    assert h["license"] is None and h["lease_ttls"] is None
    assert doc["coverage"]["complete"] is True
    assert not [f for f in doc["findings"] if f["rule_id"] in ("VT-HLTH-001", "VT-HLTH-002")]


def test_secondary_refuses_audit(dr_addr, capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", dr_addr)
    code, err = run(capsys, "audit", "--output-dir", str(tmp_path))
    assert code == vo.EXIT_FATAL
    assert "DR secondary" in err
