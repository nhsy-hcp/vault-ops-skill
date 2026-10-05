"""OSS smoke tests: need a Community `vault server -dev` set up by `task test:oss` (scripts/test_oss.sh).

Community has no namespaces, Sentinel, license, Raft or automated snapshots: every subcommand must
still exit 0 with complete coverage and report those features as absent, not as errors.
"""

import json
import os
from pathlib import Path

import jsonschema
import pytest
import vault_ops as vo

MODE = os.getenv("VAULT_OPS_OSS")  # "1" = unsealed pass, "sealed" = after scripts/test_oss.sh seals the server
pytestmark = [pytest.mark.oss, pytest.mark.skipif(MODE not in ("1", "sealed"), reason="run with task test:oss")]
unsealed = pytest.mark.skipif(MODE != "1", reason="unsealed pass only")
sealed = pytest.mark.skipif(MODE != "sealed", reason="sealed pass only")


def run(capsys, *args):
    code = vo.main(list(args))
    paths = capsys.readouterr().out.split()
    return code, [json.loads(Path(p).read_text()) for p in paths]


@unsealed
def test_audit(capsys, tmp_path, schema):
    code, (findings, inventory) = run(capsys, "audit", "--fail-on-gaps", "--output-dir", str(tmp_path))
    assert code == vo.EXIT_OK
    jsonschema.validate(findings, schema)
    assert findings["coverage"] == {"namespaces_processed": 1, "complete": True, "denied": [], "errors": []}
    assert findings["cluster_context"]["sentinel"] == "unsupported"
    assert findings["cluster_context"]["enterprise"] is False
    assert {"VT-AUD-001", "VT-MOUNT-006"} <= set(findings["summary"]["by_rule"])
    assert not any(r.startswith("VT-SNT-") for r in findings["summary"]["by_rule"])
    assert inventory["summary"]["sentinel"] == "unsupported" and inventory["summary"]["namespaces"] == 1


@unsealed
def test_health(capsys, tmp_path):
    code, (doc,) = run(capsys, "health", "--output-dir", str(tmp_path))
    assert code == vo.EXIT_OK
    health = doc["health"]
    assert health["enterprise"] is False and health["sealed"] is False
    assert (health["license"], health["raft"], health["snapshots"]) == (None, None, None)
    assert health["replication"]["mode"] == "disabled"


@unsealed
@pytest.mark.parametrize("args", [["inventory"], ["usage"], ["entities"], ["entities", "--list"]])
def test_other_subcommands(capsys, tmp_path, args):
    code, (doc,) = run(capsys, *args, "--output-dir", str(tmp_path))
    assert code == vo.EXIT_OK
    assert doc["coverage"]["complete"] is True, doc["coverage"]


@unsealed
def test_policies(capsys, tmp_path):
    code, (doc,) = run(capsys, "policies", "--output-dir", str(tmp_path))
    assert code == vo.EXIT_OK
    assert doc["coverage"]["complete"] is True, doc["coverage"]
    assert doc["sentinel"]["status"] == "unsupported" and doc["sentinel"]["policies"] == []
    assert ("VT-POL-001", "admin") in {(f["rule_id"], f["object"]["path"]) for f in doc["findings"]}


@sealed
def test_sealed_health(capsys, tmp_path):
    """Regression: a sealed node made every subcommand, `health` included, exit 1 with VaultDown."""
    code, (doc,) = run(capsys, "health", "--output-dir", str(tmp_path))
    assert code == vo.EXIT_OK
    assert doc["health"]["sealed"] is True and doc["health"]["seal"]["type"] == "shamir"
    assert doc["coverage"]["complete"] is True
    assert [f["rule_id"] for f in doc["findings"]] == ["VT-HLTH-001"]


@sealed
@pytest.mark.parametrize("command", ["audit", "inventory", "usage", "entities", "policies"])
def test_sealed_refuses_authenticated_subcommands(capsys, tmp_path, command):
    assert vo.main([command, "--output-dir", str(tmp_path)]) == vo.EXIT_FATAL
    assert "is sealed" in capsys.readouterr().err
