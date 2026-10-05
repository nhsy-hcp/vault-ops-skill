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

pytestmark = [pytest.mark.oss, pytest.mark.skipif(os.getenv("VAULT_OPS_OSS") != "1", reason="run with task test:oss")]


def run(capsys, *args):
    code = vo.main(list(args))
    paths = capsys.readouterr().out.split()
    return code, [json.loads(Path(p).read_text()) for p in paths]


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


def test_health(capsys, tmp_path):
    code, (doc,) = run(capsys, "health", "--output-dir", str(tmp_path))
    assert code == vo.EXIT_OK
    health = doc["health"]
    assert health["enterprise"] is False and health["sealed"] is False
    assert (health["license"], health["raft"], health["snapshots"]) == (None, None, None)
    assert health["replication"]["mode"] == "disabled"


@pytest.mark.parametrize("args", [["inventory"], ["usage"], ["entities"], ["entities", "--list"]])
def test_other_subcommands(capsys, tmp_path, args):
    code, (doc,) = run(capsys, *args, "--output-dir", str(tmp_path))
    assert code == vo.EXIT_OK
    assert doc["coverage"]["complete"] is True, doc["coverage"]


def test_policies(capsys, tmp_path):
    code, (doc,) = run(capsys, "policies", "--output-dir", str(tmp_path))
    assert code == vo.EXIT_OK
    assert doc["coverage"]["complete"] is True, doc["coverage"]
    assert doc["sentinel"]["status"] == "unsupported" and doc["sentinel"]["policies"] == []
    assert ("VT-POL-001", "admin") in {(f["rule_id"], f["object"]["path"]) for f in doc["findings"]}
