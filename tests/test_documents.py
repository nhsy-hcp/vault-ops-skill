import json
import stat

import jsonschema
import vault_ops as vo
from conftest import FAKE_TOKEN


def build(cluster_data, health, coverage=None):
    coverage = coverage or vo.Coverage(namespaces_processed=4)
    findings = vo.mount_findings(cluster_data, 2764800) + vo.namespace_findings(cluster_data) + vo.sentinel_findings(cluster_data) + vo.health_findings(health)
    run = vo.run_block("c1", "https://vault.example:8200", "", vo.utc_now(), 4)
    return vo.build_findings_document(findings, coverage, health, cluster_data.sentinel, run)


def test_document_validates_and_covers_every_rule(cluster_data, health, schema):
    doc = build(cluster_data, health)
    jsonschema.validate(doc, schema)
    assert set(doc["summary"]["by_rule"]) == {r for r in vo.RULES if not r.startswith("VT-ID-")}  # ID rules: entities
    assert doc["summary"]["total"] == len(doc["findings"])
    assert sum(doc["summary"]["by_severity"].values()) == doc["summary"]["total"]
    assert doc["coverage"]["complete"] is True


def test_findings_sorted_by_severity(cluster_data, health):
    severities = [f["severity"] for f in build(cluster_data, health)["findings"]]
    assert severities == sorted(severities, key=vo.SEVERITIES.index)


def test_coverage_gaps_recorded(cluster_data, health, schema):
    cov = vo.Coverage()
    cov.deny("team-a", "child namespaces (subtree not audited)")
    cov.error("", vo.hvac_exc.InternalServerError("boom http://x/v1/y"))
    doc = build(cluster_data, health, cov)
    jsonschema.validate(doc, schema)
    assert doc["coverage"]["complete"] is False
    assert doc["coverage"]["denied"] == [{"namespace": "team-a/", "scope": "child namespaces (subtree not audited)"}]
    assert doc["coverage"]["errors"][0]["message"] == "InternalServerError"


def test_no_secrets_in_output(cluster_data, health):
    cluster_data.namespaces["team-a"]["custom_metadata"] = {"owner": "alice@example.com"}
    text = json.dumps(build(cluster_data, health))
    assert FAKE_TOKEN not in text
    assert "alice@example.com" not in text
    assert "rule { real }" not in text and "rule { true" not in text  # no Sentinel source


def test_exit_codes(cluster_data, health):
    doc = build(cluster_data, health)
    assert vo.exit_code_for(doc, None, False) == vo.EXIT_OK
    assert vo.exit_code_for(doc, "medium", False) == vo.EXIT_FINDINGS
    clean = {**doc, "findings": [f for f in doc["findings"] if f["severity"] == "info"]}
    assert vo.exit_code_for(clean, "low", False) == vo.EXIT_OK
    gaps = {**clean, "coverage": {**doc["coverage"], "complete": False}}
    assert vo.exit_code_for(gaps, None, True) == vo.EXIT_GAPS
    assert vo.exit_code_for({**doc, "coverage": gaps["coverage"]}, "info", True) == vo.EXIT_FINDINGS


def test_write_json_mode_0600(tmp_path):
    path = vo.write_json(tmp_path / "sub" / "x.json", {"a": 1})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text()) == {"a": 1}


def test_diff(cluster_data, health):
    old = build(cluster_data, health)
    cluster_data.auth[""]["userpass/"]["config"] = {}  # resolves VT-AUTH-001
    cluster_data.secrets[""]["long/"]["config"]["max_lease_ttl"] = 400 * 24 * 3600  # evidence change
    cluster_data.secrets["team-b"]["kv/"] = {"type": "kv", "local": True, "config": {}}  # resolves VT-NS-002, adds -003
    new = build(cluster_data, health)
    d = vo.diff_documents(old, new)
    assert sorted(f["rule_id"] for f in d["resolved"]) == ["VT-AUTH-001", "VT-NS-002"]
    assert [f["rule_id"] for f in d["new"]] == ["VT-MOUNT-003"]
    assert d["summary"]["evidence_changed"] == 1
    assert d["summary"]["unchanged"] == len(d["unchanged"])


def test_inventory_document(cluster_data):
    doc = vo.build_inventory_document(cluster_data, vo.Coverage(), {"cluster_name": "c1"})
    assert doc["summary"]["namespaces"] == 4
    root = next(r for r in doc["namespaces"] if r["namespace"] == "/")
    assert [m["path"] for m in root["secrets_mounts"]] == ["long/", "old/"]  # built-ins omitted
    assert root["egp_policies"] == ["adv", "wild"]
    assert "custom_metadata" not in json.dumps(doc)


def test_usage_document():
    activity = {
        "start_time": "2026-01-01T00:00:00Z",
        "end_time": "2026-09-30T23:59:59Z",
        "total": {"clients": 7, "entity_clients": 5, "non_entity_clients": 2},
        "by_namespace": [
            {"namespace_path": "", "counts": {"clients": 2}, "mounts": [{}]},
            {"namespace_path": "tn001/kubernetes/prod/", "counts": {"clients": 5}, "mounts": [{}, {}]},
        ],
        "months": [{"timestamp": "2026-09-01T00:00:00Z", "counts": {"clients": 7}}],
    }
    current = {"clients": 9, "entity_clients": 9, "by_namespace": [{}, {}]}
    doc = vo.build_usage_document(activity, 1, {"cluster_name": "c1"}, vo.Coverage(), current)
    assert doc["current_month"] == {"total": {"clients": 9, "entity_clients": 9}, "namespaces_reported": 2}
    assert vo.build_usage_document({}, 1, {}, vo.Coverage())["current_month"] is None
    assert doc["total"] == {"clients": 7, "entity_clients": 5, "non_entity_clients": 2}
    assert doc["namespaces_reported"] == 2
    assert doc["top_namespaces"] == [{"namespace": "tn001/kubernetes/prod/", "counts": {"clients": 5}, "mounts": 2}]
