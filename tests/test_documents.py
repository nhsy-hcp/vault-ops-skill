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
    # ID: entities, CLI: usage, POL: policies; AUD-001/SNAP-001 exclude the fixture's AUD-002/003 and SNAP-002/003 (see test_every_rule_is_produced_somewhere)
    expected = {r for r in vo.RULES if not r.startswith(("VT-ID-", "VT-CLI-", "VT-POL-"))} - {"VT-AUD-001", "VT-SNAP-001"}
    assert set(doc["summary"]["by_rule"]) == expected
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
    cluster_data.secrets["team-b"]["kv/"] = {"type": "kv", "local": True, "options": {"version": "2"}, "config": {}}  # resolves VT-NS-002, adds -003
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
    assert (root["depth"], root["auth_count"], root["secrets_count"], root["acl_policy_count"]) == (0, 2, 2, 1)
    summary = doc["summary"]
    assert summary["max_depth"] == 2
    assert summary["auth_types"]["ns_token"] == {"mounts": 3, "namespaces": 3}
    assert summary["secrets_types"]["kv"] == {"mounts": 24, "namespaces": 3}
    assert "ns_system" not in summary["secrets_types"]
    assert summary["auth_mounts_total"] == 7 and summary["secrets_mounts_total"] == 24
    assert (summary["egp_policies"], summary["rgp_policies"]) == (2, 3)
    assert summary["acl_policies_top"] == [{"namespace": "/", "count": 1}, {"namespace": "team-a/prod/", "count": 1}]
    assert summary["sentinel_by_enforcement"] == {"advisory": 1, "hard-mandatory": 3, "soft-mandatory": 1}
    assert sum(s["count"] for s in summary["shapes"]) == 4
    assert summary["shapes"][0] == {"depth": 0, "auth_types": ["token", "userpass"], "secrets_types": ["kv", "kv"], "count": 1, "examples": ["/"]}
    dumped = json.dumps(doc)
    assert "custom_metadata" not in dumped and "main = rule" not in dumped  # no namespace metadata, no Sentinel source


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
    assert doc["findings"] == []  # below every client threshold


def test_usage_document_findings_validate(activity, schema):
    doc = vo.build_usage_document(activity, 5, {"cluster_name": "c1"}, vo.Coverage(), None, enterprise=True)
    assert sorted(f["rule_id"] for f in doc["findings"]) == ["VT-CLI-001", "VT-CLI-002", "VT-CLI-003", "VT-CLI-004"]
    finding_schema = {**schema["$defs"]["finding"], "$defs": schema["$defs"]}
    for f in doc["findings"]:
        jsonschema.validate(f, finding_schema)


def test_default_output_dir_is_project_local_and_gitignored(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("VAULT_OPS_OUTPUT_DIR", raising=False)
    args = vo.build_parser().parse_args(["diff", "a", "b"])
    assert args.output_dir == vo.DEFAULT_OUTPUT_DIR
    path = vo.write_json(vo.output_path(args.output_dir, "c1", "health", vo.utc_now()), {})
    assert path.parent == tmp_path / ".tmp" / "vault-ops"
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert (path.parent / ".gitignore").read_text().splitlines()[-1] == "*"
    existing = tmp_path / "existing"
    existing.mkdir()
    vo.write_json(vo.output_path(str(existing), "c1", "health", vo.utc_now()), {})
    assert not (existing / ".gitignore").exists()  # never drop files into a directory the script didn't create
    monkeypatch.setenv("VAULT_OPS_OUTPUT_DIR", str(tmp_path / "custom"))
    assert vo.build_parser().parse_args(["diff", "a", "b"]).output_dir == str(tmp_path / "custom")
