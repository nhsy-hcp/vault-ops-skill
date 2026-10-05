import json
from pathlib import Path

import jsonschema
import pytest
import vault_ops as vo
from test_walker_cli import FakeReader, _ValidatingFake

LISTING = {
    "data": {
        "keys": ["e1", "e2", "e3", "e4"],
        "key_info": {
            "e1": {"name": "alice", "aliases": [{"mount_path": "userpass/", "mount_type": "userpass", "name": "alice"}]},
            "e2": {"name": "orphan", "aliases": []},
            "e3": {"name": "svc", "aliases": [{"mount_path": "approle/", "mount_type": "approle", "name": "8f1c-role-id"}]},
            "e4": {"name": "gone", "aliases": []},
        },
    }
}

ROUTES = {
    ("", "sys/namespaces"): {"data": {"key_info": {"tn001/": {}}}},
    ("tn001", "sys/namespaces"): {"data": {"key_info": {"app/": {}}}},
    ("tn001/app", "sys/namespaces"): vo.hvac_exc.InvalidPath("none"),
    ("", "identity/entity/id"): vo.hvac_exc.InvalidPath("no entities"),
    ("tn001", "identity/entity/id"): vo.hvac_exc.Forbidden("denied"),
    ("tn001/app", "identity/entity/id"): LISTING,
    ("tn001/app", "identity/entity/id/e1"): {"data": {"name": "alice", "metadata": {"email": "alice@example.com"}, "group_ids": ["g1"], "aliases": LISTING["data"]["key_info"]["e1"]["aliases"]}},
    ("tn001/app", "identity/entity/id/e2"): {"data": {"name": "orphan", "aliases": [], "group_ids": []}},
    ("tn001/app", "identity/entity/id/e3"): {"data": {"name": "svc", "policies": ["kv-read", "admin"], "aliases": LISTING["data"]["key_info"]["e3"]["aliases"]}},
    ("tn001/app", "identity/entity/id/e4"): vo.hvac_exc.Forbidden("denied"),
}


def collect(routes=ROUTES, start=""):
    cov = vo.Coverage()
    reader = FakeReader(routes)
    namespaces = vo.discover_namespaces(reader, cov, start, workers=2)
    return cov, namespaces, vo.collect_entities(reader, cov, namespaces, workers=2)


def test_discover_and_collect():
    cov, namespaces, entities = collect()
    assert namespaces == ["", "tn001", "tn001/app"]
    assert entities[""] == [] and entities["tn001"] == []
    by_name = {e.name: e for e in entities["tn001/app"]}
    assert by_name["alice"].group_count == 1 and by_name["alice"].alias_mounts == [{"path": "userpass/", "type": "userpass"}]
    assert by_name["alice"].metadata == {"email": "alice@example.com"}
    assert by_name["svc"].aliases == [{"name": "8f1c-role-id", "mount_path": "approle/", "mount_type": "approle", "metadata": {}}]
    assert by_name["svc"].policies == ["admin", "kv-read"]
    assert by_name["gone"].disabled is None  # body unreadable: listing data only
    assert sorted((d["namespace"], d["scope"]) for d in cov.denied) == [("tn001/", "identity entities"), ("tn001/app/", "identity entity details")]


def test_entity_findings():
    _, _, entities = collect()
    entities["tn001/app"][0].disabled = True  # alice
    found = {(f.rule_id, f.object_path) for f in vo.entity_findings(entities)}
    assert found == {("VT-ID-001", "orphan"), ("VT-ID-001", "gone"), ("VT-ID-002", "svc"), ("VT-ID-003", "alice")}


def test_entities_document_list_and_schema(schema):
    cov, _, entities = collect()
    doc = vo.build_entities_document(entities, cov, {"cluster_name": "c1"}, include_list=True)
    app = next(r for r in doc["namespaces"] if r["namespace"] == "tn001/app/")
    assert app["entities"] == 4 and app["without_aliases"] == 2 and app["with_direct_policies"] == 1
    assert app["alias_mount_types"] == {"approle": 1, "userpass": 1}
    rows = {e["name"]: e for e in app["entity_list"]}
    assert list(rows) == ["alice", "gone", "orphan", "svc"]
    assert rows["alice"]["metadata"] == {"email": "alice@example.com"}
    assert rows["alice"]["aliases"][0]["name"] == "alice" and rows["svc"]["aliases"][0]["name"] == "8f1c-role-id"
    assert doc["summary"]["entities"] == 4 and doc["summary"]["namespaces_with_entities"] == 1
    finding_schema = {**schema["$defs"]["finding"], "$defs": schema["$defs"]}
    for f in doc["findings"]:
        jsonschema.validate(f, finding_schema)


def test_metadata_and_alias_names_only_with_list():
    cov, _, entities = collect()
    text = json.dumps(vo.build_entities_document(entities, cov, {"cluster_name": "c1"}, include_list=False))
    assert "alice@example.com" not in text and "8f1c-role-id" not in text and "entity_list" not in text
    findings_text = json.dumps(vo.build_entities_document(entities, cov, {}, include_list=True)["findings"])
    assert "alice@example.com" not in findings_text and "8f1c-role-id" not in findings_text


def test_every_rule_is_produced_somewhere(cluster_data, health):
    _, _, entities = collect()
    entities["tn001/app"][0].disabled = True
    produced = {
        f.rule_id for f in vo.mount_findings(cluster_data, None) + vo.namespace_findings(cluster_data) + vo.sentinel_findings(cluster_data) + vo.health_findings(health) + vo.entity_findings(entities)
    }
    assert produced == set(vo.RULES)


@pytest.fixture
def cli_env(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_ADDR", "https://v:8200")
    monkeypatch.setenv("VAULT_TOKEN", "t")
    monkeypatch.delenv("VAULT_NAMESPACE", raising=False)
    monkeypatch.setenv("VAULT_OPS_OUTPUT_DIR", str(tmp_path))


def test_entities_cli_scoped(cli_env, monkeypatch, capsys):
    routes = {**ROUTES, ("", "auth/token/lookup-self"): {"data": {}}, ("", "sys/health"): {"cluster_name": "c1", "version": "2.1.1+ent"}}
    monkeypatch.setattr(vo, "VaultReader", lambda cfg: _ValidatingFake(routes))
    assert vo.main(["entities", "--namespace", "tn001/app", "--list"]) == vo.EXIT_OK
    doc = json.loads(Path(capsys.readouterr().out.strip()).read_text())
    assert doc["run"]["start_namespace"] == "tn001/app/"
    assert [r["namespace"] for r in doc["namespaces"]] == ["tn001/app/"]
    assert doc["coverage"]["namespaces_processed"] == 1
