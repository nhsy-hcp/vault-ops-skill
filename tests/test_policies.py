import json
from pathlib import Path

import jsonschema
import pytest
import vault_ops as vo
from test_walker_cli import FakeReader, _ValidatingFake

CANARY = "CANARY-param-value-never-written"

ADMIN = 'path "*" {\n  capabilities = ["create", "read", "update", "delete", "list", "sudo"]\n}\n'
ESCALATE = f"""
# can rewrite policies and mint tokens
path "sys/policies/acl/*" {{ capabilities = ["create", "update"] }}
path "auth/token/create" {{
  capabilities = ["update"]
  allowed_parameters = {{ "policies" = ["{CANARY}"] }}
}}
"""
SUDO = 'path "sys/leases/revoke-force/*" { capabilities = ["update", "sudo"] }'
CLEAN = '// app read access\npath "secret/data/app/*" { capabilities = ["read", "list"] }\npath "*" { capabilities = ["deny"] }'
CLEAN_V2 = 'path "secret/data/app/*" { capabilities = ["read"] }'


def acl(text):
    return {"data": {"name": "x", "policy": text}}


ROUTES = {
    ("", "sys/namespaces"): {"data": {"key_info": {"tn001/": {}, "tn002/": {}}}},
    ("tn001", "sys/namespaces"): vo.hvac_exc.InvalidPath("none"),
    ("tn002", "sys/namespaces"): vo.hvac_exc.InvalidPath("none"),
    ("", "sys/policies/acl"): {"data": {"keys": ["default", "root", "admin", "read-only"]}},
    ("", "sys/policies/acl/default"): acl(CLEAN),
    ("", "sys/policies/acl/admin"): acl(ADMIN),
    ("", "sys/policies/acl/read-only"): acl(CLEAN),
    ("tn001", "sys/policies/acl"): {"data": {"keys": ["read-only", "ops", "broken", "gone"]}},
    ("tn001", "sys/policies/acl/read-only"): acl(CLEAN_V2),  # drifted copy: VT-POL-004
    ("tn001", "sys/policies/acl/ops"): acl(ESCALATE + SUDO),
    ("tn001", "sys/policies/acl/broken"): acl('path "x" { capabilities = ['),
    ("tn002", "sys/policies/acl"): {"data": {"keys": ["read-only"]}},
    ("tn002", "sys/policies/acl/read-only"): vo.hvac_exc.Forbidden("denied"),
}


def collect(routes=ROUTES):
    cov = vo.Coverage()
    reader = FakeReader(routes)
    namespaces = vo.discover_namespaces(reader, cov, "", workers=2)
    return cov, reader, vo.collect_acl_policies(reader, cov, namespaces, workers=2)


@pytest.mark.parametrize(
    "text, expected",
    [
        (CLEAN, (vo.AclRule("secret/data/app/*", ("read", "list")), vo.AclRule("*", ("deny",)))),
        ('{"path": {"sys/*": {"capabilities": ["read"]}}}', (vo.AclRule("sys/*", ("read",)),)),
        ("", ()),
        ('path "a" { capabilities = ["read"], }', (vo.AclRule("a", ("read",)),)),
        ('path "x" { capabilities = [', None),
        ("not a policy", None),
        ('path "x" { /* unterminated', None),
        ('{"path": ["not", "a", "map"]}', None),
    ],
)
def test_parse_acl_policy(text, expected):
    assert vo.parse_acl_policy(text) == expected


def test_parser_drops_parameter_values():
    rules = vo.parse_acl_policy(ESCALATE)
    assert [r.path for r in rules] == ["sys/policies/acl/*", "auth/token/create"]
    assert CANARY not in repr(rules)


@pytest.mark.parametrize(
    "glob, path, expected",
    [
        ("*", "anything/at/all", True),
        ("+/*", "child/sys/auth", True),
        ("sys/*", "sys/policies/acl/x", True),
        ("sys/policies/acl/+", "sys/policies/acl/x", True),
        ("auth/token/create*", "auth/token/create-orphan", True),
        ("auth/token/create", "auth/token/create", True),
        ("secret/*", "sys/auth/x", False),
        ("sys/policies/acl", "sys/policies/acl/x", False),
        ("+/sys/auth/x", "sys/auth/x", False),
    ],
)
def test_glob_matches(glob, path, expected):
    assert vo.glob_matches(glob, path) is expected


def test_rule_flags():
    assert vo.rule_flags(vo.AclRule("*", ("create", "read"))) == ["VT-POL-001"]
    assert vo.rule_flags(vo.AclRule("+/+/*", ("sudo",))) == ["VT-POL-001", "VT-POL-003"]
    assert vo.rule_flags(vo.AclRule("*", ("read", "list"))) == []  # read-everything is not judged
    assert vo.rule_flags(vo.AclRule("*", ("deny",))) == []
    assert vo.rule_flags(vo.AclRule("sys/*", ("update",))) == ["VT-POL-002"]
    assert vo.rule_flags(vo.AclRule("identity/group/id/*", ("update",))) == ["VT-POL-002"]
    assert vo.rule_flags(vo.AclRule("sys/policies/acl/*", ("read", "list"))) == []
    assert vo.rule_flags(vo.AclRule("secret/data/*", ("create", "update", "delete"))) == []


def test_collect_reads_bodies_and_records_denials():
    cov, reader, policies = collect()
    got = {(p.namespace, p.name): p for p in policies}
    assert sorted(got) == [("", "admin"), ("", "default"), ("", "read-only"), ("tn001", "broken"), ("tn001", "ops"), ("tn001", "read-only")]
    assert ("", "sys/policies/acl/root") not in reader.calls  # root is built in and never read
    assert got[("tn001", "broken")].rules is None
    assert got[("", "read-only")].sha256 != got[("tn001", "read-only")].sha256
    assert cov.denied == [{"namespace": "tn002/", "scope": "ACL policy bodies (attach vault-ops-policy-reader)"}]


def test_collect_listing_errors_degrade():
    routes = {
        ("", "sys/namespaces"): {"data": {"key_info": {"a/": {}, "b/": {}, "c/": {}}}},
        **{(ns, "sys/namespaces"): vo.hvac_exc.InvalidPath("none") for ns in ("a", "b", "c")},
        ("", "sys/policies/acl"): {"data": {"keys": ["odd", "boom"]}},
        ("", "sys/policies/acl/odd"): {"data": {"policy": 42}},
        ("", "sys/policies/acl/boom"): vo.hvac_exc.InternalServerError("x"),
        ("a", "sys/policies/acl"): vo.hvac_exc.Forbidden("denied"),
        ("b", "sys/policies/acl"): vo.hvac_exc.InternalServerError("x"),
    }
    cov, _, policies = collect(routes)
    assert policies == []
    assert cov.denied == [{"namespace": "a/", "scope": "ACL policy names"}]
    assert sorted(e["message"] for e in cov.errors) == ["InternalServerError", "InternalServerError", "ValueError"]


def test_findings_and_document(schema):
    cov, _, policies = collect()
    doc = vo.build_policies_document(policies, cov, {"cluster_name": "c1"})
    by_rule = {}
    for f in doc["findings"]:
        by_rule.setdefault(f["rule_id"], []).append(f)
    assert sorted(by_rule) == ["VT-POL-001", "VT-POL-002", "VT-POL-003", "VT-POL-004", "VT-POL-005"]
    (admin,) = by_rule["VT-POL-001"]
    assert (admin["namespace"], admin["object"]["path"], admin["evidence"]["paths"]) == ("/", "admin", ["*"])
    (escalate,) = by_rule["VT-POL-002"]
    assert escalate["evidence"]["areas"] == ["ACL policies", "token creation"]
    assert {(f["namespace"], f["object"]["path"]) for f in by_rule["VT-POL-003"]} == {("/", "admin"), ("tn001/", "ops")}
    (drift,) = by_rule["VT-POL-004"]
    assert (drift["object"]["path"], drift["evidence"]["variants"], drift["evidence"]["namespaces"]) == ("read-only", 2, 2)
    assert by_rule["VT-POL-005"][0]["object"]["path"] == "broken"
    rows = {(r["namespace"], r["name"]): r for r in doc["policies"]}
    assert rows[("/", "default")]["flagged"] == [] and rows[("/", "default")]["rule_count"] == 2
    assert rows[("tn001/", "ops")]["flagged"][0] == {"path": "sys/policies/acl/*", "capabilities": ["create", "update"], "rules": ["VT-POL-002"]}
    assert rows[("tn001/", "broken")] | {"sha256": None} == {"namespace": "tn001/", "name": "broken", "sha256": None, "parsed": False, "rule_count": None, "flagged": []}
    assert doc["summary"] | {"by_rule": None} == {"policies": 6, "names": 5, "distinct_bodies": 5, "unparsed": 1, "with_flagged_rules": 2, "by_rule": None}
    finding_schema = {**schema["$defs"]["finding"], "$defs": schema["$defs"]}
    for f in doc["findings"]:
        jsonschema.validate(f, finding_schema)


def test_bodies_never_written():
    cov, _, policies = collect()
    text = json.dumps(vo.build_policies_document(policies, cov, {}))
    assert CANARY not in text and "capabilities =" not in text and "allowed_parameters" not in text and "app read access" not in text


@pytest.fixture
def cli_env(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_ADDR", "https://v:8200")
    monkeypatch.setenv("VAULT_TOKEN", "t")
    monkeypatch.delenv("VAULT_NAMESPACE", raising=False)
    monkeypatch.setenv("VAULT_OPS_OUTPUT_DIR", str(tmp_path))


def test_policies_cli(cli_env, monkeypatch, capsys):
    routes = {**ROUTES, ("", "auth/token/lookup-self"): {"data": {}}, ("", "sys/health"): {"cluster_name": "c1", "version": "2.1.1+ent"}}
    monkeypatch.setattr(vo, "VaultReader", lambda cfg: _ValidatingFake(routes))
    assert vo.main(["policies", "-w", "2"]) == vo.EXIT_OK
    path = Path(capsys.readouterr().out.strip())
    assert "c1-policies-" in path.name and path.stat().st_mode & 0o777 == 0o600
    doc = json.loads(path.read_text())
    assert doc["coverage"]["namespaces_processed"] == 3 and doc["coverage"]["complete"] is False
    assert CANARY not in path.read_text()


def test_policies_refused_on_dr_secondary(cli_env, monkeypatch, capsys):
    monkeypatch.setattr(vo, "VaultReader", lambda cfg: _ValidatingFake({("", "sys/health"): {"replication_dr_mode": "secondary"}}))
    assert vo.main(["policies"]) == vo.EXIT_FATAL
    assert "DR secondary" in capsys.readouterr().err
