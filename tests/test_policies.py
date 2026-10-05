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


# --------------------------------------------------------------------------- Sentinel

SNT_CANARY = "CANARY-sentinel-source-never-written"
NOOP = f'# {SNT_CANARY}\nimport "time"\n\nmain = rule {{ time.now.unix > 0 }}\n'
NOOP_V2 = 'import "time"\n\nmain = rule { time.now.unix >= 0 }\n'
LOCKOUT = 'import "time"\n// deny everything\nmain = rule {\n  false\n}\n'
HTTP = 'import "http"\nimport "strings"\n\nmain = rule { true and request.path is not "" }\n'


def snt(level, text, paths=None):
    return {"data": {"enforcement_level": level, "policy": text, **({"paths": paths} if paths is not None else {})}}


SENTINEL_ROUTES = {
    ("", "sys/policies/egp"): {"data": {"keys": ["adv", "lockout", "soft-false"]}},
    ("", "sys/policies/egp/adv"): snt("advisory", NOOP, ["*"]),  # VT-SNT-001, -003
    ("", "sys/policies/egp/lockout"): snt("hard-mandatory", LOCKOUT, ["sys/*", "secret/*"]),  # VT-SNT-006
    ("", "sys/policies/egp/soft-false"): snt("soft-mandatory", LOCKOUT, ["kv/*"]),  # VT-SNT-002, not -006
    ("", "sys/policies/rgp"): {"data": {"keys": ["hard", "trivial"]}},
    ("", "sys/policies/rgp/hard"): snt("hard-mandatory", NOOP),  # control
    ("", "sys/policies/rgp/trivial"): snt("hard-mandatory", "# c\nmain = rule { true }"),  # VT-SNT-004
    ("tn001", "sys/policies/egp"): {"data": {"keys": ["http"]}},
    ("tn001", "sys/policies/egp/http"): snt("hard-mandatory", HTTP, ["secret/data/x/*"]),  # VT-SNT-007
    ("tn001", "sys/policies/rgp"): {"data": {"keys": ["hard"]}},
    ("tn001", "sys/policies/rgp/hard"): snt("hard-mandatory", NOOP_V2),  # drifted copy: VT-SNT-005
    ("tn002", "sys/policies/egp"): {"data": {"keys": ["locked"]}},
    ("tn002", "sys/policies/egp/locked"): vo.hvac_exc.Forbidden("denied"),
    ("tn002", "sys/policies/rgp"): vo.hvac_exc.Forbidden("denied"),
}


def collect_sentinel(routes=None):
    routes = routes or {**ROUTES, **SENTINEL_ROUTES}
    cov = vo.Coverage()
    reader = FakeReader(routes)
    namespaces = vo.discover_namespaces(reader, cov, "", workers=2)
    return cov, reader, vo.collect_sentinel_policies(reader, cov, namespaces, workers=2)


@pytest.mark.parametrize(
    "text, expected",
    [
        ("main = rule { false }", True),
        ('import "time"\n# x\nmain = rule {\n  false\n}', True),
        ("main = false", True),
        ("main = rule { true }", False),
        ("x = false\nmain = rule { x }", False),
        (None, False),
    ],
)
def test_is_always_false_policy(text, expected):
    assert vo.is_always_false_policy(text) is expected


def test_collect_sentinel_hashes_and_records_denials():
    cov, _, (status, policies) = collect_sentinel()
    assert status == "supported"
    got = {(p.namespace, p.kind, p.name): p for p in policies}
    assert sorted(got) == [("", "egp", "adv"), ("", "egp", "lockout"), ("", "egp", "soft-false"), ("", "rgp", "hard"), ("", "rgp", "trivial"), ("tn001", "egp", "http"), ("tn001", "rgp", "hard")]
    assert got[("", "egp", "lockout")].paths == ("secret/*", "sys/*") and got[("", "egp", "lockout")].always_false
    assert got[("", "rgp", "hard")].paths == () and got[("", "rgp", "hard")].imports == ("time",)
    assert got[("tn001", "egp", "http")].imports == ("http", "strings")
    assert got[("", "rgp", "hard")].sha256 != got[("tn001", "rgp", "hard")].sha256
    assert sorted(d["scope"] for d in cov.denied) == ["sentinel EGP policy bodies (attach vault-ops-sentinel-reader)", "sentinel RGP policies"]
    assert cov.errors == []


@pytest.mark.parametrize("message", ["1 error occurred: unsupported path", "enterprise-only feature"])
def test_collect_sentinel_unsupported_stops_probing(message):
    routes = {**ROUTES, ("", "sys/policies/egp"): vo.hvac_exc.InvalidPath(message)}
    cov, reader, (status, policies) = collect_sentinel(routes)
    assert (status, policies, cov.errors, cov.denied) == ("unsupported", [], [], [])
    assert [c for c in reader.calls if c[1].startswith(("sys/policies/egp", "sys/policies/rgp"))] == [("", "sys/policies/egp")]


def test_collect_sentinel_odd_payload_is_an_error():
    routes = {**ROUTES, ("", "sys/policies/egp"): {"data": {"keys": ["odd"]}}, ("", "sys/policies/egp/odd"): {"data": {"policy": 7}}}
    cov, _, (status, policies) = collect_sentinel(routes)
    assert (status, policies) == ("supported", [])
    assert [e["message"] for e in cov.errors] == ["ValueError"]


def test_sentinel_findings_and_block(schema):
    cov, _, (status, sentinel) = collect_sentinel()
    doc = vo.build_policies_document([], cov, {}, status, sentinel)
    fired = sorted((f["rule_id"], f["namespace"], f["object"]["path"]) for f in doc["findings"])
    assert fired == [
        ("VT-SNT-001", "/", "adv"),
        ("VT-SNT-002", "/", "soft-false"),
        ("VT-SNT-003", "/", "adv"),
        ("VT-SNT-004", "/", "trivial"),
        ("VT-SNT-005", "/", "hard"),
        ("VT-SNT-006", "/", "lockout"),
        ("VT-SNT-007", "tn001/", "http"),
    ]
    by_rule = {f["rule_id"]: f for f in doc["findings"]}
    assert by_rule["VT-SNT-005"]["evidence"] | {"examples": None} == {"namespaces": 2, "variants": 2, "outliers": 1, "examples": None}
    assert by_rule["VT-SNT-006"]["evidence"]["paths"] == ["secret/*", "sys/*"]
    assert by_rule["VT-SNT-007"]["evidence"]["imports"] == ["http", "strings"]
    block = doc["sentinel"]
    assert block["status"] == "supported"
    assert block["summary"] == {"egp": 4, "rgp": 3, "distinct_bodies": 5, "by_enforcement": {"advisory": 1, "hard-mandatory": 5, "soft-mandatory": 1}}
    rows = {(r["namespace"], r["kind"], r["name"]): r for r in block["policies"]}
    assert rows[("/", "egp", "adv")] | {"sha256": None} == {
        "namespace": "/",
        "kind": "egp",
        "name": "adv",
        "enforcement_level": "advisory",
        "paths": ["*"],
        "sha256": None,
        "imports": ["time"],
        "flagged": ["VT-SNT-001", "VT-SNT-003"],
    }
    assert rows[("/", "rgp", "hard")]["flagged"] == []
    assert doc["summary"]["by_rule"] == {r: 1 for r in ("VT-SNT-001", "VT-SNT-002", "VT-SNT-003", "VT-SNT-004", "VT-SNT-005", "VT-SNT-006", "VT-SNT-007")}
    finding_schema = {**schema["$defs"]["finding"], "$defs": schema["$defs"]}
    for f in doc["findings"]:
        jsonschema.validate(f, finding_schema)


def test_sentinel_rules_match_audit():
    """VT-SNT-001..004 must read the same in `policies` and `audit`, so `diff` stays consistent."""
    routes = {**ROUTES, **SENTINEL_ROUTES}
    _, _, (_, sentinel) = collect_sentinel(routes)
    data = vo.ClusterData(
        egp={"": {n: routes[("", f"sys/policies/egp/{n}")]["data"] for n in ("adv", "lockout", "soft-false")}, "tn001": {"http": routes[("tn001", "sys/policies/egp/http")]["data"]}},
        rgp={"": {n: routes[("", f"sys/policies/rgp/{n}")]["data"] for n in ("hard", "trivial")}, "tn001": {"hard": routes[("tn001", "sys/policies/rgp/hard")]["data"]}},
    )
    shared = [f.to_dict() for f in vo.sentinel_policy_findings(sentinel) if f.rule_id <= "VT-SNT-004"]
    assert sorted(shared, key=lambda f: f["fingerprint"]) == sorted((f.to_dict() for f in vo.sentinel_findings(data)), key=lambda f: f["fingerprint"])


def test_sentinel_source_never_written():
    cov, _, (status, sentinel) = collect_sentinel()
    text = json.dumps(vo.build_policies_document([], cov, {}, status, sentinel))
    assert SNT_CANARY not in text and "main = rule" not in text and 'import \\"' not in text and "deny everything" not in text


def test_policies_cli_sentinel(cli_env, monkeypatch, capsys):
    routes = {**ROUTES, **SENTINEL_ROUTES, ("", "auth/token/lookup-self"): {"data": {}}, ("", "sys/health"): {"cluster_name": "c1", "version": "2.1.1+ent"}}
    readers = []
    monkeypatch.setattr(vo, "VaultReader", lambda cfg: readers.append(_ValidatingFake(routes)) or readers[-1])
    assert vo.main(["policies"]) == vo.EXIT_OK
    doc = json.loads(Path(capsys.readouterr().out.strip()).read_text())
    assert doc["sentinel"]["status"] == "supported" and "VT-SNT-006" in doc["summary"]["by_rule"]
    assert vo.main(["policies", "--no-sentinel"]) == vo.EXIT_OK
    doc = json.loads(Path(capsys.readouterr().out.strip()).read_text())
    assert doc["sentinel"] == {"status": "skipped", "policies": [], "summary": {"egp": 0, "rgp": 0, "distinct_bodies": 0, "by_enforcement": {}}}
    assert not any("egp" in path or "rgp" in path for _, path in readers[-1].calls)
