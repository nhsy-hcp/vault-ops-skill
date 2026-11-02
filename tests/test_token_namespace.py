"""Tokens created in a child namespace (`admin/` here; any Vault Enterprise namespace):
validation, scoped health, usage, fingerprints."""

import json
from pathlib import Path

import jsonschema
import pytest
import vault_ops as vo
from conftest import FAKE_TOKEN
from test_walker_cli import _ValidatingFake, mounts

DENIED = vo.Forbidden("permission denied")

# Root-only cluster endpoints: a child-namespace token is refused there. Reading any of them in scoped mode is a bug.
ROOT_ONLY = (
    "sys/license/status",
    "sys/config/state/sanitized",
    "sys/storage/raft/configuration",
    "sys/storage/raft/autopilot/configuration",
    "sys/storage/raft/autopilot/state",
    "sys/audit",
    "sys/storage/raft/snapshot-auto/config",
    "sys/metrics",
)

ADMIN_ROUTES = {
    ("", "sys/health"): {"cluster_name": "c1", "version": "2.1.1+ent", "sealed": False},
    ("admin", "auth/token/lookup-self"): {"data": {"namespace_path": "admin/", "policies": ["vault-ops-readonly"]}},
    ("", "auth/token/lookup-self"): DENIED,
    # Unauthenticated, but a platform may still refuse them to a child-namespace token: no coverage gap.
    ("", "sys/leader"): DENIED,
    ("", "sys/replication/status"): DENIED,
    **{("", path): DENIED for path in ROOT_ONLY},
    ("admin", "sys/auth"): mounts(token="ns_token", userpass="userpass"),
    ("admin", "sys/mounts"): mounts(sys="ns_system", secret="kv"),
    ("admin", "sys/policies/acl"): {"data": {"keys": ["default"]}},
    ("admin", "sys/namespaces"): {"data": {"key_info": {"tn001/": {"id": "n1"}}}},
    ("admin/tn001", "sys/auth"): mounts(token="ns_token"),  # VT-NS-001: no auth method besides token
    ("admin/tn001", "sys/mounts"): mounts(sys="ns_system"),
    ("admin/tn001", "sys/policies/acl"): {"data": {"keys": []}},
}


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_ADDR", "https://vault.example:8200")
    monkeypatch.setenv("VAULT_TOKEN", FAKE_TOKEN)
    monkeypatch.setenv("VAULT_SKIP_VERIFY", "true")
    monkeypatch.setenv("VAULT_NAMESPACE", "admin")
    monkeypatch.setenv("VAULT_OPS_OUTPUT_DIR", str(tmp_path))
    return tmp_path


def run(monkeypatch, capsys, routes, argv):
    readers = []
    monkeypatch.setattr(vo, "VaultReader", lambda cfg: readers.append(_ValidatingFake(routes, cfg)) or readers[-1])
    code = vo.main(argv)
    paths = capsys.readouterr().out.split()
    return code, [json.loads(Path(p).read_text()) for p in paths], readers[-1]


def test_child_token_audit_skips_root_only_reads(env, monkeypatch, capsys, schema):
    code, (findings, inventory), fake = run(monkeypatch, capsys, ADMIN_ROUTES, ["audit", "--fail-on-gaps"])
    assert code == vo.EXIT_OK  # no gaps: nothing root-only was attempted or recorded as denied
    assert ("admin", "auth/token/lookup-self") in fake.calls and ("", "auth/token/lookup-self") not in fake.calls
    assert not {path for _, path in fake.calls} & set(ROOT_ONLY)
    assert findings["run"]["token_namespace"] == "admin/" and findings["run"]["start_namespace"] == "admin/"
    assert findings["coverage"]["complete"] is True and findings["coverage"]["denied"] == []
    assert findings["cluster_context"]["system_max_lease_ttl_seconds"] is None
    assert "VT-NS-001" in {f["rule_id"] for f in findings["findings"]}
    assert {f["namespace"] for f in findings["findings"]} <= {"admin/", "admin/tn001/"}  # full paths, nothing at root
    assert [r["namespace"] for r in inventory["namespaces"]] == ["admin/", "admin/tn001/"]
    jsonschema.validate(findings, schema)


def test_child_token_health_leaves_platform_blocks_null(env, monkeypatch, capsys):
    code, (doc,), _ = run(monkeypatch, capsys, ADMIN_ROUTES, ["health"])
    assert code == vo.EXIT_OK
    health = doc["health"]
    assert all(health[k] is None for k in ("leader", "license", "replication", "raft", "lease_ttls", "audit_devices", "snapshots", "metrics"))
    assert doc["coverage"]["complete"] is True and doc["findings"] == []
    assert doc["run"]["token_namespace"] == "admin/" and doc["run"]["start_namespace"] == "admin/"


def test_child_token_still_reads_unauthenticated_replication_status(env, monkeypatch, capsys):
    routes = {**ADMIN_ROUTES, ("", "sys/replication/status"): {"data": {"dr": {"mode": "disabled"}, "performance": {"mode": "disabled"}}}}
    _, (doc,), _ = run(monkeypatch, capsys, routes, ["health"])
    assert doc["health"]["replication"]["dr"]["mode"] == "disabled"


def test_child_token_without_namespace_explains_the_fix(env, monkeypatch, capsys):
    monkeypatch.delenv("VAULT_NAMESPACE")
    monkeypatch.setattr(vo, "VaultReader", lambda cfg: _ValidatingFake(ADMIN_ROUTES, cfg))
    assert vo.main(["audit"]) == vo.EXIT_FATAL
    err = capsys.readouterr().err
    assert "namespace /" in err and "VAULT_NAMESPACE=admin" in err and FAKE_TOKEN not in err


def test_any_enterprise_child_namespace_is_scoped(env, monkeypatch, capsys):
    """Any namespace name and depth: a token created in team-x/ with VAULT_NAMESPACE=team-x/apps is scoped the same way."""
    monkeypatch.setenv("VAULT_NAMESPACE", "team-x/apps")
    routes = {
        ("", "sys/health"): {"cluster_name": "c1", "version": "2.1.1+ent", "sealed": False},
        ("team-x/apps", "auth/token/lookup-self"): {"data": {"namespace_path": "team-x/", "policies": ["vault-ops-readonly"]}},
        **{("", path): DENIED for path in ROOT_ONLY},
    }
    code, (doc,), fake = run(monkeypatch, capsys, routes, ["health"])
    assert code == vo.EXIT_OK and doc["run"]["token_namespace"] == "team-x/" and doc["run"]["start_namespace"] == "team-x/apps/"
    assert not {path for _, path in fake.calls} & set(ROOT_ONLY) and doc["coverage"]["complete"] is True
    _, (usage,), fake = run(monkeypatch, capsys, routes, ["usage"])
    assert ("team-x", "sys/internal/counters/activity") in fake.calls  # the token's namespace, not the start namespace
    assert usage["run"]["start_namespace"] == "team-x/"


def test_root_token_with_child_start_namespace_reads_cluster_blocks(env, monkeypatch, capsys):
    """Regression: a root-namespace token starting in tn001 keeps today's cluster reads."""
    monkeypatch.setenv("VAULT_NAMESPACE", "/tn001/")
    routes = {
        ("", "sys/health"): {"cluster_name": "c1", "version": "2.1.1+ent", "sealed": False},
        ("tn001", "auth/token/lookup-self"): {"data": {"namespace_path": "", "policies": ["vault-ops-readonly"]}},
        ("", "sys/license/status"): {"data": {"license_id": "L"}},
        ("", "sys/internal/counters/activity"): {"data": {"total": {"clients": 1}, "by_namespace": [{"namespace_path": "tn001/", "counts": {"clients": 1}}]}},
    }
    code, (doc,), fake = run(monkeypatch, capsys, routes, ["health"])
    assert code == vo.EXIT_OK and doc["run"]["token_namespace"] == "/"
    assert ("", "sys/license/status") in fake.calls and doc["health"]["license"] == {"license_id": "L"}
    _, (usage,), fake = run(monkeypatch, capsys, routes, ["usage"])
    assert ("", "sys/internal/counters/activity") in fake.calls  # still at root: every namespace
    assert usage["top_namespaces"][0]["namespace"] == "tn001/"


@pytest.mark.parametrize("paths", [("admin/", "admin/tn001/"), ("", "tn001/")], ids=["full", "relative"])
def test_child_token_usage_reads_counters_in_admin(env, monkeypatch, capsys, paths):
    routes = {
        **ADMIN_ROUTES,
        ("admin", "sys/internal/counters/activity"): {
            "data": {
                "total": {"clients": 120},
                "by_namespace": [
                    {"namespace_path": paths[0], "counts": {"clients": 100, "entity_clients": 100}},
                    {"namespace_path": paths[1], "counts": {"clients": 20, "entity_clients": 20}},
                ],
            }
        },
        ("admin", "sys/internal/counters/config"): DENIED,
    }
    code, (doc,), fake = run(monkeypatch, capsys, routes, ["usage"])
    assert code == vo.EXIT_OK
    assert ("admin", "sys/internal/counters/activity") in fake.calls and ("", "sys/internal/counters/activity") not in fake.calls
    assert ("admin", "sys/internal/counters/config") in fake.calls
    assert doc["activity_log"] is None and doc["coverage"]["denied"] == []  # 403 on the cluster setting is not a gap
    assert [r["namespace"] for r in doc["top_namespaces"]] == ["admin/", "admin/tn001/"]
    (cli4,) = [f for f in doc["findings"] if f["rule_id"] == "VT-CLI-004"]
    assert cli4["namespace"] == "admin/" and "`admin/` namespace" in cli4["detail"]
    assert doc["run"]["start_namespace"] == "admin/" and doc["run"]["token_namespace"] == "admin/"


def test_fingerprints_match_between_child_token_and_root_token_runs(env, monkeypatch, capsys):
    _, (scoped, _), _ = run(monkeypatch, capsys, ADMIN_ROUTES, ["audit"])
    root_routes = {**ADMIN_ROUTES, ("admin", "auth/token/lookup-self"): {"data": {"namespace_path": ""}}}
    _, (unscoped, _), _ = run(monkeypatch, capsys, root_routes, ["audit", "--namespace", "admin"])
    assert unscoped["run"]["token_namespace"] == "/"
    walk = {f["fingerprint"] for f in scoped["findings"]}
    assert walk and walk <= {f["fingerprint"] for f in unscoped["findings"]}
    diff = vo.diff_documents(unscoped, scoped)
    assert diff["summary"]["new"] == 0
    assert all(f["namespace"] == "/" for f in diff["resolved"])  # only cluster-level findings differ


@pytest.mark.parametrize(
    "token_ns, path, relative, full",
    [
        ("", "tn001/", True, "tn001"),
        ("admin", "", True, "admin"),
        ("admin", "tn001/", True, "admin/tn001"),
        ("admin", "admin/", True, "admin/admin"),  # relative row for the descendant admin/admin/
        ("admin", "admin/tn001/", False, "admin/tn001"),
        ("admin", "admin/", False, "admin"),
        ("admin", None, True, "admin"),
    ],
)
def test_full_activity_namespace(token_ns, path, relative, full):
    assert vo.full_activity_namespace(token_ns, path, relative) == full


def _months(*paths):
    return [{"timestamp": "t", "namespaces": [{"namespace_path": p} for p in paths], "new_clients": {"namespaces": [{"namespace_path": p} for p in paths]}}]


@pytest.mark.parametrize(
    "paths, full",
    [
        (["admin/", "admin/tn001/", "admin/admin/"], True),  # what Vault returns: canonical full paths
        (["admin/"], True),
        (["", "tn001/"], False),
        (["tn001/"], False),
        (["admin/", ""], False),
        ([], False),
    ],
)
def test_activity_paths_are_full(paths, full):
    assert vo.activity_paths_are_full({"by_namespace": [{"namespace_path": p} for p in paths]}, "admin") is full
    assert vo.activity_paths_are_full({"months": _months(*paths)}, "admin") is full


def test_scope_activity_full_paths_kept():
    payload = {"by_namespace": [{"namespace_path": p} for p in ("admin/", "admin/tn001/", "admin/admin/")], "months": _months("admin/", "admin/admin/")}
    scoped = vo.scope_activity(payload, "admin")
    assert [r["namespace_path"] for r in scoped["by_namespace"]] == ["admin", "admin/tn001", "admin/admin"]  # admin/admin stays distinct
    assert [r["namespace_path"] for r in scoped["months"][0]["new_clients"]["namespaces"]] == ["admin", "admin/admin"]


def test_scope_activity_relative_rows_prefixed():
    payload = {"by_namespace": [{"namespace_path": p} for p in ("", "admin/", "tn001/")], "months": _months("", "tn001/")}
    scoped = vo.scope_activity(payload, "admin")
    assert [r["namespace_path"] for r in scoped["by_namespace"]] == ["admin", "admin/admin", "admin/tn001"]
    assert [r["namespace_path"] for r in scoped["months"][0]["namespaces"]] == ["admin", "admin/tn001"]
    assert [r["namespace_path"] for r in scoped["months"][0]["new_clients"]["namespaces"]] == ["admin", "admin/tn001"]
    assert payload["by_namespace"][0]["namespace_path"] == ""  # input untouched
    assert vo.scope_activity(payload, "") is payload and vo.scope_activity({}, "admin") == {}


def test_cli_004_judges_token_namespace_as_effective_root(activity):
    scoped = vo.scope_activity(activity, "admin")
    found = {f.rule_id: f for f in vo.usage_findings(scoped, None, enterprise=True, token_ns="admin")}
    assert found["VT-CLI-004"].namespace == "admin" and found["VT-CLI-004"].evidence["root_clients"] == 380
    assert "VT-CLI-004" not in {f.rule_id for f in vo.usage_findings(scoped, None, enterprise=True)}  # root row is gone


def test_health_without_validation_has_null_token_namespace():
    run = vo.run_block("c1", "a", "", vo.utc_now(), None)
    assert run["token_namespace"] is None
    assert vo.run_block("c1", "a", "", vo.utc_now(), None, "")["token_namespace"] == "/"


# entities / policies / inventory with a child-namespace token: every read stays in the token's subtree.
ENTITY_ROUTES = {
    **ADMIN_ROUTES,
    ("admin", "identity/entity/id"): {"data": {"keys": ["e1"], "key_info": {"e1": {"name": "alice", "aliases": []}}}},
    ("admin", "identity/entity/id/e1"): {"data": {"name": "alice", "aliases": [], "group_ids": []}},
    ("admin", "sys/internal/counters/activity"): {"data": {"total": {"clients": 1}, "by_namespace": [{"namespace_path": "admin/", "counts": {"clients": 1, "entity_clients": 1}}]}},
}


def no_root_reads(fake):
    root_calls = {path for ns, path in fake.calls if ns == ""}
    assert not root_calls & set(ROOT_ONLY), root_calls
    assert not {p for p in root_calls if p.startswith(("identity/", "sys/policies/", "sys/internal/counters/activity"))}, root_calls


def test_child_token_entities_reads_identity_in_admin(env, monkeypatch, capsys):
    code, (doc,), fake = run(monkeypatch, capsys, ENTITY_ROUTES, ["entities"])
    assert code == vo.EXIT_OK and doc["run"]["token_namespace"] == "admin/" and doc["run"]["platform"] == "enterprise"
    assert ("admin", "identity/entity/id") in fake.calls and ("admin/tn001", "identity/entity/id") in fake.calls
    assert ("admin", "sys/internal/counters/activity") in fake.calls
    no_root_reads(fake)
    assert doc["coverage"]["complete"] is True and doc["coverage"]["namespaces_processed"] == 2


def test_child_token_policies_reads_bodies_in_admin(env, monkeypatch, capsys):
    routes = {**ADMIN_ROUTES, ("admin", "sys/policies/acl/default"): {"data": {"name": "default", "policy": 'path "secret/*" { capabilities = ["read"] }'}}}
    code, (doc,), fake = run(monkeypatch, capsys, routes, ["policies"])
    assert code in (vo.EXIT_OK, vo.EXIT_FINDINGS) and doc["run"]["token_namespace"] == "admin/"
    assert ("admin", "sys/policies/acl/default") in fake.calls
    assert [(p["namespace"], p["name"]) for p in doc["policies"]] == [("admin/", "default")]
    no_root_reads(fake)
    assert doc["coverage"]["denied"] == [] and doc["coverage"]["errors"] == []


def test_child_token_inventory_paths_are_full(env, monkeypatch, capsys):
    code, (doc,), fake = run(monkeypatch, capsys, ADMIN_ROUTES, ["inventory"])
    assert code == vo.EXIT_OK and doc["run"]["token_namespace"] == "admin/"
    rows = {r["namespace"]: r for r in doc["namespaces"]}
    assert list(rows) == ["admin/", "admin/tn001/"] and rows["admin/tn001/"]["depth"] == 2
    no_root_reads(fake)
    assert doc["coverage"]["complete"] is True


def test_child_token_activity_denied_is_recorded_at_token_namespace(env, monkeypatch, capsys):
    routes = {**ENTITY_ROUTES, ("admin", "sys/internal/counters/activity"): DENIED, ("admin", "sys/internal/counters/activity/monthly"): DENIED}
    code, (usage,), _ = run(monkeypatch, capsys, routes, ["usage"])
    assert code == vo.EXIT_OK and usage["coverage"]["complete"] is False
    assert usage["coverage"]["denied"] == [
        {"namespace": "admin/", "scope": "sys/internal/counters/activity"},
        {"namespace": "admin/", "scope": "sys/internal/counters/activity/monthly"},
    ]
    assert not [f for f in usage["findings"] if f["rule_id"] != "VT-CLI-005"]
    _, (entities,), _ = run(monkeypatch, capsys, routes, ["entities"])
    assert not [f for f in entities["findings"] if f["rule_id"] == "VT-ID-004"]


@pytest.mark.parametrize("paths", [("admin/", "admin/tn001/"), ("", "tn001/")], ids=["full", "relative"])
def test_id_004_matches_scoped_activity_rows(paths):
    many = vo.ENTITY_RULE_MIN_ENTITIES + 1

    def entities(ns):
        return [vo.Entity(id=f"{ns}-{i}", name=f"e{i}", namespace=ns, disabled=False, policies=[], group_count=0, aliases=[]) for i in range(many)]

    activity = {"total": {"clients": many}, "by_namespace": [{"namespace_path": paths[0], "counts": {"entity_clients": many}}, {"namespace_path": paths[1], "counts": {"entity_clients": 0}}]}
    active = vo.active_entity_clients(vo.scope_activity(activity, "admin"))
    assert active == {"admin": many, "admin/tn001": 0}
    found = vo.entity_findings({"admin": entities("admin"), "admin/tn001": entities("admin/tn001")}, active)
    assert [f.namespace for f in found if f.rule_id == "VT-ID-004"] == ["admin/tn001"]  # other VT-ID rules are per-entity noise here
