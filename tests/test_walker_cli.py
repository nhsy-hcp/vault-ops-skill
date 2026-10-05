import json
from pathlib import Path

import pytest
import vault_ops as vo
from conftest import FAKE_TOKEN


class FakeReader:
    """Stands in for VaultReader: routes (namespace, path) to canned responses or exceptions."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, path, namespace="", params=None):
        self.calls.append((namespace, path))
        value = self.routes.get((namespace, path))
        if value is None:
            raise vo.hvac_exc.InvalidPath("not found")
        if isinstance(value, Exception):
            raise value
        return value

    def list(self, path, namespace=""):
        return list(self.get(path, namespace).get("data", {}).get("keys") or [])

    def data(self, path, namespace="", params=None):
        payload = self.get(path, namespace, params)
        return payload.get("data", payload) if isinstance(payload.get("data"), dict) else payload


def mounts(**types):
    return {"data": {f"{p}/": {"type": t} for p, t in types.items()}, "request_id": "x"}


ROUTES = {
    ("", "sys/auth"): mounts(token="token"),
    ("", "sys/mounts"): mounts(sys="system", secret="kv"),
    ("", "sys/policies/acl"): {"data": {"keys": ["default", "root", "ops"]}},
    ("", "sys/policies/egp"): {"data": {"keys": ["adv"]}},
    ("", "sys/policies/egp/adv"): {"data": {"enforcement_level": "advisory", "paths": ["*"], "policy": "x"}},
    ("", "sys/policies/rgp"): vo.hvac_exc.InvalidPath("no policies"),
    ("", "sys/namespaces"): {"data": {"key_info": {"a/": {"id": "1", "custom_metadata": {"owner": "x@y"}}, "b/": {"id": "2"}}}},
    ("a", "sys/auth"): mounts(token="ns_token", approle="approle"),
    ("a", "sys/mounts"): mounts(sys="ns_system"),
    ("a", "sys/policies/acl"): vo.hvac_exc.Forbidden("denied"),
    ("a", "sys/policies/egp"): {"data": {"keys": ["locked"]}},
    ("a", "sys/policies/egp/locked"): vo.hvac_exc.Forbidden("denied"),
    ("a", "sys/policies/rgp"): vo.hvac_exc.InvalidPath("none"),
    ("a", "sys/namespaces"): {"data": {"key_info": {"c/": {"id": "3"}}}},
    ("a/c", "sys/auth"): mounts(token="ns_token"),
    ("a/c", "sys/mounts"): mounts(sys="ns_system"),
    ("a/c", "sys/policies/acl"): {"data": {"keys": []}},
    ("a/c", "sys/namespaces"): vo.hvac_exc.Forbidden("denied"),
    ("b", "sys/auth"): vo.hvac_exc.Forbidden("denied"),
}


def test_walker_collects_tree_and_coverage():
    cov = vo.Coverage()
    data = vo.Walker(FakeReader(ROUTES), cov, workers=2).walk("")
    assert sorted(data.auth) == ["", "a", "a/c"]
    assert sorted(data.namespaces) == ["a", "a/c", "b"]
    assert "custom_metadata" not in data.namespaces["a"]
    assert data.acl_policies[""] == ["ops"]
    assert data.sentinel == "supported"
    assert data.egp["a"]["locked"]["read_error"] is True
    assert cov.namespaces_processed == 4
    assert sorted((d["namespace"], d["scope"]) for d in cov.denied) == [
        ("a/", "ACL policy names"),
        ("a/", "sentinel EGP policy bodies (attach vault-ops-sentinel-reader)"),
        ("a/c/", "child namespaces (subtree not audited)"),
        ("b/", "whole namespace (no data collected)"),
    ]


@pytest.mark.parametrize("message", ["1 error occurred: unsupported path", "enterprise-only feature, on list http://v/v1/sys/policies/egp"])
def test_walker_sentinel_unsupported_and_skipped(message):
    """Regression: Vault 2.x Community answers `enterprise-only feature`, older builds `unsupported path`."""
    routes = {
        ("", "sys/auth"): mounts(token="token"),
        ("", "sys/mounts"): mounts(sys="system"),
        ("", "sys/policies/egp"): vo.hvac_exc.InvalidPath(message),
    }
    reader = FakeReader(routes)
    assert vo.Walker(reader, vo.Coverage()).walk("").sentinel == "unsupported"
    assert ("", "sys/policies/rgp") not in reader.calls  # stops probing once unsupported
    assert vo.Walker(FakeReader(routes), vo.Coverage(), sentinel=False).walk("").sentinel == "skipped"


def test_collect_health_maps_fields():
    routes = {
        ("", "sys/health"): {"cluster_name": "c1", "version": "2.1.1+ent", "sealed": False, "initialized": True},
        ("", "sys/leader"): {"ha_enabled": False, "is_self": False, "leader_address": ""},
        ("", "sys/license/status"): {"data": {"autoloaded": {"license_id": "L", "expiration_time": "2027-01-01T00:00:00Z"}}},
        ("", "sys/replication/status"): {"data": {"dr": {"mode": "disabled"}, "performance": {"mode": "disabled"}}},
        ("", "sys/config/state/sanitized"): vo.hvac_exc.Forbidden("denied"),
    }
    cov = vo.Coverage()
    h = vo.collect_health(FakeReader(routes), cov)
    assert h["enterprise"] is True and h["cluster_name"] == "c1"
    assert h["license"] == {"license_id": "L", "expiration_time": "2027-01-01T00:00:00Z"}
    assert h["replication"]["dr"]["mode"] == "disabled"
    assert h["lease_ttls"] is None
    assert cov.denied == [{"namespace": "/", "scope": "sys/config/state/sanitized"}]


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_ADDR", "https://vault.example:8200/")
    monkeypatch.setenv("VAULT_TOKEN", FAKE_TOKEN)
    monkeypatch.setenv("VAULT_SKIP_VERIFY", "true")
    monkeypatch.delenv("VAULT_NAMESPACE", raising=False)
    monkeypatch.setenv("VAULT_OPS_OUTPUT_DIR", str(tmp_path))
    return tmp_path


def test_config_from_env(env, monkeypatch):
    cfg = vo.Config.from_env()
    assert cfg.addr == "https://vault.example:8200" and cfg.verify is False and cfg.namespace == ""
    monkeypatch.setenv("VAULT_SKIP_VERIFY", "false")
    monkeypatch.setenv("VAULT_CACERT", "/ca.pem")
    monkeypatch.setenv("VAULT_NAMESPACE", "/tn001/")
    cfg = vo.Config.from_env()
    assert cfg.verify == "/ca.pem" and cfg.namespace == "tn001"
    assert vo.Config.from_env("x/y/").namespace == "x/y"


def test_missing_env_is_fatal(monkeypatch, capsys):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    assert vo.main(["health"]) == vo.EXIT_FATAL
    assert "VAULT_ADDR" in capsys.readouterr().err


def test_audit_cli_end_to_end(env, monkeypatch, capsys):
    routes = dict(ROUTES)
    routes[("", "auth/token/lookup-self")] = {"data": {}}
    routes[("", "sys/health")] = {"cluster_name": "c1", "version": "2.1.1+ent", "sealed": False}
    monkeypatch.setattr(vo, "VaultReader", lambda cfg: _ValidatingFake(routes))
    code = vo.main(["audit", "--redact-addr", "--fail-on-gaps"])
    out = capsys.readouterr().out.strip().splitlines()
    assert code == vo.EXIT_GAPS
    assert len(out) == 2 and "c1-findings-" in out[0] and "c1-inventory-" in out[1]
    assert all(p.endswith(".json") and Path(p).stat().st_mode & 0o777 == 0o600 for p in out)
    assert json.loads(Path(out[1]).read_text())["summary"]["namespaces"] >= 1
    doc = json.loads(Path(out[0]).read_text())
    assert doc["run"]["vault_addr"] == "<redacted>"
    assert FAKE_TOKEN not in json.dumps(doc)
    assert {"VT-SNT-001", "VT-SNT-003"} <= set(doc["summary"]["by_rule"])


def test_other_subcommands(env, monkeypatch, capsys):
    routes = dict(ROUTES)
    routes[("", "auth/token/lookup-self")] = {"data": {}}
    routes[("", "sys/health")] = {"cluster_name": "c1", "version": "2.1.1"}
    routes[("", "sys/internal/counters/activity")] = {"data": {"total": {"clients": 3}, "by_namespace": []}}
    monkeypatch.setattr(vo, "VaultReader", lambda cfg: _ValidatingFake(routes))
    for cmd in (["health"], ["inventory", "--no-sentinel"], ["usage"]):
        assert vo.main(cmd) == vo.EXIT_OK
    paths = capsys.readouterr().out.split()
    assert [p.split("c1-")[1].split("-")[0] for p in paths] == ["health", "inventory", "usage"]
    usage = json.loads(Path(paths[2]).read_text())
    assert usage["total"] == {"clients": 3}


def test_diff_cli(env, tmp_path, capsys):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    finding = {
        "fingerprint": "f" * 16,
        "rule_id": "VT-NS-001",
        "severity": "info",
        "namespace": "/",
        "object": {},
        "detail": "",
        "evidence": {},
    }
    a.write_text(json.dumps({"findings": [finding]}))
    b.write_text(json.dumps({"findings": []}))
    assert vo.main(["diff", str(a), str(b)]) == vo.EXIT_OK
    doc = json.loads(Path(capsys.readouterr().out.strip()).read_text())
    assert doc["summary"]["resolved"] == 1
    assert vo.main(["diff", str(a), str(tmp_path / "missing.json")]) == vo.EXIT_FATAL


class _ValidatingFake(FakeReader):
    def validate(self):
        self.get("auth/token/lookup-self")

    def probe(self):
        return self.get("sys/health")


@pytest.mark.parametrize("verify", [False, "/ca.pem", True])
def test_reader_session_carries_tls_setting(verify):
    """Regression: hvac ignores verify= when a session with verify=True is passed in."""
    reader = vo.VaultReader(vo.Config(addr="https://v:8200", token="t", verify=verify))
    client = reader.client("ns1")
    assert reader.session.verify == verify
    assert client.adapter._kwargs["verify"] == verify
    assert client.adapter.namespace == "ns1"


def test_collect_health_dev_mode_shapes():
    """Dev/inmem: replication is a bare {"mode": "unsupported"}; lease TTLs of 0 mean unset."""
    routes = {
        ("", "sys/health"): {"cluster_name": "c1", "version": "2.1.1+ent", "sealed": False},
        ("", "sys/replication/status"): {"data": {"mode": "unsupported"}},
        ("", "sys/config/state/sanitized"): {"data": {"default_lease_ttl": 0, "max_lease_ttl": 0}},
    }
    h = vo.collect_health(FakeReader(routes), vo.Coverage())
    assert h["replication"] == {"mode": "unsupported"}
    assert h["lease_ttls"] == {"default_lease_ttl_seconds": None, "max_lease_ttl_seconds": None}
    assert not [f for f in vo.health_findings(h) if f.rule_id == "VT-HLTH-002"]


RAFT_ROUTES = {
    ("", "sys/storage/raft/configuration"): {
        "data": {
            "config": {
                "servers": [
                    {"node_id": "n1", "address": "n1.internal:8201", "leader": True, "voter": True, "protocol_version": "3"},
                    {"node_id": "n2", "address": "n2.internal:8201", "leader": False, "voter": False, "protocol_version": "3"},
                ],
                "index": 0,
            }
        }
    },
    ("", "sys/storage/raft/autopilot/configuration"): {
        "data": {
            "cleanup_dead_servers": False,
            "dead_server_last_contact_threshold": "24h0m0s",
            "last_contact_threshold": "10s",
            "max_trailing_logs": 1000,
            "min_quorum": 0,
            "server_stabilization_time": "10s",
        }
    },
    ("", "sys/storage/raft/autopilot/state"): {
        "data": {
            "healthy": True,
            "failure_tolerance": 0,
            "leader": "n1",
            "voters": ["n1"],
            "upgrade_info": {"status": "idle"},
            "servers": {
                "n2": {"id": "n2", "address": "n2.internal:8201", "status": "non-voter", "node_type": "voter", "healthy": True, "last_contact": "1s", "last_index": 9},
                "n1": {"id": "n1", "address": "n1.internal:8201", "status": "leader", "node_type": "voter", "healthy": True, "last_contact": "0s", "last_index": 10},
            },
        }
    },
}


def test_collect_raft_maps_peers_and_autopilot_without_addresses():
    cov = vo.Coverage()
    raft = vo.collect_health(FakeReader({("", "sys/health"): {"sealed": False}, **RAFT_ROUTES}), cov)["raft"]
    assert raft["peers"] == [{"node_id": "n1", "leader": True, "voter": True}, {"node_id": "n2", "leader": False, "voter": False}]
    assert raft["autopilot"]["configuration"]["max_trailing_logs"] == 1000
    state = raft["autopilot"]["state"]
    assert (state["healthy"], state["leader"], state["voters"], state["upgrade_status"]) == (True, "n1", ["n1"], "idle")
    assert [(s["id"], s["status"], s["last_index"]) for s in state["servers"]] == [("n1", "leader", 10), ("n2", "non-voter", 9)]
    assert "internal" not in json.dumps(raft)
    assert cov.complete


def test_collect_raft_not_in_use_and_denied():
    not_raft = vo.hvac_exc.InvalidRequest("raft storage is not in use")
    routes = {(ns, p): not_raft for ns, p in RAFT_ROUTES}
    cov = vo.Coverage()
    assert vo.collect_raft(FakeReader(routes), cov) is None and cov.complete
    routes = {**RAFT_ROUTES, ("", "sys/storage/raft/autopilot/state"): vo.hvac_exc.Forbidden("denied")}
    cov = vo.Coverage()
    raft = vo.collect_raft(FakeReader(routes), cov)
    assert raft["peers"] and raft["autopilot"]["state"] is None
    assert cov.denied == [{"namespace": "/", "scope": "sys/storage/raft/autopilot/state"}]


DR_PRIMARY_REPL = {
    "data": {
        "dr": {"mode": "primary", "state": "running", "secondaries": [{"node_id": "vault-dr", "connection_status": "connected"}]},
        "performance": {"mode": "disabled"},
    }
}


def test_replication_summary_and_connected_primary_is_healthy():
    routes = {
        ("", "sys/health"): {"cluster_name": "c1", "version": "2.1.1+ent", "sealed": False, "replication_dr_mode": "primary"},
        ("", "sys/replication/status"): DR_PRIMARY_REPL,
    }
    h = vo.collect_health(FakeReader(routes), vo.Coverage())
    assert h["replication"]["dr"] == {"mode": "primary", "state": "running", "secondaries": [{"node_id": "vault-dr", "connection_status": "connected"}]}
    assert h["dr_secondary"] is False
    assert vo.health_findings(h) == []


METRICS_PAYLOAD = {
    "Timestamp": "2026-10-05 14:53:30 +0000 UTC",
    "Gauges": [
        {"Name": "vault.expire.num_leases", "Value": 1234.0, "Labels": {}},
        {"Name": "vault.expire.num_irrevocable_leases", "Value": 0.0, "Labels": {}},
        {"Name": "vault.core.in_flight_requests", "Value": 2.0, "Labels": {"cluster": "vault-cluster-secret-name"}},
        {"Name": "vault.core.in_flight_requests", "Value": 3.0, "Labels": {"cluster": "other"}},
        {"Name": "vault.raft_storage.stats.fsm_pending", "Value": 4.0, "Labels": {"peer_id": "node-a"}},
        {"Name": "vault.raft_storage.stats.fsm_pending", "Value": 1.0, "Labels": {"peer_id": "node-b"}},
        {"Name": "vault.runtime.num_goroutines", "Value": 412.0, "Labels": {}},
        {"Name": "vault.runtime.alloc_bytes", "Value": 1.5, "Labels": {}},
        {"Name": "vault.replication.rpc.server.last_heartbeat", "Value": 1.0, "Labels": {"cluster_address": "10.0.0.9:8201"}},
        {"Name": "vault.runtime.sys_bytes", "Value": "junk"},
        {"Value": 5.0},
        "not-a-gauge",
    ],
    "Counters": [{"Name": "vault.cache.write", "Count": 1}],
}


def health_with_metrics(metrics_route):
    routes = {("", "sys/health"): {"cluster_name": "c1", "version": "2.1.1+ent", "sealed": False}}
    if metrics_route is not None:
        routes[("", "sys/metrics")] = metrics_route
    cov = vo.Coverage()
    return vo.collect_health(FakeReader(routes), cov), cov


def test_collect_metrics_allowlists_and_aggregates():
    h, cov = health_with_metrics(METRICS_PAYLOAD)
    assert h["metrics"] == {
        "node_scope": True,
        "timestamp": "2026-10-05T14:53:30Z",
        "leases": 1234,
        "irrevocable_leases": 0,
        "in_flight_requests": 5,  # summed over clusters
        "raft_fsm_pending": 4,  # max over peers
        "raft_oldest_log_age_ms": None,  # leader-only gauge, absent here
        "goroutines": 412,
        "alloc_bytes": 1.5,
        "sys_bytes": None,  # non-numeric value skipped
        "token_count": None,
    }
    assert cov.to_dict()["complete"] is True
    text = json.dumps(h)
    assert "vault-cluster-secret-name" not in text and "10.0.0.9" not in text and "node-a" not in text


@pytest.mark.parametrize(
    "route, denied, error",
    [
        (vo.hvac_exc.Forbidden("permission denied"), [{"namespace": "/", "scope": "sys/metrics"}], None),
        (None, [], None),  # 404: endpoint not there
        (vo.hvac_exc.InvalidRequest("prometheus is not enabled"), [], "InvalidRequest"),
        (vo.hvac_exc.InternalServerError("boom"), [], "InternalServerError"),
        (vo.requests.exceptions.ConnectionError("refused"), [], "ConnectionError"),
        ({"unexpected": "shape"}, [], "ValueError"),
    ],
)
def test_collect_metrics_degrades_gracefully(route, denied, error):
    h, cov = health_with_metrics(route)
    assert h["metrics"] is None
    assert h["cluster_name"] == "c1"  # the rest of health is unaffected
    assert cov.denied == denied
    assert [e["message"] for e in cov.errors] == ([error] if error else [])
    assert vo.health_findings(h) == []


def test_metrics_timestamp_unparseable_is_none():
    assert vo.metrics_timestamp("yesterday") is None and vo.metrics_timestamp(None) is None


def test_disconnected_secondary_fires_hlth_002():
    health = {"replication": {"dr": {"mode": "primary", "state": "running", "secondaries": [{"node_id": "vault-dr", "connection_status": "disconnected"}]}}}
    (f,) = vo.health_findings(health)
    assert f.rule_id == "VT-HLTH-002" and f.object_type == "dr"
    assert f.evidence["disconnected_peers"] == ["vault-dr"]
    assert "vault-dr" in f.detail


def test_dr_secondary_health_skips_authenticated_reads(env, monkeypatch, capsys):
    routes = {
        ("", "sys/health"): {"cluster_name": "c1", "version": "2.1.1+ent", "sealed": False, "replication_dr_mode": "secondary"},
        ("", "sys/leader"): {"ha_enabled": True, "leader_address": "https://vault-dr:8200"},
        ("", "sys/replication/status"): {
            "data": {"dr": {"mode": "secondary", "state": "stream-wals", "connection_state": "ready", "primaries": [{"connection_status": "connected"}]}, "performance": {"mode": "disabled"}}
        },
        # Disabled on a DR secondary: reading these would be a bug.
        ("", "auth/token/lookup-self"): vo.hvac_exc.InvalidRequest("path disabled in replication DR secondary mode"),
        ("", "sys/license/status"): vo.hvac_exc.InvalidRequest("path disabled"),
        ("", "sys/config/state/sanitized"): vo.hvac_exc.InvalidRequest("path disabled"),
    }
    fake = _ValidatingFake(routes)
    monkeypatch.setattr(vo, "VaultReader", lambda cfg: fake)
    assert vo.main(["health"]) == vo.EXIT_OK
    doc = json.loads(Path(capsys.readouterr().out.strip()).read_text())
    assert doc["health"]["dr_secondary"] is True
    assert doc["health"]["replication"]["dr"]["state"] == "stream-wals"
    assert doc["coverage"]["complete"] is True and doc["findings"] == []
    called = {path for _, path in fake.calls}
    assert not called & {"auth/token/lookup-self", "sys/license/status", "sys/config/state/sanitized", *(p for _, p in RAFT_ROUTES)}
    assert doc["health"]["raft"] is None
    assert "sys/metrics" not in called and doc["health"]["metrics"] is None


@pytest.mark.parametrize("command", [["audit"], ["inventory"], ["usage"]])
def test_dr_secondary_refused_for_authenticated_subcommands(env, monkeypatch, capsys, command):
    routes = {("", "sys/health"): {"replication_dr_mode": "secondary"}}
    monkeypatch.setattr(vo, "VaultReader", lambda cfg: _ValidatingFake(routes))
    assert vo.main(command) == vo.EXIT_FATAL
    assert "DR secondary" in capsys.readouterr().err


def test_validate_reports_vault_errors_without_traceback(env, monkeypatch, capsys):
    routes = {("", "sys/health"): {"replication_dr_mode": "disabled"}, ("", "auth/token/lookup-self"): vo.hvac_exc.InvalidRequest("boom")}

    class Reader(_ValidatingFake):
        validate = vo.VaultReader.validate

        def __init__(self):
            super().__init__(routes)
            self.config = vo.Config.from_env()

    monkeypatch.setattr(vo, "VaultReader", lambda cfg: Reader())
    assert vo.main(["health"]) == vo.EXIT_FATAL
    assert "token validation failed" in capsys.readouterr().err


CANARY = "CANARY-must-never-appear"
AUDIT_ROUTE = {
    "data": {
        "file/": {"type": "file", "description": CANARY, "local": False, "options": {"file_path": f"/var/log/{CANARY}.log", "format": "json", "prefix": CANARY}},
        "stdout/": {"type": "file", "local": True, "options": {"file_path": "stdout", "hmac_accessor": "false", "log_raw": "true"}},
        "socket/": {"type": "socket", "options": {"address": f"{CANARY}:9090", "socket_type": "tcp", "format": CANARY, "fallback": "true"}},
        "syslog/": {"type": "syslog", "options": {"tag": CANARY, "facility": "AUTH", "elide_list_responses": "1"}},
    },
}
SNAPSHOT_ROUTES = {
    ("", "sys/storage/raft/snapshot-auto/config"): {"data": {"keys": ["s3-daily", "local"]}},
    ("", "sys/storage/raft/snapshot-auto/status/s3-daily"): {
        "data": {
            "consecutive_errors": 3,
            "last_snapshot_error": f"AccessDenied: {CANARY} AKIAEXAMPLE",
            "last_snapshot_start": "2026-10-04T00:00:00Z",
            "last_snapshot_end": "2026-10-04T00:00:02Z",
            "last_snapshot_url": f"s3://{CANARY}-bucket/vault/snap.snap",
            "next_snapshot_start": "2026-10-05T00:00:00Z",
            "snapshot_start": "2026-10-05T00:00:00Z",
            "snapshot_url": f"s3://{CANARY}-bucket/vault/next.snap",
        }
    },
    ("", "sys/storage/raft/snapshot-auto/status/local"): {"data": {"last_snapshot_url": f"file:///{CANARY}/snap.snap", "consecutive_errors": 0}},
    ("", "sys/storage/raft/snapshot-auto/config/s3-daily"): {"data": {"aws_secret_access_key": CANARY}},  # must never be requested
}


def secure_health_routes():
    return {("", "sys/health"): {"cluster_name": "c1", "version": "2.1.1+ent", "sealed": False}, **RAFT_ROUTES, ("", "sys/audit"): AUDIT_ROUTE, **SNAPSHOT_ROUTES}


def test_collect_audit_devices_and_snapshots_allowlisted():
    reader = FakeReader(secure_health_routes())
    cov = vo.Coverage()
    h = vo.collect_health(reader, cov)
    assert cov.complete
    devices = {d["path"]: d for d in h["audit_devices"]}
    assert devices["file/"] == {"path": "file/", "type": "file", "local": False, "options": {"format": "json", "sink": "file"}}
    assert devices["stdout/"]["options"] == {"hmac_accessor": False, "log_raw": True, "sink": "stdout"}
    assert devices["socket/"]["options"] == {"fallback": True}
    assert devices["syslog/"]["options"] == {"elide_list_responses": True}
    configs = {c["name"]: c for c in h["snapshots"]["configs"]}
    assert configs["s3-daily"] == {
        "name": "s3-daily",
        "status_readable": True,
        "consecutive_errors": 3,
        "last_snapshot_start": "2026-10-04T00:00:00Z",
        "last_snapshot_end": "2026-10-04T00:00:02Z",
        "next_snapshot_start": "2026-10-05T00:00:00Z",
        "in_progress": True,
        "storage_scheme": "s3",
    }
    assert configs["local"]["storage_scheme"] == "file"
    assert not [p for _, p in reader.calls if p.startswith("sys/storage/raft/snapshot-auto/config/")]  # configs hold credentials


def test_audit_and_snapshot_secrets_never_reach_output():
    h = vo.collect_health(FakeReader(secure_health_routes()), vo.Coverage())
    findings = vo.health_findings(h)
    assert {"VT-AUD-003", "VT-SNAP-002", "VT-SNAP-003"} <= {f.rule_id for f in findings}
    text = json.dumps(h) + json.dumps([f.to_dict() for f in findings])
    assert CANARY not in text and "AKIA" not in text and "bucket" not in text


def test_audit_and_snapshot_reads_denied_or_absent():
    routes = secure_health_routes()
    routes[("", "sys/audit")] = vo.hvac_exc.Forbidden("denied")
    routes[("", "sys/storage/raft/snapshot-auto/config")] = vo.hvac_exc.Forbidden("denied")
    cov = vo.Coverage()
    h = vo.collect_health(FakeReader(routes), cov)
    assert h["audit_devices"] is None and h["snapshots"] is None
    assert sorted(d["scope"] for d in cov.denied) == ["sys/audit", "sys/storage/raft/snapshot-auto/config"]
    assert not [f for f in vo.health_findings(h) if f.rule_id.startswith(("VT-AUD-", "VT-SNAP-"))]
    # Enterprise raft cluster with no snapshot config: the list 404s, which means none configured
    del routes[("", "sys/storage/raft/snapshot-auto/config")]
    routes[("", "sys/audit")] = {"data": {}}
    h = vo.collect_health(FakeReader(routes), vo.Coverage())
    assert h["audit_devices"] == [] and h["snapshots"] == {"configs": []}
    assert {"VT-AUD-001", "VT-SNAP-001"} <= {f.rule_id for f in vo.health_findings(h)}
    # CE (no "+ent") or no raft: snapshots are not read at all
    routes[("", "sys/health")] = {"cluster_name": "c1", "version": "2.1.1", "sealed": False}
    assert vo.collect_health(FakeReader(routes), vo.Coverage())["snapshots"] is None
