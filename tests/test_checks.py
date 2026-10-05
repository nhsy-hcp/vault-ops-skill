from datetime import UTC, datetime

import vault_ops as vo

NOW = datetime(2026, 10, 5, tzinfo=UTC)


def ids(findings):
    return sorted(f.rule_id for f in findings)


def test_mount_findings_fire_once_each(cluster_data):
    found = vo.mount_findings(cluster_data, 32 * 24 * 3600)
    assert ids(found) == ["VT-AUTH-001", "VT-MOUNT-001", "VT-MOUNT-002", "VT-MOUNT-003", "VT-MOUNT-004", "VT-MOUNT-005", "VT-MOUNT-006"]
    lease = next(f for f in found if f.rule_id == "VT-MOUNT-002")
    assert lease.evidence["baseline_source"] == "cluster"
    assert lease.object_path == "long/"
    assert "overrides the cluster system max of 768h" in lease.detail


def test_lease_fallback_baseline(cluster_data):
    lease = next(f for f in vo.mount_findings(cluster_data, None) if f.rule_id == "VT-MOUNT-002")
    assert lease.evidence["baseline_source"] == "fallback"
    assert lease.evidence["baseline_seconds"] == vo.LONG_MAX_LEASE_TTL_SECONDS


def test_default_lease_ttl_override(cluster_data):
    default = [f for f in vo.mount_findings(cluster_data, None) if f.rule_id == "VT-MOUNT-004"]
    assert [(f.namespace, f.object_path) for f in default] == [("", "long/")]  # oidc/ 1h is the control
    assert default[0].evidence == {"default_lease_ttl_seconds": 40 * 24 * 3600, "threshold_seconds": vo.DEFAULT_LEASE_TTL_WARNING_SECONDS}
    assert "960h, above the 768h review threshold" in default[0].detail


def test_default_lease_ttl_inherited_or_at_threshold_ignored(cluster_data):
    for value in (0, vo.DEFAULT_LEASE_TTL_WARNING_SECONDS):
        cluster_data.secrets[""]["long/"]["config"]["default_lease_ttl"] = value
        assert "VT-MOUNT-004" not in ids(vo.mount_findings(cluster_data, None))


def test_kv_v1_and_mount_sprawl(cluster_data):
    found = vo.mount_findings(cluster_data, None)
    assert [(f.namespace, f.object_path) for f in found if f.rule_id == "VT-MOUNT-006"] == [("", "old/")]  # kv v2 mounts are controls
    sprawl = next(f for f in found if f.rule_id == "VT-MOUNT-005")
    assert (sprawl.namespace, sprawl.object_kind, sprawl.object_path) == ("team-a", "secrets_mount", None)
    assert sprawl.evidence["mounts_by_type"] == {"kv": vo.MOUNT_SPRAWL_THRESHOLD + 1}
    del cluster_data.secrets["team-a"]["app00/"]  # exactly at the threshold
    assert "VT-MOUNT-005" not in ids(vo.mount_findings(cluster_data, None))


def test_usage_findings_fire_once_each(activity):
    found = vo.usage_findings(activity, None, enterprise=True)
    assert ids(found) == ["VT-CLI-001", "VT-CLI-002", "VT-CLI-003", "VT-CLI-004"]
    by_rule = {f.rule_id: f for f in found}
    assert by_rule["VT-CLI-001"].namespace == "" and by_rule["VT-CLI-001"].evidence["source"] == "billing_period"
    assert by_rule["VT-CLI-002"].evidence == {"month": "2026-09", "clients": 300, "baseline_clients": 100, "months_compared": 1}
    churn = by_rule["VT-CLI-003"]
    assert (churn.object_kind, churn.object_path, churn.object_type) == ("auth_mount", "jwt/", "jwt")
    assert churn.evidence == {"month": "2026-09", "clients": 280, "new_clients": 270}
    assert by_rule["VT-CLI-004"].evidence["root_clients"] == 380


def test_usage_findings_controls(activity):
    assert "VT-CLI-004" not in ids(vo.usage_findings(activity, None, enterprise=False))  # no namespaces on CE
    assert "VT-CLI-003" not in ids(vo.usage_findings({**activity, "months": activity["months"][1:]}))  # first month: all clients are new
    # The partial current month is the latest point: 150 against a 200 average is not growth.
    current = {"clients": 150, "months": [{"timestamp": "2026-10-01T00:00:00Z"}], "by_namespace": []}
    assert "VT-CLI-002" not in ids(vo.usage_findings(activity, current))
    assert vo.usage_findings({}, None, enterprise=True) == []


def test_usage_findings_fall_back_to_current_month():
    current = {"clients": 60, "by_namespace": [{"namespace_path": "tn001/", "counts": {"clients": 60, "non_entity_clients": 40}}]}
    (found,) = vo.usage_findings({"total": {"clients": 0}}, current)
    assert (found.rule_id, found.namespace, found.evidence["source"]) == ("VT-CLI-001", "tn001", "current_month")


def test_builtin_local_mounts_ignored(cluster_data):
    local = [f for f in vo.mount_findings(cluster_data, None) if f.rule_id == "VT-MOUNT-003"]
    assert [(f.namespace, f.object_path) for f in local] == [("team-a/prod", "kv-local/")]


def test_namespace_findings(cluster_data):
    found = vo.namespace_findings(cluster_data)
    assert [(f.rule_id, f.namespace) for f in sorted(found, key=lambda f: f.rule_id)] == [
        ("VT-NS-001", "team-a"),
        ("VT-NS-002", "team-b"),
    ]


def test_sentinel_findings(cluster_data):
    found = vo.sentinel_findings(cluster_data)
    assert ids(found) == ["VT-SNT-001", "VT-SNT-002", "VT-SNT-003", "VT-SNT-004"]
    assert not any(f.object_path == "ok" for f in found)
    trivial = next(f for f in found if f.rule_id == "VT-SNT-004")
    assert trivial.object_kind == "rgp_policy" and trivial.evidence["policy_line_count"] == 5


def test_is_trivial_policy():
    assert vo.is_trivial_policy("main = rule { true }")
    assert vo.is_trivial_policy("# only comments\n")
    assert not vo.is_trivial_policy("main = rule { false }")
    assert not vo.is_trivial_policy(None)


def test_health_findings_all_fire(health):
    found = vo.health_findings(health, now=NOW)
    assert ids(found) == ["VT-HLTH-001", "VT-HLTH-002", "VT-HLTH-003", "VT-HLTH-004", "VT-LEASE-001", "VT-LIC-001"]
    raft = next(f for f in found if f.rule_id == "VT-HLTH-004")
    assert raft.evidence == {"healthy": False, "failure_tolerance": 0, "unhealthy_servers": ["n2"]}
    lease = next(f for f in found if f.rule_id == "VT-LEASE-001")
    assert lease.evidence == {"default_lease_ttl_seconds": 1000 * 3600, "threshold_seconds": vo.DEFAULT_LEASE_TTL_WARNING_SECONDS}
    lic = next(f for f in found if f.rule_id == "VT-LIC-001")
    assert lic.evidence["days_remaining"] == 15
    repl = [f for f in found if f.rule_id == "VT-HLTH-002"]
    assert [f.object_type for f in repl] == ["performance"]  # dr "idle" is healthy


def test_health_findings_clear_when_healthy(health):
    health.update(
        sealed=False,
        version="2.1.1+ent",
        leader={"ha_enabled": True, "leader_address_present": True},
        license={"expiration_time": "2027-12-01T00:00:00Z"},
        replication={"dr": {"mode": "disabled"}, "performance": {"mode": "primary", "state": "running"}},
        lease_ttls={"default_lease_ttl_seconds": None, "max_lease_ttl_seconds": None},  # unset: built-in 768h
        raft={"peers": [], "autopilot": {"configuration": None, "state": {"healthy": True, "failure_tolerance": 0, "servers": [{"id": "n1", "healthy": True}]}}},
    )
    assert vo.health_findings(health, now=NOW) == []
    health["lease_ttls"] = None  # DR secondary / unreadable config
    assert vo.health_findings(health, now=NOW) == []


def test_fingerprint_stable_and_ignores_evidence(cluster_data):
    a = vo.mount_findings(cluster_data, None)
    cluster_data.secrets[""]["long/"]["config"]["max_lease_ttl"] = 200 * 24 * 3600
    b = vo.mount_findings(cluster_data, None)
    fp = {f.rule_id: f.fingerprint for f in a}
    assert fp == {f.rule_id: f.fingerprint for f in b}
    assert all(len(v) == 16 for v in fp.values())


def test_helpers():
    assert vo.display_namespace("") == "/"
    assert vo.display_namespace("a/b") == "a/b/"
    assert vo.normalise_namespace("/a/b/") == "a/b"
    assert vo.parent_of("a/b") == "a" and vo.parent_of("a") == "" and vo.parent_of("") is None
    assert vo.format_ttl(7200) == "2h" and vo.format_ttl(120) == "2m" and vo.format_ttl(7) == "7s"
    assert vo.format_multiple(90, 30) == "3x" and vo.format_multiple(45, 30) == "1.5x"
    assert vo.parse_version("v1.19.3+ent") == (1, 19) and vo.parse_version("garbage") is None
    assert vo.days_until("not-a-date") is None


def test_sanitise_error_drops_message():
    exc = vo.hvac_exc.Forbidden("permission denied https://vault.internal/v1/secret?token=abc")
    assert vo.sanitise_error(exc) == "Forbidden"
