import json
from pathlib import Path

import pytest
import vault_ops as vo

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "skills/vault-ops/schemas/findings.schema.json"
FAKE_TOKEN = "hvs.FAKE-TOKEN-must-never-appear"


@pytest.fixture
def schema():
    return json.loads(SCHEMA_PATH.read_text())


def mount(mtype, **kw):
    return {"type": mtype, "config": kw.pop("config", {}), **kw}


@pytest.fixture
def cluster_data():
    """A small tree where every mount/namespace/sentinel rule fires exactly once, plus controls."""
    builtin_secrets = {
        "cubbyhole/": mount("ns_cubbyhole", local=True),
        "identity/": mount("ns_identity"),
        "sys/": mount("ns_system"),
    }
    return vo.ClusterData(
        namespaces={"team-a": {"id": "a1"}, "team-a/prod": {"id": "a2"}, "team-b": {"id": "b1"}},
        auth={
            "": {"token/": mount("token"), "userpass/": mount("userpass", config={"listing_visibility": "unauth"})},
            "team-a": {"token/": mount("ns_token")},  # VT-NS-001
            "team-a/prod": {"token/": mount("ns_token"), "approle/": mount("approle")},
            "team-b": {
                "token/": mount("ns_token"),
                "oidc/": mount("oidc", config={"default_lease_ttl": 3600, "max_lease_ttl": 3600}),
            },
        },
        secrets={
            "": {
                **builtin_secrets,
                "old/": mount("kv", deprecation_status="pending-removal"),
                "long/": mount("kv", options={"version": "2"}, config={"default_lease_ttl": 40 * 24 * 3600, "max_lease_ttl": 90 * 24 * 3600}),
            },
            "team-a": {**builtin_secrets, **{f"app{i:02d}/": mount("kv", options={"version": "2"}) for i in range(vo.MOUNT_SPRAWL_THRESHOLD + 1)}},  # VT-MOUNT-005; has a child
            "team-a/prod": {**builtin_secrets, "kv-local/": mount("kv", local=True, options={"version": "2"})},
            "team-b": dict(builtin_secrets),  # leaf with built-ins only: VT-NS-002
        },
        acl_policies={"": ["ops"], "team-a": [], "team-a/prod": ["app"], "team-b": []},
        egp={
            "": {
                "adv": {"enforcement_level": "advisory", "paths": ["secret/*"], "policy": "main = rule { x }"},
                "wild": {"enforcement_level": "hard-mandatory", "paths": ["*"], "policy": "main = rule { y }"},
            }
        },
        rgp={
            "team-a": {
                "soft": {"enforcement_level": "soft-mandatory", "policy": "main = rule { z }"},
                "noop": {"enforcement_level": "hard-mandatory", "policy": "# c\n// d\nmain = rule {\n true\n}"},
                "ok": {"enforcement_level": "hard-mandatory", "policy": "main = rule { real }"},
            }
        },
        sentinel="supported",
    )


@pytest.fixture
def health():
    return {
        "cluster_name": "vault-cluster-x",
        "version": "1.18.2+ent",
        "enterprise": True,
        "sealed": True,
        "leader": {"ha_enabled": True, "leader_address_present": False},
        "license": {"expiration_time": "2026-10-20T00:00:00Z", "license_id": "L1"},
        "replication": {
            "dr": {"mode": "primary", "state": "idle"},
            "performance": {"mode": "secondary", "state": "connecting"},
        },
        "lease_ttls": {"default_lease_ttl_seconds": 1000 * 3600, "max_lease_ttl_seconds": 8760 * 3600},  # VT-LEASE-001
        "raft": {  # VT-HLTH-004
            "peers": [{"node_id": "n1", "leader": True, "voter": True}, {"node_id": "n2", "leader": False, "voter": True}],
            "autopilot": {"configuration": None, "state": {"healthy": False, "failure_tolerance": 0, "servers": [{"id": "n1", "healthy": True}, {"id": "n2", "healthy": False}]}},
        },
    }


def ns_counts(clients, entity=None):
    entity = clients if entity is None else entity
    return {"clients": clients, "entity_clients": entity, "non_entity_clients": clients - entity}


def month(timestamp, mounts, new_mounts):
    """One activity month in the root namespace; mounts and new_mounts map mount_path -> clients."""

    def namespaces(by_mount):
        rows = [{"mount_path": p, "mount_type": p.split("/")[1], "counts": ns_counts(c)} for p, c in by_mount.items()]
        return [{"namespace_path": "", "counts": ns_counts(sum(by_mount.values())), "mounts": rows}]

    return {
        "timestamp": timestamp,
        "counts": ns_counts(sum(mounts.values())),
        "namespaces": namespaces(mounts),
        "new_clients": {"counts": ns_counts(sum(new_mounts.values())), "namespaces": namespaces(new_mounts)},
    }


@pytest.fixture
def activity():
    """Billing period where every VT-CLI-* rule fires once (current month not included)."""
    return {
        "start_time": "2026-08-01T00:00:00Z",
        "end_time": "2026-09-30T23:59:59Z",
        "total": ns_counts(460, 180),
        "by_namespace": [
            {"namespace_path": "", "counts": ns_counts(380, 100)},  # VT-CLI-001 (74% token-only), VT-CLI-004 (83% of clients)
            {"namespace_path": "team-a/", "counts": ns_counts(60)},  # control: all entity clients
            {"namespace_path": "team-b/", "counts": ns_counts(20, 0)},  # control: below CLIENT_RULE_MIN_CLIENTS
        ],
        "months": [
            month("2026-09-01T00:00:00Z", {"auth/jwt/": 280, "auth/userpass/": 20}, {"auth/jwt/": 270}),  # VT-CLI-002, VT-CLI-003 on jwt/
            month("2026-08-01T00:00:00Z", {"auth/jwt/": 80, "auth/userpass/": 20}, {"auth/jwt/": 80, "auth/userpass/": 20}),
        ],
    }
