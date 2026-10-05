import json
from pathlib import Path

import pytest
import vault_ops as vo

SCHEMA_PATH = Path(__file__).resolve().parents[1] / ".claude/skills/vault-ops/schemas/findings.schema.json"
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
                "oidc/": mount("oidc", config={"max_lease_ttl": 3600}),
            },
        },
        secrets={
            "": {
                **builtin_secrets,
                "old/": mount("kv", deprecation_status="pending-removal"),
                "long/": mount("kv", config={"max_lease_ttl": 90 * 24 * 3600}),
            },
            "team-a": dict(builtin_secrets),  # has a child: not a leaf, no VT-NS-002
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
        "lease_ttls": {"default_lease_ttl_seconds": 2764800, "max_lease_ttl_seconds": 2764800},
    }
