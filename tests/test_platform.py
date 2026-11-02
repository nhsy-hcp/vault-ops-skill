"""run.platform: informational label from the VAULT_ADDR host (HCP Vault Dedicated) or the sys/health version."""

import pytest
import vault_ops as vo
from test_token_namespace import ADMIN_ROUTES, DENIED, ROOT_ONLY, env, run  # noqa: F401  (env is a fixture)

HCP_PUBLIC = "https://vault-cluster-public-vault-0a1b2c3d.4e5f6a7b.z1.hashicorp.cloud:8200"
HCP_PRIVATE = "https://vault-cluster-private-vault-0a1b2c3d.4e5f6a7b.z1.hashicorp.cloud:8200"


@pytest.mark.parametrize(
    ("addr", "version", "expected"),
    [
        (HCP_PUBLIC, "1.21.2+ent", "hcp"),
        (HCP_PRIVATE, "1.21.2+ent", "hcp"),
        (HCP_PUBLIC.upper().replace("HTTPS", "https"), "1.21.2+ent", "hcp"),
        (HCP_PUBLIC, None, "hcp"),
        ("https://127.0.0.1:8210", "2.1.1+ent", "enterprise"),
        ("https://vault.example.com:8200", "1.21.0+ent.hsm.fips1403", "enterprise"),
        ("http://127.0.0.1:8230", "1.21.0", "community"),
        ("https://vault.example.com", None, None),
        ("https://vault.example.com", "", None),
        # Lookalikes: the suffix must end the host.
        ("https://hashicorp.cloud.evil.com", "1.21.0", "community"),
        ("https://x.hashicorp.cloud.example:8200", "1.21.0+ent", "enterprise"),
        ("https://evilhashicorp.cloud", "1.21.0", "community"),
        ("not a url", "1.21.0", "community"),
        ("https://[bad-ipv6", "1.21.0+ent", "enterprise"),  # urlsplit raises ValueError
    ],
)
def test_detect_platform(addr, version, expected):
    assert vo.detect_platform(addr, version) == expected


def test_platform_in_every_output(env, monkeypatch, capsys):  # noqa: F811
    for cmd in ("health", "audit", "usage"):
        _, docs, _ = run(monkeypatch, capsys, ADMIN_ROUTES, [cmd])
        assert docs and all(doc["run"]["platform"] == "enterprise" for doc in docs), cmd


def test_platform_survives_redact_addr(env, monkeypatch, capsys):  # noqa: F811
    monkeypatch.setenv("VAULT_ADDR", HCP_PUBLIC)
    _, (doc,), _ = run(monkeypatch, capsys, ADMIN_ROUTES, ["health", "--redact-addr"])
    assert doc["run"]["vault_addr"] == "<redacted>" and doc["run"]["platform"] == "hcp"
    assert "hashicorp.cloud" not in str(doc)


# HCP Vault Dedicated read profile: the documented customer sys endpoints, in the token's namespace.
HCP_ROUTES = {
    **ADMIN_ROUTES,
    ("admin", "sys/seal-status"): {"type": "awskms", "t": 1, "n": 1, "progress": 0, "migration": False, "recovery_seal": True, "cluster_id": "x"},
    ("admin", "sys/metrics"): {"Gauges": [{"Name": "vault.expire.num_irrevocable_leases", "Value": 2.0}]},  # must not be read
}


def test_hcp_reads_documented_sys_endpoints(env, monkeypatch, capsys):  # noqa: F811
    monkeypatch.setenv("VAULT_ADDR", HCP_PUBLIC)
    code, (doc,), fake = run(monkeypatch, capsys, HCP_ROUTES, ["health"])
    health = doc["health"]
    assert code == vo.EXIT_OK and doc["run"]["platform"] == "hcp"
    assert health["seal"] == {"type": "awskms", "t": 1, "n": 1, "progress": 0, "migration": False, "recovery_seal": True}
    assert ("admin", "sys/seal-status") in fake.calls and doc["findings"] == []
    # sys/metrics is skipped on HCP, and every root-only cluster read stays unread.
    assert health["metrics"] is None and not {path for _, path in fake.calls} & set(ROOT_ONLY)
    assert all(h is None for h in (health["license"], health["raft"], health["lease_ttls"], health["audit_devices"], health["snapshots"]))
    assert doc["coverage"]["complete"] is True


def test_hcp_refused_seal_status_is_not_a_gap(env, monkeypatch, capsys):  # noqa: F811
    monkeypatch.setenv("VAULT_ADDR", HCP_PUBLIC)
    _, (doc,), _ = run(monkeypatch, capsys, {**HCP_ROUTES, ("admin", "sys/seal-status"): DENIED}, ["health"])
    assert doc["health"]["seal"] is None
    assert doc["coverage"] == {"namespaces_processed": 0, "complete": True, "denied": [], "errors": []}


def test_other_child_namespace_tokens_skip_hcp_reads(env, monkeypatch, capsys):  # noqa: F811
    _, (doc,), fake = run(monkeypatch, capsys, HCP_ROUTES, ["health"])  # VAULT_ADDR vault.example: enterprise
    assert doc["run"]["platform"] == "enterprise" and doc["health"]["metrics"] is None and doc["health"]["seal"] is None
    assert not {path for _, path in fake.calls} & {"sys/metrics", "sys/seal-status"}
