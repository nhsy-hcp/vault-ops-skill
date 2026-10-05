#!/usr/bin/env python3
"""Read-only HashiCorp Vault ops collector for the vault-ops Claude skill.

Subcommands write small JSON files (mode 0600) and print only the written
paths on stdout; diagnostics go to stderr. Nothing here writes to Vault.

  audit      namespace walk + rule checks          -> {cluster}-findings-{ts}.json
                                                      + {cluster}-inventory-{ts}.json
  health     seal/HA/version/license/replication   -> {cluster}-health-{ts}.json
  inventory  namespaces, mounts, ACL policy names  -> {cluster}-inventory-{ts}.json
  usage      activity-log client counts            -> {cluster}-usage-{ts}.json
  entities   identity entities per namespace       -> {cluster}-entities-{ts}.json
  policies   ACL policy permission assessment      -> {cluster}-policies-{ts}.json
             (needs the add-on vault-ops-policy-reader policy; bodies are never written)
  diff A B   compare two findings files            -> diff-{ts}.json

Check logic is ported from nhsy-hcp/vault-tools (src/namespace_audit/report.py).
"""

# /// script
# requires-python = ">=3.12"
# dependencies = ["hvac==2.4.0", "requests>=2.32,<3"]
#
# [tool.uv]
# exclude-newer = "2026-10-05T00:00:00Z"
# ///

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any

import hvac
import requests
from hvac import exceptions as hvac_exc

TOOL_NAME = "vault-ops"
TOOL_VERSION = "0.3.0"
SCHEMA_VERSION = "1.9.0"

EXIT_OK, EXIT_FATAL, EXIT_GAPS, EXIT_FINDINGS, EXIT_INTERRUPTED = 0, 1, 2, 3, 130

# Relative to the working directory (the user's project), so Claude can read results without
# leaving the project. Output can hold hostnames, emails and role_ids: a directory the script
# creates gets a catch-all .gitignore so results are never committed.
DEFAULT_OUTPUT_DIR = ".tmp/vault-ops"

# Fallback lease ceiling when sys/config/state/sanitized is unreadable: Vault's stock 768h.
LONG_MAX_LEASE_TTL_SECONDS = 768 * 3600
# Default lease TTLs above Vault's built-in 768h default are flagged (VT-MOUNT-004, VT-LEASE-001).
DEFAULT_LEASE_TTL_WARNING_SECONDS = 768 * 3600
LICENSE_EXPIRY_WARNING_DAYS = 90
# Anti-pattern thresholds. Client rules ignore namespaces/mounts below CLIENT_RULE_MIN_CLIENTS.
MOUNT_SPRAWL_THRESHOLD = 20  # mounts of one type per namespace (VT-MOUNT-005)
CLIENT_RULE_MIN_CLIENTS = 50
NON_ENTITY_SHARE_WARNING = 0.5  # VT-CLI-001
CLIENT_GROWTH_WARNING = 0.5  # VT-CLI-002: latest month above the recent average by this fraction
CLIENT_GROWTH_MIN_CLIENTS = 100
CLIENT_CHURN_WARNING = 0.9  # VT-CLI-003: share of a mount's clients that are new this month
ROOT_NAMESPACE_SHARE_WARNING = 0.8  # VT-CLI-004
ENTITY_ACTIVE_RATIO_WARNING = 3  # VT-ID-004: entities per active entity client
ENTITY_RULE_MIN_ENTITIES = 100
# Oldest Vault major.minor still treated as supported. Update when HashiCorp ships a release.
MIN_SUPPORTED_VERSION = (1, 19)
# VT-SNAP-002: never judge overdue sooner than this past next_snapshot_start. A config write restarts the
# schedule but leaves the status's next_snapshot_start stale until the next run; 25h covers daily schedules.
SNAPSHOT_OVERDUE_MIN_GRACE_SECONDS = 25 * 3600
# VT-HLTH-006: outstanding leases on the active node. A heuristic: large lease counts slow
# unseal, leader election and expiration; tune per cluster.
LEASE_COUNT_WARNING = 100_000
# health.metrics: allowlisted sys/metrics gauges as output key -> (metric name, aggregation over
# label sets). Labels are dropped: their values can carry cluster names and addresses.
METRIC_GAUGES = {
    "leases": ("vault.expire.num_leases", "max"),
    "irrevocable_leases": ("vault.expire.num_irrevocable_leases", "max"),
    "in_flight_requests": ("vault.core.in_flight_requests", "sum"),
    "raft_fsm_pending": ("vault.raft_storage.stats.fsm_pending", "max"),
    "raft_oldest_log_age_ms": ("vault.raft.leader.oldestLogAge", "max"),
    "goroutines": ("vault.runtime.num_goroutines", "max"),
    "alloc_bytes": ("vault.runtime.alloc_bytes", "max"),
    "sys_bytes": ("vault.runtime.sys_bytes", "max"),
    "token_count": ("vault.token.count", "sum"),
}

BUILTIN_ENGINE_TYPES = frozenset(
    {
        "cubbyhole",
        "identity",
        "system",
        "ns_cubbyhole",
        "ns_identity",
        "ns_system",
        "ns_agent_registry",
        "agent_registry",
    }
)
BUILTIN_AUTH_TYPES = frozenset({"token", "ns_token"})
# ACL policy assessment (policies subcommand). Capabilities that change state; sudo is judged separately.
WRITE_CAPABILITIES = frozenset({"create", "update", "patch", "delete"})
# Representative paths whose write access lets a holder grant itself more access (VT-POL-002):
# a rule is flagged when its glob matches one of them. Values label the area in evidence.
ESCALATION_PATHS = {
    "sys/policies/acl/x": "ACL policies",
    "sys/policy/x": "ACL policies",
    "sys/auth/x": "auth methods",
    "sys/mounts/x": "secrets engines",
    "sys/namespaces/x": "namespaces",
    "auth/token/create": "token creation",
    "auth/token/create-orphan": "token creation",
    "auth/token/create/x": "token creation",
    "auth/token/roles/x": "token roles",
    "identity/entity": "identity entities",
    "identity/entity/id/x": "identity entities",
    "identity/entity/name/x": "identity entities",
    "identity/entity-alias": "identity entity aliases",
    "identity/entity-alias/id/x": "identity entity aliases",
    "identity/group": "identity groups",
    "identity/group/id/x": "identity groups",
    "identity/group/name/x": "identity groups",
}
DEPRECATED_STATUSES = frozenset({"deprecated", "pending-removal", "removed"})
BROAD_EGP_PATHS = frozenset({"*", "/*"})
# 404 bodies for an Enterprise-only path on Community: "unsupported path" (older), "enterprise-only feature" (2.x).
ENTERPRISE_ONLY_MARKERS = ("unsupported path", "enterprise-only feature")
ALWAYS_TRUE_MAIN = re.compile(r"^main\s*=\s*rule\s*\{\s*true\s*\}$")
ALWAYS_FALSE_MAIN = re.compile(r"^main\s*=\s*(?:rule\s*\{\s*false\s*\}|false)$")
SENTINEL_IMPORT = re.compile(r'^\s*import\s+"([^"]+)"', re.M)
HEALTHY_REPLICATION_STATES = frozenset({"running", "stream-wals", "idle"})
# sys/health query that returns 200 (and a body) for every node state.
HEALTH_PARAMS = {
    "standbyok": "true",
    "perfstandbyok": "true",
    "sealedcode": "200",
    "uninitcode": "200",
    "drsecondarycode": "200",
    "performancestandbycode": "200",
    "standbycode": "200",
}

SEVERITIES = ("medium", "low", "info")


@dataclass(frozen=True)
class Rule:
    severity: str
    category: str
    title: str


RULES: dict[str, Rule] = {
    "VT-MOUNT-001": Rule("medium", "lifecycle", "Plugin deprecated or pending removal"),
    "VT-AUTH-001": Rule("low", "exposure", "Auth mount listed to unauthenticated callers"),
    "VT-MOUNT-002": Rule("low", "lease", "Mount max lease TTL overrides cluster ceiling"),
    "VT-MOUNT-003": Rule("info", "replication", "Mount is local (not replicated)"),
    "VT-MOUNT-004": Rule("low", "lease", "Mount default lease TTL is long"),
    "VT-MOUNT-005": Rule("info", "hygiene", "Many mounts of one type in a namespace"),
    "VT-MOUNT-006": Rule("info", "hygiene", "KV version 1 mount"),
    "VT-NS-001": Rule("info", "hygiene", "Namespace has no auth method beyond token"),
    "VT-NS-002": Rule("info", "hygiene", "Leaf namespace appears unused"),
    "VT-SNT-001": Rule("low", "governance", "Sentinel policy is advisory"),
    "VT-SNT-002": Rule("info", "governance", "Sentinel policy is overridable"),
    "VT-SNT-003": Rule("info", "governance", "EGP applies to every path"),
    "VT-SNT-004": Rule("low", "governance", "Sentinel policy always evaluates true"),
    "VT-SNT-005": Rule("low", "governance", "Same-named Sentinel policy differs across namespaces"),
    "VT-SNT-006": Rule("medium", "governance", "Hard-mandatory Sentinel policy always evaluates false"),
    "VT-SNT-007": Rule("info", "governance", "Sentinel policy makes outbound HTTP calls"),
    "VT-LIC-001": Rule("medium", "lifecycle", "License expires soon"),
    "VT-HLTH-001": Rule("medium", "availability", "Node sealed or no active leader"),
    "VT-HLTH-002": Rule("medium", "replication", "Replication enabled but not healthy"),
    "VT-HLTH-003": Rule("info", "lifecycle", "Vault version below supported window"),
    "VT-HLTH-004": Rule("medium", "availability", "Raft autopilot reports the cluster or a server unhealthy"),
    "VT-HLTH-005": Rule("low", "lease", "Irrevocable leases present"),
    "VT-HLTH-006": Rule("medium", "lease", "Lease count is high"),
    "VT-LEASE-001": Rule("low", "lease", "Cluster default lease TTL is long"),
    "VT-AUD-001": Rule("medium", "audit", "No audit device enabled"),
    "VT-AUD-002": Rule("low", "audit", "Only one audit device enabled"),
    "VT-AUD-003": Rule("medium", "audit", "Audit device logs raw values or unhashed accessors"),
    "VT-SNAP-001": Rule("medium", "backup", "No automated Raft snapshots configured"),
    "VT-SNAP-002": Rule("medium", "backup", "Automated snapshot failing or overdue"),
    "VT-SNAP-003": Rule("info", "backup", "Automated snapshots stored on the node's local disk"),
    "VT-ID-001": Rule("low", "identity", "Entity has no aliases"),
    "VT-ID-002": Rule("info", "identity", "Policies attached directly to entity"),
    "VT-ID-003": Rule("info", "identity", "Entity is disabled"),
    "VT-ID-004": Rule("low", "identity", "Far more entities than active clients"),
    "VT-ID-005": Rule("low", "identity", "Alias name shared by several entities"),
    "VT-CLI-001": Rule("low", "clients", "Most clients are token-only (non-entity)"),
    "VT-CLI-002": Rule("low", "clients", "Client count growing sharply"),
    "VT-CLI-003": Rule("low", "clients", "Mount creates new clients every month"),
    "VT-CLI-004": Rule("info", "clients", "Most clients in the root namespace"),
    "VT-POL-001": Rule("medium", "access", "ACL policy grants write or sudo on every path"),
    "VT-POL-002": Rule("medium", "access", "ACL policy can change access control"),
    "VT-POL-003": Rule("low", "access", "ACL policy grants sudo"),
    "VT-POL-004": Rule("low", "access", "Same-named ACL policy differs across namespaces"),
    "VT-POL-005": Rule("info", "access", "ACL policy could not be parsed"),
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    namespace: str  # stored key: "" for root, "a/b" for children
    object_kind: str
    object_path: str | None
    object_type: str | None
    detail: str
    evidence: MappingProxyType = field(default_factory=lambda: MappingProxyType({}), compare=False, hash=False)

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.rule_id, display_namespace(self.namespace), self.object_kind, self.object_path)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "severity": self.rule.severity,
            "category": self.rule.category,
            "namespace": display_namespace(self.namespace),
            "object": {"kind": self.object_kind, "path": self.object_path, "type": self.object_type},
            "title": self.rule.title,
            "detail": self.detail,
            "evidence": dict(sorted(self.evidence.items())),
        }


def finding(
    rule_id: str,
    namespace: str,
    object_kind: str,
    object_path: str | None,
    object_type: str | None,
    detail: str,
    **evidence: Any,
) -> Finding:
    return Finding(rule_id, namespace, object_kind, object_path, object_type, detail, MappingProxyType(evidence))


# --------------------------------------------------------------------------- helpers


def fingerprint(rule_id: str, namespace: str, kind: str, path: str | None) -> str:
    raw = f"{rule_id}|{namespace}|{kind}|{path or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def display_namespace(path: str) -> str:
    return "/" if path in ("", "/") else f"{path.strip('/')}/"


def normalise_namespace(path: str | None) -> str:
    return (path or "").strip().strip("/")


def format_ttl(seconds: int) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def format_multiple(value: int, baseline: int) -> str:
    ratio = value / baseline
    return f"{ratio:.0f}x" if abs(ratio - round(ratio)) < 0.05 else f"{ratio:.1f}x"


def client_count(block: dict[str, Any] | None, key: str = "clients") -> int:
    return int((block or {}).get(key) or 0)


def share(part: int, whole: int) -> str:
    return f"{part / whole:.0%}" if whole else "n/a"


def parent_of(path: str) -> str | None:
    if path == "":
        return None
    return path.rsplit("/", 1)[0] if "/" in path else ""


def _meaningful_lines(body: str) -> list[str]:
    return [s for line in body.splitlines() if (s := line.strip()) and not s.startswith(("#", "//"))]


def is_trivial_policy(body: Any) -> bool:
    if not isinstance(body, str):
        return False
    meaningful = _meaningful_lines(body)
    if not meaningful:
        return True
    return ALWAYS_TRUE_MAIN.match(" ".join(meaningful)) is not None


def is_always_false_policy(body: Any) -> bool:
    """Only `main = rule { false }` (or `main = false`) beyond comments and imports: denies every matched request."""
    if not isinstance(body, str):
        return False
    meaningful = [s for s in _meaningful_lines(body) if not SENTINEL_IMPORT.match(s)]
    return ALWAYS_FALSE_MAIN.match(" ".join(meaningful)) is not None


def sentinel_imports(body: str) -> tuple[str, ...]:
    return tuple(sorted(set(SENTINEL_IMPORT.findall(body))))


def days_until(timestamp: str, now: datetime | None = None) -> int | None:
    try:
        expiry = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return (expiry - (now or datetime.now(UTC))).days


def parse_time(timestamp: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def as_bool(value: Any) -> bool:
    """Vault stores audit options as strings ("true"/"false"); parse them like Go's ParseBool."""
    return value is True or str(value).strip().lower() in ("1", "t", "true")


def parse_version(version: str) -> tuple[int, int] | None:
    match = re.match(r"v?(\d+)\.(\d+)", version or "")
    return (int(match[1]), int(match[2])) if match else None


def sanitise_error(exc: BaseException) -> str:
    """Exception class plus HTTP status only: hvac messages can echo request URLs."""
    status = getattr(getattr(exc, "response", None), "status_code", None)
    message = type(exc).__name__ + (f" (HTTP {status})" if status else "")
    return message[:200]


def utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def iso(ts: datetime) -> str:
    return ts.isoformat().replace("+00:00", "Z")


def log(message: str) -> None:
    print(message, file=sys.stderr)


# --------------------------------------------------------------------------- vault access


@dataclass
class Config:
    addr: str
    token: str
    verify: bool | str
    namespace: str = ""

    @classmethod
    def from_env(cls, namespace: str | None = None) -> Config:
        addr = os.getenv("VAULT_ADDR", "")
        token = os.getenv("VAULT_TOKEN", "")
        if not addr or not token:
            raise SystemExit("error: VAULT_ADDR and VAULT_TOKEN must be set in the environment")
        skip = os.getenv("VAULT_SKIP_VERIFY", "").lower() in ("1", "true")
        verify: bool | str = False if skip else (os.getenv("VAULT_CACERT") or True)
        if verify is False:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        ns = namespace if namespace is not None else os.getenv("VAULT_NAMESPACE", "")
        return cls(addr=addr.rstrip("/"), token=token, verify=verify, namespace=normalise_namespace(ns))


class VaultReader:
    """GET-only access to Vault, one hvac client per namespace over a shared session."""

    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        # hvac lets a passed-in session's verify override its own verify= argument, and
        # Session.verify defaults to True, so skip-verify/CA settings must live on the session.
        self.session.verify = config.verify
        self._clients: dict[str, hvac.Client] = {}
        self._lock = threading.Lock()

    def client(self, namespace: str = "") -> hvac.Client:
        with self._lock:
            if namespace not in self._clients:
                self._clients[namespace] = hvac.Client(
                    url=self.config.addr,
                    token=self.config.token,
                    namespace=namespace or None,
                    verify=self.config.verify,
                    session=self.session,
                )
            return self._clients[namespace]

    def get(self, path: str, namespace: str = "", params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET /v1/<path>; raises hvac exceptions (InvalidPath on 404, Forbidden on 403)."""
        response = self.client(namespace).adapter.get(f"/v1/{path}", params=params)
        return response if isinstance(response, dict) else {}

    def list(self, path: str, namespace: str = "") -> list[str]:
        return list(self.get(path, namespace, params={"list": "true"}).get("data", {}).get("keys") or [])

    def data(self, path: str, namespace: str = "", params: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = self.get(path, namespace, params)
        return payload.get("data", payload) if isinstance(payload.get("data"), dict) else payload

    def validate(self) -> None:
        try:
            self.get("auth/token/lookup-self")
        except hvac_exc.Forbidden as exc:
            raise SystemExit("error: token rejected (403 on auth/token/lookup-self)") from exc
        except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
            raise SystemExit(f"error: token validation failed at {self.config.addr}: {sanitise_error(exc)}") from exc

    def probe(self) -> dict[str, Any]:
        """Unauthenticated sys/health; works on every node type, DR secondaries included."""
        try:
            return self.get("sys/health", params=HEALTH_PARAMS)
        except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
            raise SystemExit(f"error: cannot reach Vault at {self.config.addr}: {sanitise_error(exc)}") from exc


def connect(namespace: str | None, allow_dr_secondary: bool = False) -> tuple[Config, VaultReader, dict[str, Any]]:
    """Probe the node, refuse DR secondaries where the subcommand needs authenticated reads, validate the token."""
    config = Config.from_env(namespace)
    reader = VaultReader(config)
    probe = reader.probe()
    if probe.get("replication_dr_mode") == "secondary":
        if not allow_dr_secondary:
            raise SystemExit(f"error: {config.addr} is a DR secondary, which rejects authenticated reads; only `health` works there. Run this against the primary.")
        return config, reader, probe  # token endpoints are disabled on a DR secondary
    reader.validate()
    return config, reader, probe


# --------------------------------------------------------------------------- collection


@dataclass
class Coverage:
    denied: list[dict[str, str]] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    namespaces_processed: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def deny(self, namespace: str, scope: str) -> None:
        with self._lock:
            self.denied.append({"namespace": display_namespace(namespace), "scope": scope})

    def error(self, namespace: str, exc: BaseException) -> None:
        with self._lock:
            self.errors.append({"namespace": display_namespace(namespace), "message": sanitise_error(exc)})

    @property
    def complete(self) -> bool:
        return not self.denied and not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "namespaces_processed": self.namespaces_processed,
            "complete": self.complete,
            "denied": sorted(self.denied, key=lambda d: (d["namespace"], d["scope"])),
            "errors": sorted(self.errors, key=lambda d: (d["namespace"], d["message"])),
        }


@dataclass
class ClusterData:
    namespaces: dict[str, dict[str, Any]] = field(default_factory=dict)
    auth: dict[str, dict[str, Any]] = field(default_factory=dict)
    secrets: dict[str, dict[str, Any]] = field(default_factory=dict)
    acl_policies: dict[str, list[str]] = field(default_factory=dict)
    egp: dict[str, dict[str, Any]] = field(default_factory=dict)
    rgp: dict[str, dict[str, Any]] = field(default_factory=dict)
    sentinel: str = "skipped"  # supported / unsupported / skipped


class Walker:
    """Breadth-first namespace walk, one thread pool per level."""

    def __init__(self, reader: VaultReader, coverage: Coverage, workers: int = 4, sentinel: bool = True):
        self.reader = reader
        self.coverage = coverage
        self.workers = max(1, workers)
        self.data = ClusterData(sentinel="unknown" if sentinel else "skipped")
        self._lock = threading.Lock()

    def walk(self, start: str = "") -> ClusterData:
        level = [start]
        seen = {start}
        while level:
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                children = [c for result in pool.map(self._visit, level) for c in result]
            level = [c for c in sorted(children) if c not in seen]
            seen.update(level)
        if self.data.sentinel == "unknown":
            self.data.sentinel = "unsupported"
        return self.data

    def _visit(self, ns: str) -> list[str]:
        with self._lock:
            self.coverage.namespaces_processed += 1
        try:
            auth = self.reader.data("sys/auth", ns)
            secrets = self.reader.data("sys/mounts", ns)
        except hvac_exc.Forbidden:
            self.coverage.deny(ns, "whole namespace (no data collected)")
            return []
        except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
            self.coverage.error(ns, exc)
            return []
        acl = self._acl_policies(ns)
        egp, rgp = self._sentinel(ns, "egp"), self._sentinel(ns, "rgp")
        with self._lock:
            self.data.auth[ns] = _mounts_only(auth)
            self.data.secrets[ns] = _mounts_only(secrets)
            self.data.acl_policies[ns] = acl
            if egp:
                self.data.egp[ns] = egp
            if rgp:
                self.data.rgp[ns] = rgp
        return self._children(ns)

    def _acl_policies(self, ns: str) -> list[str]:
        try:
            names = self.reader.list("sys/policies/acl", ns)
        except hvac_exc.Forbidden:
            self.coverage.deny(ns, "ACL policy names")
            return []
        except hvac_exc.InvalidPath:
            return []
        except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
            self.coverage.error(ns, exc)
            return []
        return sorted(n for n in names if n not in ("default", "root", "default-ceiling"))

    def _sentinel(self, ns: str, kind: str) -> dict[str, Any]:
        if self.data.sentinel in ("skipped", "unsupported"):
            return {}
        status, policies = read_sentinel_policies(self.reader, self.coverage, ns, kind)
        if status == "unsupported":
            with self._lock:
                self.data.sentinel = "unsupported"
        elif status == "supported":
            self._mark_sentinel()
        return policies

    def _mark_sentinel(self) -> None:
        with self._lock:
            if self.data.sentinel == "unknown":
                self.data.sentinel = "supported"

    def _children(self, ns: str) -> list[str]:
        try:
            payload = self.reader.get("sys/namespaces", ns, params={"list": "true"})
        except hvac_exc.InvalidPath:
            return []  # Community edition, or no children
        except hvac_exc.Forbidden:
            self.coverage.deny(ns, "child namespaces (subtree not audited)")
            return []
        except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
            self.coverage.error(ns, exc)
            return []
        key_info = (payload.get("data") or {}).get("key_info") or {}
        children = []
        with self._lock:
            for name, info in key_info.items():
                child = f"{ns}/{name.strip('/')}" if ns else name.strip("/")
                # custom_metadata is free text and owner-controlled: never carried forward.
                self.data.namespaces[child] = {k: v for k, v in (info or {}).items() if k != "custom_metadata"}
                children.append(child)
        return children


def read_sentinel_policies(reader: VaultReader, coverage: Coverage, ns: str, kind: str) -> tuple[str, dict[str, Any]]:
    """EGP or RGP policies in one namespace, by name. Status: supported / unsupported (no Sentinel in this build) / none (listing failed)."""
    try:
        names = reader.list(f"sys/policies/{kind}", ns)
    except hvac_exc.InvalidPath as exc:
        # Vault 404s both "no Sentinel in this build" and "no policies here"; only the body differs.
        return ("unsupported" if any(m in str(exc).lower() for m in ENTERPRISE_ONLY_MARKERS) else "supported"), {}
    except hvac_exc.Forbidden:
        coverage.deny(ns, f"sentinel {kind.upper()} policies")
        return "none", {}
    except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
        coverage.error(ns, exc)
        return "none", {}
    policies: dict[str, Any] = {}
    denied = False
    for name in names:
        try:
            policies[name] = reader.data(f"sys/policies/{kind}/{name}", ns)
        except (hvac_exc.VaultError, requests.exceptions.RequestException):
            policies[name] = {"name": name, "read_error": True}
            denied = True
    if denied:
        coverage.deny(ns, f"sentinel {kind.upper()} policy bodies (attach vault-ops-sentinel-reader)")
    return "supported", policies


def _mounts_only(payload: dict[str, Any]) -> dict[str, Any]:
    """sys/auth and sys/mounts mix mount entries with response metadata; keep mounts."""
    return {k: v for k, v in payload.items() if isinstance(v, dict) and "type" in v}


def discover_namespaces(reader: VaultReader, coverage: Coverage, start: str = "", workers: int = 4) -> list[str]:
    """Namespace tree below (and including) start, using only LIST sys/namespaces."""

    def children(ns: str) -> list[str]:
        try:
            payload = reader.get("sys/namespaces", ns, params={"list": "true"})
        except hvac_exc.InvalidPath:
            return []
        except hvac_exc.Forbidden:
            coverage.deny(ns, "child namespaces (subtree not audited)")
            return []
        except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
            coverage.error(ns, exc)
            return []
        keys = (payload.get("data") or {}).get("key_info") or {}
        return [f"{ns}/{name.strip('/')}" if ns else name.strip("/") for name in keys]

    found, level = [start], [start]
    while level:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            level = sorted(c for result in pool.map(children, level) for c in result if c not in found)
        found.extend(level)
    return found


@dataclass
class Entity:
    id: str
    name: str
    namespace: str
    disabled: bool | None  # None when the entity body could not be read
    policies: list[str]
    group_count: int | None
    aliases: list[dict[str, Any]]  # {name, mount_path, mount_type, metadata}
    metadata: dict[str, Any] = field(default_factory=dict)
    last_update_time: str | None = None

    @property
    def alias_mounts(self) -> list[dict[str, Any]]:
        return [{"path": a["mount_path"], "type": a["mount_type"]} for a in self.aliases]

    def to_dict(self) -> dict[str, Any]:
        # Only written with --list: metadata and alias names can hold emails, usernames and AppRole role_ids.
        return {
            "id": self.id,
            "name": self.name,
            "disabled": self.disabled,
            "metadata": dict(sorted(self.metadata.items())),
            "alias_count": len(self.aliases),
            "aliases": self.aliases,
            "policies": self.policies,
            "group_count": self.group_count,
            "last_update_time": self.last_update_time,
        }


def collect_entities(reader: VaultReader, coverage: Coverage, namespaces: list[str], workers: int = 4) -> dict[str, list[Entity]]:
    """Identity entities per namespace, with their aliases and metadata."""

    def alias_rows(aliases: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
        rows = (
            {
                "name": a.get("name"),
                "mount_path": a.get("mount_path") or None,
                "mount_type": a.get("mount_type") or None,
                "metadata": dict(sorted((a.get("metadata") or {}).items())),
            }
            for a in aliases or []
        )
        return sorted(rows, key=lambda r: (r["mount_path"] or "", r["name"] or ""))

    def one_namespace(ns: str) -> tuple[str, list[Entity]]:
        try:
            listing = reader.get("identity/entity/id", ns, params={"list": "true"})
        except hvac_exc.InvalidPath:
            return ns, []  # no entities
        except hvac_exc.Forbidden:
            coverage.deny(ns, "identity entities")
            return ns, []
        except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
            coverage.error(ns, exc)
            return ns, []
        key_info = (listing.get("data") or {}).get("key_info") or {}
        entities, denied = [], False
        for entity_id in sorted(key_info):
            info = key_info[entity_id] or {}
            try:
                body = reader.data(f"identity/entity/id/{entity_id}", ns)
            except (hvac_exc.VaultError, requests.exceptions.RequestException):
                body, denied = None, True
            source = body or info
            entities.append(
                Entity(
                    id=entity_id,
                    name=source.get("name") or info.get("name") or entity_id,
                    namespace=ns,
                    disabled=bool(body.get("disabled")) if body is not None else None,
                    policies=sorted(body.get("policies") or []) if body is not None else [],
                    group_count=len(body.get("group_ids") or []) if body is not None else None,
                    aliases=alias_rows(source.get("aliases")),
                    metadata=dict(body.get("metadata") or {}) if body is not None else {},
                    last_update_time=body.get("last_update_time") if body is not None else None,
                )
            )
        if denied:
            coverage.deny(ns, "identity entity details")
        return ns, entities

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return dict(pool.map(one_namespace, namespaces))


@dataclass(frozen=True)
class AclRule:
    path: str
    capabilities: tuple[str, ...]


@dataclass(frozen=True)
class AclPolicy:
    """An ACL policy as assessed. The body itself is never kept: only its hash and parsed rules."""

    namespace: str
    name: str
    sha256: str
    rules: tuple[AclRule, ...] | None  # None when the body could not be parsed


_HCL_TOKEN = re.compile(r'\s+|#[^\n]*|//[^\n]*|/\*.*?\*/|"(?:[^"\\]|\\.)*"|[A-Za-z_][\w.-]*|-?\d+(?:\.\d+)?|[{}\[\]=,:]', re.S)


def parse_acl_policy(text: str) -> tuple[AclRule, ...] | None:
    """Path rules of an HCL or JSON ACL policy; None when it can't be parsed. Never raises.

    Only `path` blocks and their `capabilities` are kept: other attributes (allowed/denied
    parameters, wrapping TTLs) are skipped, so their values never leave this function.
    """
    try:
        if text.lstrip().startswith("{"):
            paths = json.loads(text).get("path") or {}
            return tuple(AclRule(str(glob), tuple(str(c) for c in (body or {}).get("capabilities") or [])) for glob, body in paths.items())
        return _parse_hcl_policy(text)
    except (ValueError, TypeError, IndexError, AttributeError):
        return None


def _parse_hcl_policy(text: str) -> tuple[AclRule, ...] | None:
    tokens, pos = [], 0
    while pos < len(text):
        match = _HCL_TOKEN.match(text, pos)
        if not match:
            return None
        pos = match.end()
        if not match.group()[0].isspace() and not match.group().startswith(("#", "//", "/*")):
            tokens.append(match.group())

    def skip_value(i: int) -> int:
        if tokens[i] not in ("{", "["):
            return i + 1
        depth = 0
        while True:
            depth += {"{": 1, "[": 1, "}": -1, "]": -1}.get(tokens[i], 0)
            i += 1
            if depth == 0:
                return i

    rules, i = [], 0
    while i < len(tokens):
        if tokens[i] != "path" or not tokens[i + 1].startswith('"') or tokens[i + 2] != "{":
            return None
        glob, capabilities, i = json.loads(tokens[i + 1]), [], i + 3
        while tokens[i] != "}":
            key = tokens[i].strip('"')
            i += 2 if tokens[i + 1] == "=" else 1
            if key == "capabilities" and tokens[i] == "[":
                i += 1
                while tokens[i] != "]":
                    if tokens[i] != ",":
                        capabilities.append(json.loads(tokens[i]))
                    i += 1
                i += 1
            else:
                i = skip_value(i)
            if tokens[i] == ",":
                i += 1
        rules.append(AclRule(glob, tuple(capabilities)))
        i += 1
    return tuple(rules)


def glob_matches(glob: str, path: str) -> bool:
    """Vault ACL path matching: `+` is one whole segment, a trailing `*` is a prefix match."""
    prefix = glob.endswith("*")
    pattern = "/".join("[^/]+" if part == "+" else re.escape(part) for part in (glob[:-1] if prefix else glob).split("/"))
    return re.fullmatch(pattern + (".*" if prefix else ""), path) is not None


def matches_everything(glob: str) -> bool:
    """`*`, `+/*`, `+/+/*`...: every path in the namespace (and, past the `+` levels, its children)."""
    return glob.endswith("*") and all(part in ("+", "") for part in glob[:-1].split("/"))


def rule_flags(rule: AclRule) -> list[str]:
    """VT-POL rule IDs one path rule trips. A rule containing `deny` grants nothing."""
    capabilities = set(rule.capabilities)
    if "deny" in capabilities:
        return []
    flags = []
    if matches_everything(rule.path) and capabilities & (WRITE_CAPABILITIES | {"sudo"}):
        flags.append("VT-POL-001")
    elif capabilities & WRITE_CAPABILITIES and any(glob_matches(rule.path, target) for target in ESCALATION_PATHS):
        flags.append("VT-POL-002")
    if "sudo" in capabilities:
        flags.append("VT-POL-003")
    return flags


def collect_acl_policies(reader: VaultReader, coverage: Coverage, namespaces: list[str], workers: int = 4) -> list[AclPolicy]:
    """ACL policy bodies per namespace (all but `root`), parsed and hashed; bodies are not kept.

    Reading a body needs the add-on vault-ops-policy-reader policy (`read`, no sudo). A denied
    body is recorded once per namespace and the walk continues.
    """

    def one_namespace(ns: str) -> list[AclPolicy]:
        try:
            names = reader.list("sys/policies/acl", ns)
        except hvac_exc.InvalidPath:
            return []
        except hvac_exc.Forbidden:
            coverage.deny(ns, "ACL policy names")
            return []
        except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
            coverage.error(ns, exc)
            return []
        policies, denied = [], False
        for name in sorted(n for n in names if n != "root"):
            try:
                body = reader.data(f"sys/policies/acl/{name}", ns).get("policy")
            except hvac_exc.Forbidden:
                denied = True
                continue
            except hvac_exc.InvalidPath:
                continue  # deleted between list and read
            except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
                coverage.error(ns, exc)
                continue
            if not isinstance(body, str):
                coverage.error(ns, ValueError("unrecognised ACL policy payload"))
                continue
            policies.append(AclPolicy(ns, name, hashlib.sha256(body.encode()).hexdigest()[:16], parse_acl_policy(body)))
        if denied:
            coverage.deny(ns, "ACL policy bodies (attach vault-ops-policy-reader)")
        return policies

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return [p for result in pool.map(one_namespace, namespaces) for p in result]


@dataclass(frozen=True)
class SentinelPolicy:
    """A Sentinel EGP/RGP as assessed. The source is hashed and scanned, never kept."""

    namespace: str
    kind: str  # egp / rgp
    name: str
    enforcement_level: str | None
    paths: tuple[str, ...]  # EGP only
    sha256: str
    imports: tuple[str, ...]
    trivial: bool
    always_false: bool
    line_count: int


def sentinel_policy(ns: str, kind: str, name: str, policy: dict[str, Any], body: str) -> SentinelPolicy:
    paths = policy.get("paths") if kind == "egp" else None
    return SentinelPolicy(
        namespace=ns,
        kind=kind,
        name=name,
        enforcement_level=policy.get("enforcement_level"),
        paths=tuple(sorted(str(p) for p in paths)) if isinstance(paths, list) else (),
        sha256=hashlib.sha256(body.encode()).hexdigest()[:16],
        imports=sentinel_imports(body),
        trivial=is_trivial_policy(body),
        always_false=is_always_false_policy(body),
        line_count=len(body.splitlines()),
    )


def collect_sentinel_policies(reader: VaultReader, coverage: Coverage, namespaces: list[str], workers: int = 4) -> tuple[str, list[SentinelPolicy]]:
    """EGP/RGP policies per namespace, hashed and scanned; sources are not kept.

    Reading a body needs the add-on vault-ops-sentinel-reader (`read`, no sudo). Returns `unsupported`
    (not an error) on a build without Sentinel, and stops probing once that is known.
    """
    state = {"status": "unknown"}
    lock = threading.Lock()

    def one_namespace(ns: str) -> list[SentinelPolicy]:
        policies: list[SentinelPolicy] = []
        for kind in ("egp", "rgp"):
            if state["status"] == "unsupported":
                break
            status, raw = read_sentinel_policies(reader, coverage, ns, kind)
            with lock:
                if status == "unsupported":
                    state["status"] = "unsupported"
                elif status == "supported" and state["status"] == "unknown":
                    state["status"] = "supported"
            for name, policy in sorted(raw.items()):
                if policy.get("read_error"):
                    continue  # recorded as a coverage denial
                body = policy.get("policy")
                if not isinstance(body, str):
                    coverage.error(ns, ValueError("unrecognised Sentinel policy payload"))
                    continue
                policies.append(sentinel_policy(ns, kind, name, policy, body))
        return policies

    if not namespaces:
        return "unsupported", []
    found = one_namespace(namespaces[0])  # probe first, so a CE build costs two requests
    if state["status"] != "unsupported":
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            found += [p for result in pool.map(one_namespace, namespaces[1:]) for p in result]
    return ("unsupported" if state["status"] == "unknown" else state["status"]), found


def collect_health(reader: VaultReader, coverage: Coverage, probe: dict[str, Any] | None = None) -> dict[str, Any]:
    """Cluster-level status. Every read is optional; failures land in coverage.

    On a DR secondary only the unauthenticated endpoints answer (health, leader,
    replication status), so license and lease reads are skipped there.
    """
    health: dict[str, Any] = probe or {}
    if probe is None:
        try:
            health = reader.get("sys/health", params=HEALTH_PARAMS)
        except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
            coverage.error("", exc)
    dr_secondary = health.get("replication_dr_mode") == "secondary"

    result: dict[str, Any] = {
        "cluster_name": health.get("cluster_name") or "vault",
        "version": health.get("version"),
        "enterprise": "+ent" in (health.get("version") or ""),
        "initialized": health.get("initialized"),
        "sealed": health.get("sealed"),
        "standby": health.get("standby"),
        "performance_standby": health.get("performance_standby"),
        "replication_dr_mode": health.get("replication_dr_mode"),
        "replication_performance_mode": health.get("replication_performance_mode"),
        "dr_secondary": dr_secondary,
        "leader": None,
        "license": None,
        "replication": None,
        "raft": None,
        "lease_ttls": None,
        "audit_devices": None,
        "snapshots": None,
        "metrics": None,
    }

    def optional(path: str, scope: str) -> dict[str, Any] | None:
        try:
            return reader.data(path)
        except hvac_exc.Forbidden:
            coverage.deny("", scope)
        except hvac_exc.InvalidPath:
            pass
        except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
            coverage.error("", exc)
        return None

    if (leader := optional("sys/leader", "sys/leader")) is not None:
        result["leader"] = {
            "ha_enabled": leader.get("ha_enabled"),
            "is_self": leader.get("is_self"),
            "leader_address_present": bool(leader.get("leader_address")),
            "raft_committed_index": leader.get("raft_committed_index"),
        }
    if result["enterprise"] and not dr_secondary and (lic := optional("sys/license/status", "sys/license/status")) is not None:
        auto = lic.get("autoloaded") if isinstance(lic.get("autoloaded"), dict) else lic
        result["license"] = {
            k: auto.get(k)
            for k in (
                "license_id",
                "edition",
                "expiration_time",
                "termination_time",
                "features",
                "performance_standby_count",
            )
            if k in auto
        }
    if (repl := optional("sys/replication/status", "sys/replication/status")) is not None:
        if isinstance(repl.get("mode"), str):
            # e.g. {"mode": "unsupported"} on storage that cannot replicate (dev/inmem)
            result["replication"] = {"mode": repl["mode"]}
        else:
            result["replication"] = {kind: replication_summary(repl.get(kind) or {}) for kind in ("dr", "performance")}
    if not dr_secondary:
        result["raft"] = collect_raft(reader, coverage)
    if not dr_secondary and (cfg := optional("sys/config/state/sanitized", "sys/config/state/sanitized")) is not None:

        def positive(value: Any) -> int | None:
            # 0 means "not configured" (Vault's built-in 768h applies), not a real ceiling
            return value if isinstance(value, int) and value > 0 else None

        result["lease_ttls"] = {
            "default_lease_ttl_seconds": positive(cfg.get("default_lease_ttl")),
            "max_lease_ttl_seconds": positive(cfg.get("max_lease_ttl")),
        }
    if not dr_secondary:
        result["audit_devices"] = collect_audit_devices(reader, coverage)
        # Automated snapshots are Enterprise and raft only; elsewhere the endpoint 404s like "none configured".
        if result["enterprise"] and result["raft"] is not None:
            result["snapshots"] = collect_snapshots(reader, coverage)
        result["metrics"] = collect_metrics(reader, coverage)
    return result


def collect_metrics(reader: VaultReader, coverage: Coverage) -> dict[str, Any] | None:
    """Allowlisted sys/metrics gauges of the queried node. None when unreadable; never fatal.

    Only the METRIC_GAUGES names are kept, aggregated over their label sets, so label
    values (cluster names, addresses, peer IDs) never leave this function.
    """
    try:
        payload = reader.get("sys/metrics")
    except hvac_exc.Forbidden:
        coverage.deny("", "sys/metrics")
        return None
    except hvac_exc.InvalidPath:
        return None  # endpoint not there: nothing to judge
    except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
        coverage.error("", exc)
        return None
    gauges = payload.get("Gauges") if isinstance(payload, dict) else None
    if not isinstance(gauges, list):
        coverage.error("", ValueError("unrecognised sys/metrics payload"))
        return None
    values: dict[str, list[float]] = {}
    for gauge in gauges:
        if isinstance(gauge, dict) and isinstance(gauge.get("Value"), int | float) and not isinstance(gauge.get("Value"), bool):
            values.setdefault(str(gauge.get("Name")), []).append(gauge["Value"])
    metrics: dict[str, Any] = {"node_scope": True, "timestamp": metrics_timestamp(payload.get("Timestamp"))}
    for key, (name, agg) in METRIC_GAUGES.items():
        found = values.get(name)
        value = (sum(found) if agg == "sum" else max(found)) if found else None
        metrics[key] = int(value) if isinstance(value, float) and value.is_integer() else value
    return metrics


def metrics_timestamp(value: Any) -> str | None:
    """sys/metrics uses Go's time format ("2026-10-05 14:53:30 +0000 UTC"); return RFC3339."""
    try:
        return iso(datetime.strptime(str(value)[:25], "%Y-%m-%d %H:%M:%S %z").astimezone(UTC))
    except ValueError:
        return None


AUTOPILOT_CONFIG_KEYS = (
    "cleanup_dead_servers",
    "dead_server_last_contact_threshold",
    "last_contact_threshold",
    "max_trailing_logs",
    "min_quorum",
    "server_stabilization_time",
    "disable_upgrade_migration",
)
AUTOPILOT_SERVER_KEYS = ("status", "node_type", "node_status", "healthy", "last_contact", "last_term", "last_index", "stable_since", "version")


def collect_raft(reader: VaultReader, coverage: Coverage) -> dict[str, Any] | None:
    """Integrated storage peers and autopilot. None when the cluster does not use raft.

    Peer addresses are omitted, as with the leader address: node IDs identify the peers.
    """

    def read(path: str) -> dict[str, Any] | None:
        try:
            return reader.data(path)
        except hvac_exc.Forbidden:
            coverage.deny("", path)
        except hvac_exc.InvalidPath:
            pass
        except hvac_exc.InvalidRequest as exc:
            if "raft storage is not in use" not in str(exc):
                coverage.error("", exc)
        except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
            coverage.error("", exc)
        return None

    config = read("sys/storage/raft/configuration")
    autopilot_config = read("sys/storage/raft/autopilot/configuration")
    state = read("sys/storage/raft/autopilot/state")
    if config is None and autopilot_config is None and state is None:
        return None
    raft: dict[str, Any] = {"peers": None, "autopilot": {"configuration": None, "state": None}}
    if config is not None:
        servers = (config.get("config") or {}).get("servers") or []
        raft["peers"] = [{"node_id": s.get("node_id"), "leader": bool(s.get("leader")), "voter": bool(s.get("voter"))} for s in servers]
    if autopilot_config is not None:
        raft["autopilot"]["configuration"] = {k: autopilot_config.get(k) for k in AUTOPILOT_CONFIG_KEYS if k in autopilot_config}
    if state is not None:
        servers = state.get("servers") or {}
        raft["autopilot"]["state"] = {
            "healthy": state.get("healthy"),
            "failure_tolerance": state.get("failure_tolerance"),
            "leader": state.get("leader"),
            "voters": sorted(state.get("voters") or []),
            "upgrade_status": (state.get("upgrade_info") or {}).get("status"),
            "servers": [{"id": sid, **{k: s.get(k) for k in AUTOPILOT_SERVER_KEYS}} for sid, s in sorted(servers.items())],
        }
    return raft


AUDIT_OPTION_FLAGS = ("hmac_accessor", "log_raw", "elide_list_responses", "fallback")
AUDIT_FORMATS = frozenset({"json", "jsonx"})
AUDIT_FILE_SINKS = frozenset({"stdout", "discard"})
SNAPSHOT_TIME_KEYS = ("last_snapshot_start", "last_snapshot_end", "next_snapshot_start")
URL_SCHEME = re.compile(r"^([a-z][a-z0-9+.-]{0,15}):")


def collect_audit_devices(reader: VaultReader, coverage: Coverage) -> list[dict[str, Any]] | None:
    """Enabled audit devices (root only; sys/audit needs read+sudo). None when unreadable.

    Options are allowlisted and coerced to booleans/enums: file paths, socket addresses,
    syslog tags, prefixes, headers and descriptions never leave this function.
    """
    try:
        devices = reader.data("sys/audit")
    except hvac_exc.Forbidden:
        coverage.deny("", "sys/audit")
        return None
    except hvac_exc.InvalidPath:
        return None  # no devices is a 200 with an empty table; a 404 means the endpoint is not there
    except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
        coverage.error("", exc)
        return None
    rows = []
    for path, device in sorted(devices.items()):
        if not isinstance(device, dict) or "type" not in device:
            continue
        raw = device.get("options") if isinstance(device.get("options"), dict) else {}
        options: dict[str, Any] = {k: as_bool(raw[k]) for k in AUDIT_OPTION_FLAGS if k in raw}
        if raw.get("format") in AUDIT_FORMATS:
            options["format"] = raw["format"]
        if device.get("type") == "file":
            options["sink"] = raw.get("file_path") if raw.get("file_path") in AUDIT_FILE_SINKS else "file"
        rows.append({"path": path, "type": device.get("type"), "local": bool(device.get("local")), "options": options})
    return rows


def snapshot_status(status: dict[str, Any]) -> dict[str, Any]:
    """Allowlisted automated-snapshot status: no snapshot URL (bucket/path) and no error text."""
    errors = status.get("consecutive_errors")
    times = {k: iso(t.astimezone(UTC)) if (t := parse_time(status[k])) else None for k in SNAPSHOT_TIME_KEYS if status.get(k)}
    scheme = URL_SCHEME.match(str(status.get("last_snapshot_url") or "").lower())
    return {
        "consecutive_errors": errors if isinstance(errors, int) else None,
        **{k: times.get(k) for k in SNAPSHOT_TIME_KEYS},
        "in_progress": bool(status.get("snapshot_start")),
        "storage_scheme": scheme[1] if scheme else None,
    }


def collect_snapshots(reader: VaultReader, coverage: Coverage) -> dict[str, Any] | None:
    """Raft automated snapshots: config names plus each one's status. None when unreadable.

    The configs themselves are never read: they return storage credentials in plaintext.
    """
    base = "sys/storage/raft/snapshot-auto"
    try:
        names = reader.list(f"{base}/config")
    except hvac_exc.Forbidden:
        coverage.deny("", f"{base}/config")
        return None
    except hvac_exc.InvalidPath:
        names = []
    except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
        coverage.error("", exc)
        return None
    configs = []
    for name in sorted(names):
        status: dict[str, Any] | None = None
        try:
            status = reader.data(f"{base}/status/{name}")
        except hvac_exc.Forbidden:
            coverage.deny("", f"{base}/status")
        except hvac_exc.InvalidPath:
            status = {}
        except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
            coverage.error("", exc)
        configs.append({"name": name, "status_readable": status is not None, **snapshot_status(status or {})})
    return {"configs": configs}


def replication_summary(status: dict[str, Any]) -> dict[str, Any]:
    """Mode/state plus the link status to peers: secondaries (on a primary) or primaries (on a secondary)."""
    summary: dict[str, Any] = {"mode": status.get("mode"), "state": status.get("state")}
    if status.get("connection_state"):
        summary["connection_state"] = status["connection_state"]
    if status.get("mode") == "primary":
        summary["secondaries"] = [{"node_id": s.get("node_id"), "connection_status": s.get("connection_status")} for s in status.get("secondaries") or []]
    elif status.get("mode") == "secondary":
        summary["primaries"] = [{"connection_status": p.get("connection_status")} for p in status.get("primaries") or []]
    return summary


# --------------------------------------------------------------------------- checks


def mount_findings(data: ClusterData, system_max_lease_ttl: int | None) -> list[Finding]:
    findings: list[Finding] = []
    baseline = system_max_lease_ttl or LONG_MAX_LEASE_TTL_SECONDS
    for kind, collection in (("auth_mount", data.auth), ("secrets_mount", data.secrets)):
        for ns, mounts in collection.items():
            for path, mount in mounts.items():
                mtype = mount.get("type", "unknown")
                config = mount.get("config") or {}

                status = (mount.get("deprecation_status") or "").lower()
                if status in DEPRECATED_STATUSES:
                    findings.append(
                        finding(
                            "VT-MOUNT-001",
                            ns,
                            kind,
                            path,
                            mtype,
                            f"Plugin lifecycle status is `{status}` — plan a migration before it stops working.",
                            deprecation_status=status,
                        )
                    )

                if kind == "auth_mount" and config.get("listing_visibility") == "unauth":
                    findings.append(
                        finding(
                            "VT-AUTH-001",
                            ns,
                            kind,
                            path,
                            mtype,
                            "`listing_visibility: unauth` — this mount is enumerable by unauthenticated callers.",
                            listing_visibility="unauth",
                        )
                    )

                max_ttl = config.get("max_lease_ttl")
                if isinstance(max_ttl, int) and max_ttl > baseline:
                    if system_max_lease_ttl:
                        detail = (
                            f"`max_lease_ttl` {format_ttl(max_ttl)} overrides the cluster system max of {format_ttl(system_max_lease_ttl)} — {format_multiple(max_ttl, system_max_lease_ttl)} higher."
                        )
                    else:
                        detail = f"`max_lease_ttl` is {format_ttl(max_ttl)}, above the {format_ttl(LONG_MAX_LEASE_TTL_SECONDS)} review threshold (the cluster system max could not be read)."
                    findings.append(
                        finding(
                            "VT-MOUNT-002",
                            ns,
                            kind,
                            path,
                            mtype,
                            detail,
                            max_lease_ttl_seconds=max_ttl,
                            baseline_seconds=baseline,
                            baseline_source="cluster" if system_max_lease_ttl else "fallback",
                            multiple=round(max_ttl / baseline, 1),
                        )
                    )

                default_ttl = config.get("default_lease_ttl")
                if isinstance(default_ttl, int) and default_ttl > DEFAULT_LEASE_TTL_WARNING_SECONDS:
                    findings.append(
                        finding(
                            "VT-MOUNT-004",
                            ns,
                            kind,
                            path,
                            mtype,
                            f"`default_lease_ttl` is {format_ttl(default_ttl)}, above the {format_ttl(DEFAULT_LEASE_TTL_WARNING_SECONDS)} review threshold — new leases get this TTL by default.",
                            default_lease_ttl_seconds=default_ttl,
                            threshold_seconds=DEFAULT_LEASE_TTL_WARNING_SECONDS,
                        )
                    )

                if mount.get("local") is True and mtype not in BUILTIN_ENGINE_TYPES:
                    findings.append(
                        finding(
                            "VT-MOUNT-003",
                            ns,
                            kind,
                            path,
                            mtype,
                            "Mount is `local` — it is not replicated to performance secondaries or DR.",
                            local=True,
                        )
                    )

                if mtype in ("kv", "generic") and str((mount.get("options") or {}).get("version") or "1") == "1":
                    findings.append(
                        finding(
                            "VT-MOUNT-006",
                            ns,
                            kind,
                            path,
                            mtype,
                            "KV version 1 — no secret versioning, soft delete or check-and-set.",
                            kv_version=1,
                        )
                    )

            by_type = Counter(m.get("type", "unknown") for m in mounts.values() if m.get("type") not in BUILTIN_ENGINE_TYPES | BUILTIN_AUTH_TYPES)
            crowded = {t: n for t, n in sorted(by_type.items()) if n > MOUNT_SPRAWL_THRESHOLD}
            if crowded:
                findings.append(
                    finding(
                        "VT-MOUNT-005",
                        ns,
                        kind,
                        None,
                        None,
                        f"{', '.join(f'{n} {t}' for t, n in crowded.items())} mounts in one namespace — consider fewer mounts with per-path policies.",
                        mounts_by_type=crowded,
                        threshold=MOUNT_SPRAWL_THRESHOLD,
                    )
                )
    return findings


def namespace_findings(data: ClusterData) -> list[Finding]:
    findings: list[Finding] = []
    for ns, mounts in data.auth.items():
        external = sorted({m.get("type") for m in mounts.values()} - BUILTIN_AUTH_TYPES - {None})
        if not external:
            findings.append(
                finding(
                    "VT-NS-001",
                    ns,
                    "namespace",
                    None,
                    None,
                    "No auth method beyond the built-in token backend — nothing can log in to this namespace directly.",
                    auth_types=sorted({m.get("type") for m in mounts.values() if m.get("type")}),
                )
            )
    # Only leaves: a parent holding nothing but child namespaces is ordinary organisation.
    has_children = {parent_of(ns) for ns in data.namespaces}
    for ns, mounts in data.secrets.items():
        if ns in has_children:
            continue
        types = {m.get("type") for m in mounts.values() if m.get("type")}
        if not types - BUILTIN_ENGINE_TYPES:
            findings.append(
                finding(
                    "VT-NS-002",
                    ns,
                    "namespace",
                    None,
                    None,
                    "No secrets engine beyond the Vault built-ins, and no child namespaces — the namespace appears unused.",
                    secrets_engine_types=sorted(types),
                )
            )
    return findings


def _sentinel_rule_findings(ns: str, kind: str, name: str, level: Any, paths: Any, trivial: bool, line_count: int) -> list[Finding]:
    """VT-SNT-001..004 for one policy; shared by `audit` and `policies` so wording and fingerprints match."""
    findings: list[Finding] = []
    object_kind = f"{kind}_policy"
    if level == "advisory":
        findings.append(finding("VT-SNT-001", ns, object_kind, name, kind, "Enforcement level is `advisory` — the policy logs violations but never blocks a request.", enforcement_level=level))
    elif level == "soft-mandatory":
        findings.append(finding("VT-SNT-002", ns, object_kind, name, kind, "Enforcement level is `soft-mandatory` — a caller with a `sudo`-capable token can override it.", enforcement_level=level))
    if kind == "egp" and isinstance(paths, (list, tuple)) and any(p in BROAD_EGP_PATHS for p in paths):
        findings.append(finding("VT-SNT-003", ns, object_kind, name, kind, "Endpoint path is a wildcard — the policy applies to every request in this namespace.", paths=sorted(paths)))
    if trivial:
        findings.append(
            finding(
                "VT-SNT-004",
                ns,
                object_kind,
                name,
                kind,
                "Policy body always evaluates to true — it enforces nothing despite appearing in the policy list.",
                always_true=True,
                policy_line_count=line_count,
            )
        )
    return findings


def sentinel_findings(data: ClusterData) -> list[Finding]:
    findings: list[Finding] = []
    for kind, collection in (("egp", data.egp), ("rgp", data.rgp)):
        for ns, policies in collection.items():
            for name, policy in policies.items():
                body = policy.get("policy")
                trivial = is_trivial_policy(body)
                findings += _sentinel_rule_findings(ns, kind, name, policy.get("enforcement_level"), policy.get("paths"), trivial, len(body.splitlines()) if trivial else 0)
    return findings


def health_findings(health: dict[str, Any], now: datetime | None = None) -> list[Finding]:
    findings: list[Finding] = []
    leader = health.get("leader") or {}
    no_leader = leader.get("ha_enabled") is True and not leader.get("leader_address_present")
    if health.get("sealed") is True or no_leader:
        reason = "sealed" if health.get("sealed") else "no active leader"
        findings.append(
            finding(
                "VT-HLTH-001",
                "",
                "cluster",
                None,
                None,
                f"Node reports `{reason}` — requests to this node will fail until it is resolved.",
                sealed=bool(health.get("sealed")),
                active_leader=not no_leader,
            )
        )
    for kind, status in sorted((health.get("replication") or {}).items()):
        if not isinstance(status, dict):
            continue
        mode, state = status.get("mode"), status.get("state")
        if not mode or mode in ("disabled", "unknown"):
            continue
        peers = status.get("secondaries") or status.get("primaries") or []
        disconnected = sorted(p.get("node_id") or "primary" for p in peers if p.get("connection_status") != "connected")
        if state not in HEALTHY_REPLICATION_STATES:
            detail = f"{kind.upper()} replication is `{mode}` but its state is `{state}` — check the replication link."
        elif disconnected:
            detail = f"{kind.upper()} replication `{mode}` has disconnected peer(s): {', '.join(disconnected)} — check the cluster port (8201) path and the peer's status."
        else:
            continue
        findings.append(finding("VT-HLTH-002", "", "cluster", None, kind, detail, mode=mode, state=state, disconnected_peers=disconnected))
    autopilot = ((health.get("raft") or {}).get("autopilot") or {}).get("state") or {}
    unhealthy = sorted(s["id"] for s in autopilot.get("servers") or [] if s.get("healthy") is False)
    if autopilot.get("healthy") is False or unhealthy:
        servers = f"unhealthy server(s): {', '.join(unhealthy)}" if unhealthy else "the cluster is unhealthy"
        findings.append(
            finding(
                "VT-HLTH-004",
                "",
                "cluster",
                None,
                "raft",
                f"Raft autopilot reports {servers} (failure tolerance {autopilot.get('failure_tolerance')}) — check node status, last contact and trailing logs.",
                healthy=autopilot.get("healthy"),
                failure_tolerance=autopilot.get("failure_tolerance"),
                unhealthy_servers=unhealthy,
            )
        )
    version = parse_version(health.get("version") or "")
    if version and version < MIN_SUPPORTED_VERSION:
        minimum = ".".join(map(str, MIN_SUPPORTED_VERSION))
        findings.append(
            finding(
                "VT-HLTH-003",
                "",
                "cluster",
                None,
                None,
                f"Vault {health.get('version')} is older than {minimum}, the oldest release this tool treats as supported.",
                version=health.get("version"),
                min_supported=minimum,
            )
        )
    default_ttl = (health.get("lease_ttls") or {}).get("default_lease_ttl_seconds")
    if isinstance(default_ttl, int) and default_ttl > DEFAULT_LEASE_TTL_WARNING_SECONDS:
        findings.append(
            finding(
                "VT-LEASE-001",
                "",
                "cluster",
                None,
                "lease_ttl",
                f"Cluster `default_lease_ttl` is {format_ttl(default_ttl)}, above the {format_ttl(DEFAULT_LEASE_TTL_WARNING_SECONDS)} review threshold — mounts without their own default inherit it.",
                default_lease_ttl_seconds=default_ttl,
                threshold_seconds=DEFAULT_LEASE_TTL_WARNING_SECONDS,
            )
        )
    findings += metric_findings(health.get("metrics"))
    findings += audit_device_findings(health.get("audit_devices"))
    findings += snapshot_findings(health.get("snapshots"), now or utc_now())
    lic = health.get("license") or {}
    expiry = lic.get("expiration_time") or ""
    days = days_until(expiry, now) if expiry else None
    if days is not None and days <= LICENSE_EXPIRY_WARNING_DAYS:
        findings.append(
            finding(
                "VT-LIC-001",
                "",
                "cluster",
                None,
                "license",
                f"License expires on {expiry[:10]} ({days} day{'s' if days != 1 else ''} remaining) — renew before the grace period ends.",
                days_remaining=days,
                expiration_time=expiry,
            )
        )
    return findings


def metric_findings(metrics: dict[str, Any] | None) -> list[Finding]:
    """None (unreadable / DR secondary) or an absent gauge (standby node) is not judged."""
    metrics = metrics or {}
    findings: list[Finding] = []
    irrevocable = metrics.get("irrevocable_leases")
    if isinstance(irrevocable, int) and irrevocable > 0:
        findings.append(
            finding(
                "VT-HLTH-005",
                "",
                "cluster",
                None,
                "metrics",
                f"{irrevocable} irrevocable lease(s): Vault could not revoke them at their backend, so the credentials may still be valid there.",
                irrevocable_leases=irrevocable,
            )
        )
    leases = metrics.get("leases")
    if isinstance(leases, int) and leases > LEASE_COUNT_WARNING:
        findings.append(
            finding(
                "VT-HLTH-006",
                "",
                "cluster",
                None,
                "metrics",
                f"{leases:,} outstanding leases, above the {LEASE_COUNT_WARNING:,} review threshold: large lease counts slow unseal, leader election and expiration.",
                leases=leases,
                threshold=LEASE_COUNT_WARNING,
            )
        )
    return findings


def audit_device_findings(devices: list[dict[str, Any]] | None) -> list[Finding]:
    """None (unreadable / DR secondary) is not judged."""
    if devices is None:
        return []
    findings: list[Finding] = []
    if not devices:
        findings.append(finding("VT-AUD-001", "", "cluster", None, "audit", "No audit device is enabled — requests to this cluster leave no audit trail.", devices=0))
    elif len(devices) == 1:
        only = devices[0]
        findings.append(
            finding(
                "VT-AUD-002",
                "",
                "cluster",
                None,
                "audit",
                f"Only one audit device (`{only['path']}`) is enabled — if it cannot write, Vault refuses every request.",
                devices=1,
                device_path=only["path"],
                device_type=only.get("type"),
            )
        )
    for device in devices:
        options = device.get("options") or {}
        problems = [p for p, bad in (("log_raw", options.get("log_raw") is True), ("hmac_accessor", options.get("hmac_accessor") is False)) if bad]
        if problems:
            what = {"log_raw": "`log_raw=true` writes secrets in clear text", "hmac_accessor": "`hmac_accessor=false` writes token accessors unhashed"}
            findings.append(
                finding(
                    "VT-AUD-003",
                    "",
                    "audit_device",
                    device["path"],
                    device.get("type"),
                    f"Audit device `{device['path']}`: {'; '.join(what[p] for p in problems)}.",
                    log_raw=options.get("log_raw", False),
                    hmac_accessor=options.get("hmac_accessor", True),
                )
            )
    return findings


def snapshot_findings(snapshots: dict[str, Any] | None, now: datetime) -> list[Finding]:
    """None (CE, no raft, DR secondary, unreadable) is not judged; a config that has never run is not judged either."""
    if snapshots is None:
        return []
    configs = snapshots.get("configs") or []
    if not configs:
        return [finding("VT-SNAP-001", "", "cluster", None, "raft", "No automated Raft snapshot is configured — recovery depends on manual snapshots.", configs=0)]
    findings: list[Finding] = []
    for cfg in configs:
        errors = cfg.get("consecutive_errors") or 0
        last_start, next_start = parse_time(cfg.get("last_snapshot_start")), parse_time(cfg.get("next_snapshot_start"))
        overdue = 0
        if last_start and next_start:
            grace = max((next_start - last_start).total_seconds(), SNAPSHOT_OVERDUE_MIN_GRACE_SECONDS)
            late = (now - next_start).total_seconds()
            overdue = int(late) // 60 * 60 if late > grace else 0
        if errors or overdue:
            reason = f"the last {errors} attempt(s) failed" if errors else f"no snapshot has started for {format_ttl(overdue)} past its scheduled time"
            findings.append(
                finding(
                    "VT-SNAP-002",
                    "",
                    "snapshot_config",
                    cfg["name"],
                    cfg.get("storage_scheme"),
                    f"Automated snapshot `{cfg['name']}`: {reason} — check the status and the storage target.",
                    consecutive_errors=errors,
                    overdue_seconds=overdue,
                    last_snapshot_end=cfg.get("last_snapshot_end"),
                    next_snapshot_start=cfg.get("next_snapshot_start"),
                )
            )
        if cfg.get("storage_scheme") == "file":
            findings.append(
                finding(
                    "VT-SNAP-003",
                    "",
                    "snapshot_config",
                    cfg["name"],
                    "file",
                    f"Automated snapshot `{cfg['name']}` writes to the node's local disk — a lost node takes its snapshots with it.",
                    storage_scheme="file",
                )
            )
    return findings


def active_entity_clients(activity: dict[str, Any], current: dict[str, Any] | None = None) -> dict[str, int] | None:
    """Active entity clients per namespace: the higher of the billing period and the current month.

    None when no client activity is recorded at all (activity log disabled or a new cluster), so
    VT-ID-004 is not judged against an empty log.
    """
    if not client_count(activity.get("total")) and not client_count(current):
        return None
    active: dict[str, int] = {}
    for rows in (activity.get("by_namespace") or [], (current or {}).get("by_namespace") or []):
        for row in rows:
            ns = normalise_namespace(row.get("namespace_path"))
            active[ns] = max(active.get(ns, 0), client_count(row.get("counts"), "entity_clients"))
    return active


def entity_findings(entities: dict[str, list[Entity]], active: dict[str, int] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for ns, items in entities.items():
        if active is not None and len(items) >= ENTITY_RULE_MIN_ENTITIES and len(items) > ENTITY_ACTIVE_RATIO_WARNING * active.get(ns, 0):
            used = active.get(ns, 0)
            ratio = f"{len(items) / used:.0f} per active client" if used else "none active"
            findings.append(
                finding(
                    "VT-ID-004",
                    ns,
                    "namespace",
                    None,
                    None,
                    f"{len(items)} entities but {used} active entity clients ({ratio}) — identities are created per login or run, or never cleaned up.",
                    entities=len(items),
                    active_entity_clients=used,
                )
            )
        # Alias names stay out of findings (they can be emails or role_ids): report counts only.
        owners: dict[str, set[str]] = {}
        for e in items:
            for alias in e.aliases:
                if alias.get("name"):
                    owners.setdefault(str(alias["name"]).casefold(), set()).add(e.id)
        shared = [ids for ids in owners.values() if len(ids) > 1]
        if shared:
            affected = set().union(*shared)
            findings.append(
                finding(
                    "VT-ID-005",
                    ns,
                    "namespace",
                    None,
                    None,
                    f"{len(shared)} alias name(s) appear on {len(affected)} separate entities — the same user logging in through different auth mounts is counted as separate clients.",
                    shared_alias_names=len(shared),
                    entities_affected=len(affected),
                )
            )
        for e in items:
            if not e.aliases:
                findings.append(
                    finding(
                        "VT-ID-001",
                        ns,
                        "entity",
                        e.name,
                        None,
                        "Entity has no aliases — no login maps to it, so it is orphaned or was created by hand and never linked.",
                        entity_id=e.id,
                        group_count=e.group_count,
                    )
                )
            if e.policies:
                findings.append(
                    finding(
                        "VT-ID-002",
                        ns,
                        "entity",
                        e.name,
                        None,
                        f"Policies attached directly to the entity ({', '.join(e.policies)}) — prefer granting through groups so access is reviewable in one place.",
                        entity_id=e.id,
                        policies=e.policies,
                    )
                )
            if e.disabled:
                findings.append(
                    finding(
                        "VT-ID-003",
                        ns,
                        "entity",
                        e.name,
                        None,
                        "Entity is disabled — its tokens are refused; remove it if the identity is gone for good.",
                        entity_id=e.id,
                        alias_count=len(e.aliases),
                    )
                )
    return findings


def _mount_clients(namespaces: list[dict[str, Any]] | None) -> dict[tuple[str, str], tuple[int, str | None]]:
    return {(normalise_namespace(ns.get("namespace_path")), m.get("mount_path") or ""): (client_count(m.get("counts")), m.get("mount_type")) for ns in namespaces or [] for m in ns.get("mounts") or []}


def usage_findings(activity: dict[str, Any], current: dict[str, Any] | None = None, enterprise: bool = False) -> list[Finding]:
    """Client-count anti-patterns from the activity log (billing period) and the current month."""
    findings: list[Finding] = []
    # Judge the billing period; a new cluster has none yet, so fall back to the month in progress.
    if client_count(activity.get("total")):
        source, rows = "billing_period", activity.get("by_namespace") or []
    else:
        source, rows = "current_month", (current or {}).get("by_namespace") or []

    total = sum(client_count(row.get("counts")) for row in rows)
    for row in rows:
        counts = row.get("counts") or {}
        clients, non_entity = client_count(counts), client_count(counts, "non_entity_clients")
        if clients >= CLIENT_RULE_MIN_CLIENTS and non_entity / clients > NON_ENTITY_SHARE_WARNING:
            findings.append(
                finding(
                    "VT-CLI-001",
                    normalise_namespace(row.get("namespace_path")),
                    "namespace",
                    None,
                    None,
                    f"{non_entity} of {clients} clients ({share(non_entity, clients)}) are token-only — every token without an entity counts as a separate client.",
                    clients=clients,
                    non_entity_clients=non_entity,
                    source=source,
                )
            )
    root = sum(client_count(row.get("counts")) for row in rows if not normalise_namespace(row.get("namespace_path")))
    if enterprise and total >= CLIENT_RULE_MIN_CLIENTS and root / total > ROOT_NAMESPACE_SHARE_WARNING:
        findings.append(
            finding(
                "VT-CLI-004",
                "",
                "namespace",
                None,
                None,
                f"{root} of {total} clients ({share(root, total)}) are in the root namespace — tenants share one policy and identity space.",
                root_clients=root,
                clients=total,
                namespaces_reported=len(rows),
                source=source,
            )
        )

    months = sorted((m for m in activity.get("months") or [] if m.get("timestamp")), key=lambda m: m["timestamp"])
    series = [(m["timestamp"], client_count(m.get("counts"))) for m in months]
    if current is not None:
        current_ts = ((current.get("months") or [{}])[0] or {}).get("timestamp") or "current"
        series = [s for s in series if s[0] != current_ts] + [(current_ts, client_count(current))]
    if len(series) >= 2:
        latest_ts, latest = series[-1]
        prior = [c for _, c in series[:-1] if c > 0][-3:]
        baseline = sum(prior) / len(prior) if prior else 0
        if baseline and latest >= CLIENT_GROWTH_MIN_CLIENTS and latest > baseline * (1 + CLIENT_GROWTH_WARNING):
            findings.append(
                finding(
                    "VT-CLI-002",
                    "",
                    "cluster",
                    None,
                    None,
                    f"{latest} clients in {latest_ts[:7]} against an average of {baseline:.0f} over the previous {len(prior)} month(s) — check for login loops or identities created per run.",
                    month=latest_ts[:7],
                    clients=latest,
                    baseline_clients=round(baseline),
                    months_compared=len(prior),
                )
            )

    # Churn needs consecutive months from one query: the first month of any window reports every
    # client as new, so the current-month response (its own window) is never used here.
    if len(months) >= 2:
        prev, last = months[-2], months[-1]
        before = _mount_clients(prev.get("namespaces"))
        new = _mount_clients((last.get("new_clients") or {}).get("namespaces"))
        for (ns, mount_path), (clients, mtype) in sorted(_mount_clients(last.get("namespaces")).items()):
            if not mount_path.endswith("/") or clients < CLIENT_RULE_MIN_CLIENTS or not before.get((ns, mount_path), (0, None))[0]:
                continue
            fresh = new.get((ns, mount_path), (0, None))[0]
            if fresh / clients >= CLIENT_CHURN_WARNING:
                kind, path = ("auth_mount", mount_path[len("auth/") :]) if mount_path.startswith("auth/") else ("secrets_mount", mount_path)
                findings.append(
                    finding(
                        "VT-CLI-003",
                        ns,
                        kind,
                        path,
                        mtype,
                        f"{fresh} of {clients} clients on this mount in {last['timestamp'][:7]} were new ({share(fresh, clients)}) — identities are created per login or run instead of reused.",
                        month=last["timestamp"][:7],
                        clients=clients,
                        new_clients=fresh,
                    )
                )
    return findings


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            SEVERITIES.index(f.rule.severity),
            display_namespace(f.namespace),
            f.object_path or "",
            f.rule_id,
        ),
    )


# --------------------------------------------------------------------------- documents


def run_block(cluster: str, addr: str, start_ns: str, started: datetime, workers: int | None) -> dict[str, Any]:
    finished = utc_now()
    block = {
        "cluster_name": cluster,
        "vault_addr": addr,
        "start_namespace": display_namespace(start_ns),
        "started_at": iso(started),
        "finished_at": iso(finished),
        "duration_seconds": round((finished - started).total_seconds(), 1),
    }
    if workers is not None:
        block["worker_threads"] = workers
    return block


def build_findings_document(
    findings: list[Finding],
    coverage: Coverage,
    health: dict[str, Any],
    sentinel: str,
    run: dict[str, Any],
) -> dict[str, Any]:
    findings = sort_findings(findings)
    by_severity = {s: 0 for s in SEVERITIES}
    by_severity.update(Counter(f.rule.severity for f in findings))
    ttls = health.get("lease_ttls") or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "run": run,
        "cluster_context": {
            "vault_version": health.get("version"),
            "enterprise": health.get("enterprise"),
            "system_max_lease_ttl_seconds": ttls.get("max_lease_ttl_seconds"),
            "system_default_lease_ttl_seconds": ttls.get("default_lease_ttl_seconds"),
            "sentinel": sentinel,
        },
        "coverage": coverage.to_dict(),
        "summary": {
            "total": len(findings),
            "by_severity": by_severity,
            "by_rule": dict(sorted(Counter(f.rule_id for f in findings).items())),
        },
        "findings": [f.to_dict() for f in findings],
    }


def namespace_depth(ns: str) -> int:
    return ns.count("/") + 1 if ns else 0


def type_distribution(mounts_by_ns: dict[str, dict[str, Any]], exclude: frozenset[str] = frozenset()) -> dict[str, dict[str, int]]:
    """{type: {"mounts": n, "namespaces": m}}, most-mounted first."""
    mounts: Counter[str] = Counter()
    spread: Counter[str] = Counter()
    for ns_mounts in mounts_by_ns.values():
        types = [m.get("type") or "unknown" for m in ns_mounts.values() if m.get("type") not in exclude]
        mounts.update(types)
        spread.update(set(types))
    return {t: {"mounts": n, "namespaces": spread[t]} for t, n in sorted(mounts.items(), key=lambda kv: (-kv[1], kv[0]))}


def build_inventory_document(data: ClusterData, coverage: Coverage, run: dict[str, Any]) -> dict[str, Any]:
    namespaces = sorted(set(data.auth) | set(data.secrets))
    rows = []
    shapes: dict[tuple[int, tuple[str, ...], tuple[str, ...]], list[str]] = {}
    for ns in namespaces:
        auth_mounts = [{"path": p, "type": m.get("type"), "local": bool(m.get("local"))} for p, m in sorted(data.auth.get(ns, {}).items())]
        secrets_mounts = [
            {
                "path": p,
                "type": m.get("type"),
                "version": (m.get("options") or {}).get("version"),
                "local": bool(m.get("local")),
            }
            for p, m in sorted(data.secrets.get(ns, {}).items())
            if m.get("type") not in BUILTIN_ENGINE_TYPES
        ]
        acl = data.acl_policies.get(ns, [])
        rows.append(
            {
                "namespace": display_namespace(ns),
                "depth": namespace_depth(ns),
                "auth_count": len(auth_mounts),
                "secrets_count": len(secrets_mounts),
                "acl_policy_count": len(acl),
                "auth_mounts": auth_mounts,
                "secrets_mounts": secrets_mounts,
                "acl_policies": acl,
                "egp_policies": sorted(data.egp.get(ns, {})),
                "rgp_policies": sorted(data.rgp.get(ns, {})),
            }
        )
        signature = (namespace_depth(ns), tuple(sorted(m["type"] or "unknown" for m in auth_mounts)), tuple(sorted(m["type"] or "unknown" for m in secrets_mounts)))
        shapes.setdefault(signature, []).append(display_namespace(ns))
    auth_types = Counter(m.get("type") for mounts in data.auth.values() for m in mounts.values())
    secret_types = Counter(m.get("type") for mounts in data.secrets.values() for m in mounts.values() if m.get("type") not in BUILTIN_ENGINE_TYPES)
    sentinel_levels = Counter((p or {}).get("enforcement_level") or "unknown" for policies in (*data.egp.values(), *data.rgp.values()) for p in policies.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "run": run,
        "coverage": coverage.to_dict(),
        "summary": {
            "namespaces": len(namespaces),
            "max_depth": max((namespace_depth(ns) for ns in namespaces), default=0),
            "auth_mounts_total": sum(auth_types.values()),
            "secrets_mounts_total": sum(secret_types.values()),
            "auth_mounts_by_type": dict(sorted(auth_types.items())),
            "secrets_mounts_by_type": dict(sorted(secret_types.items())),
            "auth_types": type_distribution(data.auth),
            "secrets_types": type_distribution(data.secrets, BUILTIN_ENGINE_TYPES),
            "acl_policies": sum(len(v) for v in data.acl_policies.values()),
            "acl_policies_top": [
                {"namespace": r["namespace"], "count": r["acl_policy_count"]} for r in sorted(rows, key=lambda r: (-r["acl_policy_count"], r["namespace"]))[:10] if r["acl_policy_count"]
            ],
            "egp_policies": sum(len(v) for v in data.egp.values()),
            "rgp_policies": sum(len(v) for v in data.rgp.values()),
            "sentinel_by_enforcement": dict(sorted(sentinel_levels.items())),
            "sentinel": data.sentinel,
            # Namespaces with identical depth and mount types, largest group first: a collapsed hierarchy.
            "shapes": [
                {"depth": depth, "auth_types": list(auth), "secrets_types": list(engines), "count": len(members), "examples": members[:3]}
                for (depth, auth, engines), members in sorted(shapes.items(), key=lambda kv: (kv[0][0], -len(kv[1]), kv[1][0]))
            ],
        },
        "namespaces": rows,
    }


def build_usage_document(
    activity: dict[str, Any],
    top: int,
    run: dict[str, Any],
    coverage: Coverage,
    current: dict[str, Any] | None = None,
    enterprise: bool = False,
) -> dict[str, Any]:
    findings = sort_findings(usage_findings(activity, current, enterprise))

    def counts(block: dict[str, Any] | None) -> dict[str, int]:
        block = block or {}
        keys = ("clients", "entity_clients", "non_entity_clients", "secret_syncs", "acme_clients")
        return {k: int(block.get(k) or 0) for k in keys if k in block}

    by_ns = [
        {
            "namespace": display_namespace(normalise_namespace(ns.get("namespace_path"))),
            "counts": counts(ns.get("counts")),
            "mounts": len(ns.get("mounts") or []),
        }
        for ns in activity.get("by_namespace") or []
    ]
    by_ns.sort(key=lambda r: (-r["counts"].get("clients", 0), r["namespace"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "run": run,
        "coverage": coverage.to_dict(),
        "period": {"start_time": activity.get("start_time"), "end_time": activity.get("end_time")},
        "total": counts(activity.get("total")),
        "namespaces_reported": len(by_ns),
        "top_namespaces": by_ns[:top],
        "months": [{"timestamp": m.get("timestamp"), "counts": counts(m.get("counts"))} for m in activity.get("months") or []],
        # The billing-period query excludes the month in progress; activity/monthly covers it.
        "current_month": ({"total": counts(current), "namespaces_reported": len(current.get("by_namespace") or [])} if current is not None else None),
        "findings": [f.to_dict() for f in findings],
    }


def build_entities_document(
    entities: dict[str, list[Entity]],
    coverage: Coverage,
    run: dict[str, Any],
    include_list: bool,
    active: dict[str, int] | None = None,
) -> dict[str, Any]:
    findings = sort_findings(entity_findings(entities, active))
    rows = []
    for ns in sorted(entities, key=display_namespace):
        items = entities[ns]
        row: dict[str, Any] = {
            "namespace": display_namespace(ns),
            "entities": len(items),
            "disabled": sum(1 for e in items if e.disabled),
            "without_aliases": sum(1 for e in items if not e.alias_mounts),
            "with_direct_policies": sum(1 for e in items if e.policies),
            "alias_mount_types": dict(sorted(Counter(m["type"] or "unknown" for e in items for m in e.alias_mounts).items())),
        }
        if include_list:
            row["entity_list"] = [e.to_dict() for e in sorted(items, key=lambda e: e.name)]
        rows.append(row)
    all_entities = [e for items in entities.values() for e in items]
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "run": run,
        "coverage": coverage.to_dict(),
        "summary": {
            "namespaces": len(entities),
            "namespaces_with_entities": sum(1 for items in entities.values() if items),
            "entities": len(all_entities),
            "disabled": sum(1 for e in all_entities if e.disabled),
            "without_aliases": sum(1 for e in all_entities if not e.alias_mounts),
            "with_direct_policies": sum(1 for e in all_entities if e.policies),
            "by_rule": dict(sorted(Counter(f.rule_id for f in findings).items())),
        },
        "namespaces": rows,
        "findings": [f.to_dict() for f in findings],
    }


def acl_policy_findings(policies: list[AclPolicy]) -> list[Finding]:
    findings: list[Finding] = []
    for p in policies:
        if p.rules is None:
            findings.append(finding("VT-POL-005", p.namespace, "acl_policy", p.name, None, "Policy body could not be parsed, so its permissions were not assessed — review it by hand."))
            continue
        flagged: dict[str, list[AclRule]] = {}
        for rule in p.rules:
            for rule_id in rule_flags(rule):
                flagged.setdefault(rule_id, []).append(rule)
        if rules := flagged.get("VT-POL-001"):
            paths = sorted({r.path for r in rules})
            detail = f"Grants write or sudo on every path ({', '.join(f'`{x}`' for x in paths)}) — effectively admin in this namespace."
            findings.append(finding("VT-POL-001", p.namespace, "acl_policy", p.name, None, detail, paths=paths))
        if rules := flagged.get("VT-POL-002"):
            paths = sorted({r.path for r in rules})
            areas = sorted({label for r in rules for target, label in ESCALATION_PATHS.items() if glob_matches(r.path, target)})
            detail = f"Can write {', '.join(areas)} ({', '.join(f'`{x}`' for x in paths)}) — a holder can grant itself or others more access."
            findings.append(finding("VT-POL-002", p.namespace, "acl_policy", p.name, None, detail, areas=areas, paths=paths))
        if rules := flagged.get("VT-POL-003"):
            paths = sorted({r.path for r in rules})
            findings.append(finding("VT-POL-003", p.namespace, "acl_policy", p.name, None, f"Grants `sudo` on {', '.join(f'`{x}`' for x in paths)}.", sudo_paths=paths))
    by_name: dict[str, list[AclPolicy]] = {}
    for p in policies:
        by_name.setdefault(p.name, []).append(p)
    for name, copies in sorted(by_name.items()):
        variants = Counter(p.sha256 for p in copies)
        if len(variants) < 2:
            continue
        common = variants.most_common(1)[0][0]
        outliers = sorted(display_namespace(p.namespace) for p in copies if p.sha256 != common)
        differ = "differs" if len(outliers) == 1 else "differ"
        detail = f"`{name}` exists in {len(copies)} namespaces with {len(variants)} different bodies — copies have drifted; {len(outliers)} {differ} from the most common one."
        findings.append(finding("VT-POL-004", "", "acl_policy", name, None, detail, namespaces=len(copies), variants=len(variants), outliers=len(outliers), examples=outliers[:3]))
    return findings


def sentinel_policy_findings(policies: list[SentinelPolicy]) -> list[Finding]:
    findings: list[Finding] = []
    for p in policies:
        findings += _sentinel_rule_findings(p.namespace, p.kind, p.name, p.enforcement_level, list(p.paths), p.trivial, p.line_count)
        if p.always_false and p.enforcement_level == "hard-mandatory":
            scope = f" on {', '.join(f'`{x}`' for x in p.paths)}" if p.paths else ""
            detail = f"Hard-mandatory and `main` is always false — every request it applies to{scope} is denied, which can lock callers out."
            findings.append(finding("VT-SNT-006", p.namespace, f"{p.kind}_policy", p.name, p.kind, detail, enforcement_level=p.enforcement_level, paths=list(p.paths)))
        if "http" in p.imports:
            detail = "Imports `http` — each request it applies to can wait on an outbound call, so that endpoint's availability and latency gate Vault requests."
            findings.append(finding("VT-SNT-007", p.namespace, f"{p.kind}_policy", p.name, p.kind, detail, imports=list(p.imports)))
    by_name: dict[tuple[str, str], list[SentinelPolicy]] = {}
    for p in policies:
        by_name.setdefault((p.kind, p.name), []).append(p)
    for (kind, name), copies in sorted(by_name.items()):
        variants = Counter(p.sha256 for p in copies)
        if len(variants) < 2:
            continue
        common = variants.most_common(1)[0][0]
        outliers = sorted(display_namespace(p.namespace) for p in copies if p.sha256 != common)
        differ = "differs" if len(outliers) == 1 else "differ"
        detail = f"{kind.upper()} `{name}` exists in {len(copies)} namespaces with {len(variants)} different bodies — copies have drifted; {len(outliers)} {differ} from the most common one."
        findings.append(finding("VT-SNT-005", "", f"{kind}_policy", name, kind, detail, namespaces=len(copies), variants=len(variants), outliers=len(outliers), examples=outliers[:3]))
    return findings


def sentinel_block(status: str, policies: list[SentinelPolicy], findings: list[Finding]) -> dict[str, Any]:
    """Names, levels, paths, imports and hashes only: Sentinel source and comments are never written."""
    flagged: dict[tuple[str, str, str], set[str]] = {}
    for f in findings:
        if f.object_kind in ("egp_policy", "rgp_policy") and f.rule_id != "VT-SNT-005":  # drift is cluster-wide, not per copy
            flagged.setdefault((f.namespace, f.object_type or "", f.object_path or ""), set()).add(f.rule_id)
    rows = [
        {
            "namespace": display_namespace(p.namespace),
            "kind": p.kind,
            "name": p.name,
            "enforcement_level": p.enforcement_level,
            "paths": list(p.paths),
            "sha256": p.sha256,
            "imports": list(p.imports),
            "flagged": sorted(flagged.get((p.namespace, p.kind, p.name), ())),
        }
        for p in sorted(policies, key=lambda p: (display_namespace(p.namespace), p.kind, p.name))
    ]
    return {
        "status": status,
        "policies": rows,
        "summary": {
            "egp": sum(1 for p in policies if p.kind == "egp"),
            "rgp": sum(1 for p in policies if p.kind == "rgp"),
            "distinct_bodies": len({p.sha256 for p in policies}),
            "by_enforcement": dict(sorted(Counter(p.enforcement_level or "unknown" for p in policies).items())),
        },
    }


def build_policies_document(policies: list[AclPolicy], coverage: Coverage, run: dict[str, Any], sentinel_status: str = "skipped", sentinel: list[SentinelPolicy] | None = None) -> dict[str, Any]:
    """Policy names, body hashes and flagged rules only: ACL bodies, parameter values and Sentinel source are never written."""
    sentinel = sentinel or []
    sentinel_found = sentinel_policy_findings(sentinel)
    findings = sort_findings(acl_policy_findings(policies) + sentinel_found)
    rows = []
    for p in sorted(policies, key=lambda p: (display_namespace(p.namespace), p.name)):
        flagged = [{"path": r.path, "capabilities": sorted(r.capabilities), "rules": flags} for r in p.rules or () if (flags := rule_flags(r))]
        rows.append(
            {
                "namespace": display_namespace(p.namespace),
                "name": p.name,
                "sha256": p.sha256,
                "parsed": p.rules is not None,
                "rule_count": len(p.rules) if p.rules is not None else None,
                "flagged": flagged,
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "run": run,
        "coverage": coverage.to_dict(),
        "summary": {
            "policies": len(policies),
            "names": len({p.name for p in policies}),
            "distinct_bodies": len({p.sha256 for p in policies}),
            "unparsed": sum(1 for p in policies if p.rules is None),
            "with_flagged_rules": sum(1 for r in rows if r["flagged"]),
            "by_rule": dict(sorted(Counter(f.rule_id for f in findings).items())),
        },
        "policies": rows,
        "sentinel": sentinel_block(sentinel_status, sentinel, sentinel_found),
        "findings": [f.to_dict() for f in findings],
    }


def diff_documents(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    old_f = {f["fingerprint"]: f for f in old.get("findings", [])}
    new_f = {f["fingerprint"]: f for f in new.get("findings", [])}

    def brief(f: dict[str, Any]) -> dict[str, Any]:
        return {k: f[k] for k in ("fingerprint", "rule_id", "severity", "namespace", "object", "detail")}

    changed_evidence = [
        {"fingerprint": fp, "rule_id": new_f[fp]["rule_id"], "old": old_f[fp]["evidence"], "new": new_f[fp]["evidence"]}
        for fp in sorted(old_f.keys() & new_f.keys())
        if old_f[fp].get("evidence") != new_f[fp].get("evidence")
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "old_run": old.get("run", {}),
        "new_run": new.get("run", {}),
        "coverage": {
            "old_complete": old.get("coverage", {}).get("complete"),
            "new_complete": new.get("coverage", {}).get("complete"),
        },
        "summary": {
            "new": len(new_f.keys() - old_f.keys()),
            "resolved": len(old_f.keys() - new_f.keys()),
            "unchanged": len(old_f.keys() & new_f.keys()),
            "evidence_changed": len(changed_evidence),
        },
        "new": [brief(new_f[fp]) for fp in sorted(new_f.keys() - old_f.keys())],
        "resolved": [brief(old_f[fp]) for fp in sorted(old_f.keys() - new_f.keys())],
        "unchanged": sorted(old_f.keys() & new_f.keys()),
        "evidence_changed": changed_evidence,
    }


# --------------------------------------------------------------------------- output


def write_json(path: Path, document: dict[str, Any]) -> Path:
    if not path.parent.exists():
        path.parent.mkdir(mode=0o700, parents=True)
        (path.parent / ".gitignore").write_text("# vault-ops results are confidential: never commit them\n*\n")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(document, handle, indent=2, sort_keys=False)
        handle.write("\n")
    os.chmod(path, 0o600)
    return path


def output_path(output_dir: str, cluster: str, kind: str, ts: datetime) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "-", cluster) or "vault"
    return Path(output_dir).expanduser().resolve() / f"{safe}-{kind}-{ts.strftime('%Y%m%d-%H%M%S')}.json"


def exit_code_for(document: dict[str, Any], fail_on: str | None, fail_on_gaps: bool) -> int:
    if fail_on:
        threshold = SEVERITIES.index(fail_on)
        if any(SEVERITIES.index(f["severity"]) <= threshold for f in document["findings"]):
            return EXIT_FINDINGS
    if fail_on_gaps and not document["coverage"]["complete"]:
        return EXIT_GAPS
    return EXIT_OK


# --------------------------------------------------------------------------- commands


def _addr(config: Config, redact: bool) -> str:
    return "<redacted>" if redact else config.addr


def read_activity(reader: VaultReader, coverage: Coverage, path: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Activity-log read at root. {} when nothing is recorded yet; None when denied or failed (recorded in coverage)."""
    try:
        return reader.data(path, params=params)
    except hvac_exc.Forbidden:
        coverage.deny("", path)
    except hvac_exc.InvalidPath:
        return {}
    except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
        coverage.error("", exc)
    return None


def cmd_audit(args: argparse.Namespace) -> int:
    config, reader, probe = connect(args.namespace)
    started = utc_now()
    coverage = Coverage()
    health = collect_health(reader, coverage, probe)
    data = Walker(reader, coverage, workers=args.workers, sentinel=not args.no_sentinel).walk(config.namespace)
    max_ttl = (health.get("lease_ttls") or {}).get("max_lease_ttl_seconds")
    findings = mount_findings(data, max_ttl) + namespace_findings(data) + sentinel_findings(data) + health_findings(health)
    run = run_block(health["cluster_name"], _addr(config, args.redact_addr), config.namespace, started, args.workers)
    document = build_findings_document(findings, coverage, health, data.sentinel, run)
    print(write_json(output_path(args.output_dir, health["cluster_name"], "findings", started), document))
    # Same walk, no extra reads: the report's type distribution and hierarchy come from here.
    print(write_json(output_path(args.output_dir, health["cluster_name"], "inventory", started), build_inventory_document(data, coverage, run)))
    return exit_code_for(document, args.fail_on, args.fail_on_gaps)


def cmd_health(args: argparse.Namespace) -> int:
    config, reader, probe = connect(args.namespace, allow_dr_secondary=True)
    started = utc_now()
    coverage = Coverage()
    health = collect_health(reader, coverage, probe)
    findings = sort_findings(health_findings(health))
    document = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "run": run_block(health["cluster_name"], _addr(config, args.redact_addr), "", started, None),
        "coverage": coverage.to_dict(),
        "health": health,
        "findings": [f.to_dict() for f in findings],
    }
    print(write_json(output_path(args.output_dir, health["cluster_name"], "health", started), document))
    return EXIT_OK


def cmd_inventory(args: argparse.Namespace) -> int:
    config, reader, probe = connect(args.namespace)
    started = utc_now()
    coverage = Coverage()
    health = collect_health(reader, coverage, probe)
    data = Walker(reader, coverage, workers=args.workers, sentinel=not args.no_sentinel).walk(config.namespace)
    run = run_block(health["cluster_name"], _addr(config, args.redact_addr), config.namespace, started, args.workers)
    document = build_inventory_document(data, coverage, run)
    print(write_json(output_path(args.output_dir, health["cluster_name"], "inventory", started), document))
    return EXIT_OK


def cmd_usage(args: argparse.Namespace) -> int:
    config, reader, probe = connect("")  # activity is queried at root; it already reports every namespace
    started = utc_now()
    coverage = Coverage()
    health = collect_health(reader, coverage, probe)
    params = {k: v for k, v in (("start_time", args.start), ("end_time", args.end)) if v}
    activity = read_activity(reader, coverage, "sys/internal/counters/activity", params or None) or {}
    current = read_activity(reader, coverage, "sys/internal/counters/activity/monthly") if not args.end else None
    run = run_block(health["cluster_name"], _addr(config, args.redact_addr), "", started, None)
    document = build_usage_document(activity, args.top, run, coverage, current, enterprise=bool(health.get("enterprise")))
    print(write_json(output_path(args.output_dir, health["cluster_name"], "usage", started), document))
    return EXIT_OK


def cmd_entities(args: argparse.Namespace) -> int:
    config, reader, probe = connect(args.namespace)
    started = utc_now()
    coverage = Coverage()
    health = collect_health(reader, coverage, probe)
    namespaces = discover_namespaces(reader, coverage, config.namespace, args.workers)
    coverage.namespaces_processed = len(namespaces)
    entities = collect_entities(reader, coverage, namespaces, args.workers)
    # Activity is read at root (it reports every namespace) to compare entity counts with active clients.
    activity = read_activity(reader, coverage, "sys/internal/counters/activity")
    current = read_activity(reader, coverage, "sys/internal/counters/activity/monthly")
    active = active_entity_clients(activity, current) if activity is not None else None
    run = run_block(health["cluster_name"], _addr(config, args.redact_addr), config.namespace, started, args.workers)
    document = build_entities_document(entities, coverage, run, include_list=args.list, active=active)
    print(write_json(output_path(args.output_dir, health["cluster_name"], "entities", started), document))
    return EXIT_OK


def cmd_policies(args: argparse.Namespace) -> int:
    config, reader, probe = connect(args.namespace)
    started = utc_now()
    coverage = Coverage()
    health = collect_health(reader, coverage, probe)
    namespaces = discover_namespaces(reader, coverage, config.namespace, args.workers)
    coverage.namespaces_processed = len(namespaces)
    policies = collect_acl_policies(reader, coverage, namespaces, args.workers)
    sentinel_status, sentinel = ("skipped", []) if args.no_sentinel else collect_sentinel_policies(reader, coverage, namespaces, args.workers)
    run = run_block(health["cluster_name"], _addr(config, args.redact_addr), config.namespace, started, args.workers)
    document = build_policies_document(policies, coverage, run, sentinel_status, sentinel)
    print(write_json(output_path(args.output_dir, health["cluster_name"], "policies", started), document))
    return EXIT_OK


def cmd_diff(args: argparse.Namespace) -> int:
    try:
        old = json.loads(Path(args.old).read_text())
        new = json.loads(Path(args.new).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: cannot read findings files: {exc}") from exc
    document = diff_documents(old, new)
    print(write_json(output_path(args.output_dir, "findings", "diff", utc_now()), document))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault_ops.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Env: VAULT_ADDR, VAULT_TOKEN (required); VAULT_CACERT, VAULT_SKIP_VERIFY, VAULT_NAMESPACE, VAULT_OPS_OUTPUT_DIR (default {DEFAULT_OUTPUT_DIR})",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--output-dir", default=os.getenv("VAULT_OPS_OUTPUT_DIR") or DEFAULT_OUTPUT_DIR)
    live = argparse.ArgumentParser(add_help=False)
    live.add_argument("--namespace", default=None, help="start namespace (default: VAULT_NAMESPACE or root)")
    live.add_argument("--redact-addr", action="store_true", help="write vault_addr as <redacted>")
    walk = argparse.ArgumentParser(add_help=False)
    walk.add_argument("-w", "--workers", type=int, default=4)
    walk.add_argument("--no-sentinel", action="store_true", help="skip Sentinel EGP/RGP collection")

    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", parents=[common, live, walk], help="namespace audit -> findings.json")
    audit.add_argument("--fail-on", choices=SEVERITIES, help="exit 3 when a finding is at or above this severity")
    audit.add_argument("--fail-on-gaps", action="store_true", help="exit 2 when coverage is incomplete")
    audit.set_defaults(func=cmd_audit)
    sub.add_parser("health", parents=[common, live], help="cluster health -> health.json").set_defaults(func=cmd_health)
    sub.add_parser("inventory", parents=[common, live, walk], help="namespace/mount inventory").set_defaults(func=cmd_inventory)
    usage = sub.add_parser("usage", parents=[common, live], help="activity-log client counts")
    usage.add_argument("--start", help="RFC3339 start time (default: billing period start)")
    usage.add_argument("--end", help="RFC3339 end time")
    usage.add_argument("--top", type=int, default=20, help="namespaces to list, by client count")
    usage.set_defaults(func=cmd_usage)
    entities = sub.add_parser("entities", parents=[common, live], help="identity entities per namespace")
    entities.add_argument("-w", "--workers", type=int, default=4)
    entities.add_argument("--list", action="store_true", help="include per-entity rows (best with --namespace)")
    entities.set_defaults(func=cmd_entities)
    policies = sub.add_parser("policies", parents=[common, live, walk], help="ACL and Sentinel policy permissions (ACL bodies need vault-ops-policy-reader)")
    policies.set_defaults(func=cmd_policies)
    diff = sub.add_parser("diff", parents=[common], help="compare two findings.json files")
    diff.add_argument("old")
    diff.add_argument("new")
    diff.set_defaults(func=cmd_diff)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        log("interrupted")
        return EXIT_INTERRUPTED
    except SystemExit as exc:
        if isinstance(exc.code, str):
            log(exc.code)
            return EXIT_FATAL
        raise


if __name__ == "__main__":
    sys.exit(main())
