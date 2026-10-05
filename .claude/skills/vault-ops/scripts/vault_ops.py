#!/usr/bin/env python3
"""Read-only HashiCorp Vault ops collector for the vault-ops Claude skill.

Subcommands each write one small JSON file (mode 0600) and print only the
written path on stdout; diagnostics go to stderr. Nothing here writes to Vault.

  audit      namespace walk + rule checks          -> {cluster}-findings-{ts}.json
  health     seal/HA/version/license/replication   -> {cluster}-health-{ts}.json
  inventory  namespaces, mounts, ACL policy names  -> {cluster}-inventory-{ts}.json
  usage      activity-log client counts            -> {cluster}-usage-{ts}.json
  diff A B   compare two findings files            -> diff-{ts}.json

Check logic is ported from nhsy-hcp/vault-tools (src/namespace_audit/report.py).
"""

# /// script
# requires-python = ">=3.12"
# dependencies = ["hvac>=2.2.0", "requests>=2.32"]
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
TOOL_VERSION = "0.1.0"
SCHEMA_VERSION = "1.1.0"

EXIT_OK, EXIT_FATAL, EXIT_GAPS, EXIT_FINDINGS, EXIT_INTERRUPTED = 0, 1, 2, 3, 130

# Fallback lease ceiling when sys/config/state/sanitized is unreadable: Vault's stock 768h.
LONG_MAX_LEASE_TTL_SECONDS = 768 * 3600
LICENSE_EXPIRY_WARNING_DAYS = 90
# Oldest Vault major.minor still treated as supported. Update when HashiCorp ships a release.
MIN_SUPPORTED_VERSION = (1, 19)

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
DEPRECATED_STATUSES = frozenset({"deprecated", "pending-removal", "removed"})
BROAD_EGP_PATHS = frozenset({"*", "/*"})
ALWAYS_TRUE_MAIN = re.compile(r"^main\s*=\s*rule\s*\{\s*true\s*\}$")
HEALTHY_REPLICATION_STATES = frozenset({"running", "stream-wals", "idle"})

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
    "VT-NS-001": Rule("info", "hygiene", "Namespace has no auth method beyond token"),
    "VT-NS-002": Rule("info", "hygiene", "Leaf namespace appears unused"),
    "VT-SNT-001": Rule("low", "governance", "Sentinel policy is advisory"),
    "VT-SNT-002": Rule("info", "governance", "Sentinel policy is overridable"),
    "VT-SNT-003": Rule("info", "governance", "EGP applies to every path"),
    "VT-SNT-004": Rule("low", "governance", "Sentinel policy always evaluates true"),
    "VT-LIC-001": Rule("medium", "lifecycle", "License expires soon"),
    "VT-HLTH-001": Rule("medium", "availability", "Node sealed or no active leader"),
    "VT-HLTH-002": Rule("medium", "replication", "Replication enabled but not healthy"),
    "VT-HLTH-003": Rule("info", "lifecycle", "Vault version below supported window"),
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


def parent_of(path: str) -> str | None:
    if path == "":
        return None
    return path.rsplit("/", 1)[0] if "/" in path else ""


def is_trivial_policy(body: Any) -> bool:
    if not isinstance(body, str):
        return False
    meaningful = [s for line in body.splitlines() if (s := line.strip()) and not s.startswith(("#", "//"))]
    if not meaningful:
        return True
    return ALWAYS_TRUE_MAIN.match(" ".join(meaningful)) is not None


def days_until(timestamp: str, now: datetime | None = None) -> int | None:
    try:
        expiry = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return (expiry - (now or datetime.now(UTC))).days


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
        except requests.exceptions.RequestException as exc:
            raise SystemExit(f"error: cannot reach Vault at {self.config.addr}: {sanitise_error(exc)}") from exc


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
        try:
            names = self.reader.list(f"sys/policies/{kind}", ns)
        except hvac_exc.InvalidPath as exc:
            # Vault 404s both "no Sentinel in this build" and "no policies here"; only the body differs.
            if "unsupported path" in str(exc).lower():
                with self._lock:
                    self.data.sentinel = "unsupported"
            else:
                self._mark_sentinel()
            return {}
        except hvac_exc.Forbidden:
            self.coverage.deny(ns, f"sentinel {kind.upper()} policies")
            return {}
        except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
            self.coverage.error(ns, exc)
            return {}
        self._mark_sentinel()
        policies: dict[str, Any] = {}
        denied = False
        for name in names:
            try:
                policies[name] = self.reader.data(f"sys/policies/{kind}/{name}", ns)
            except (hvac_exc.VaultError, requests.exceptions.RequestException):
                policies[name] = {"name": name, "read_error": True}
                denied = True
        if denied:
            self.coverage.deny(ns, f"sentinel {kind.upper()} policy bodies")
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


def _mounts_only(payload: dict[str, Any]) -> dict[str, Any]:
    """sys/auth and sys/mounts mix mount entries with response metadata; keep mounts."""
    return {k: v for k, v in payload.items() if isinstance(v, dict) and "type" in v}


def collect_health(reader: VaultReader, coverage: Coverage) -> dict[str, Any]:
    """Cluster-level status. Every read is optional; failures land in coverage."""
    health: dict[str, Any] = {}
    try:
        # Force 200 for every node state so the body is always returned.
        params = {
            "standbyok": "true",
            "perfstandbyok": "true",
            "sealedcode": "200",
            "uninitcode": "200",
            "drsecondarycode": "200",
            "performancestandbycode": "200",
            "standbycode": "200",
        }
        health = reader.get("sys/health", params=params)
    except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
        coverage.error("", exc)

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
        "leader": None,
        "license": None,
        "replication": None,
        "lease_ttls": None,
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
    if result["enterprise"] and (lic := optional("sys/license/status", "sys/license/status")) is not None:
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
            result["replication"] = {kind: {"mode": (repl.get(kind) or {}).get("mode"), "state": (repl.get(kind) or {}).get("state")} for kind in ("dr", "performance")}
    if (cfg := optional("sys/config/state/sanitized", "sys/config/state/sanitized")) is not None:

        def positive(value: Any) -> int | None:
            # 0 means "not configured" (Vault's built-in 768h applies), not a real ceiling
            return value if isinstance(value, int) and value > 0 else None

        result["lease_ttls"] = {
            "default_lease_ttl_seconds": positive(cfg.get("default_lease_ttl")),
            "max_lease_ttl_seconds": positive(cfg.get("max_lease_ttl")),
        }
    return result


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


def sentinel_findings(data: ClusterData) -> list[Finding]:
    findings: list[Finding] = []
    for kind, collection in (("egp", data.egp), ("rgp", data.rgp)):
        object_kind = f"{kind}_policy"
        for ns, policies in collection.items():
            for name, policy in policies.items():
                level = policy.get("enforcement_level")
                if level == "advisory":
                    findings.append(
                        finding(
                            "VT-SNT-001",
                            ns,
                            object_kind,
                            name,
                            kind,
                            "Enforcement level is `advisory` — the policy logs violations but never blocks a request.",
                            enforcement_level=level,
                        )
                    )
                elif level == "soft-mandatory":
                    findings.append(
                        finding(
                            "VT-SNT-002",
                            ns,
                            object_kind,
                            name,
                            kind,
                            "Enforcement level is `soft-mandatory` — a caller with a `sudo`-capable token can override it.",
                            enforcement_level=level,
                        )
                    )
                paths = policy.get("paths")
                if kind == "egp" and isinstance(paths, list) and any(p in BROAD_EGP_PATHS for p in paths):
                    findings.append(
                        finding(
                            "VT-SNT-003",
                            ns,
                            object_kind,
                            name,
                            kind,
                            "Endpoint path is a wildcard — the policy applies to every request in this namespace.",
                            paths=sorted(paths),
                        )
                    )
                body = policy.get("policy")
                if is_trivial_policy(body):
                    findings.append(
                        finding(
                            "VT-SNT-004",
                            ns,
                            object_kind,
                            name,
                            kind,
                            "Policy body always evaluates to true — it enforces nothing despite appearing in the policy list.",
                            always_true=True,
                            policy_line_count=len(body.splitlines()),
                        )
                    )
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
        mode, state = (status or {}).get("mode"), (status or {}).get("state")
        if mode and mode not in ("disabled", "unknown") and state not in HEALTHY_REPLICATION_STATES:
            findings.append(
                finding(
                    "VT-HLTH-002",
                    "",
                    "cluster",
                    None,
                    kind,
                    f"{kind.upper()} replication is `{mode}` but its state is `{state}` — check the replication link.",
                    mode=mode,
                    state=state,
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


def build_inventory_document(data: ClusterData, coverage: Coverage, run: dict[str, Any]) -> dict[str, Any]:
    namespaces = sorted(set(data.auth) | set(data.secrets))
    rows = []
    for ns in namespaces:
        rows.append(
            {
                "namespace": display_namespace(ns),
                "auth_mounts": [{"path": p, "type": m.get("type"), "local": bool(m.get("local"))} for p, m in sorted(data.auth.get(ns, {}).items())],
                "secrets_mounts": [
                    {
                        "path": p,
                        "type": m.get("type"),
                        "version": (m.get("options") or {}).get("version"),
                        "local": bool(m.get("local")),
                    }
                    for p, m in sorted(data.secrets.get(ns, {}).items())
                    if m.get("type") not in BUILTIN_ENGINE_TYPES
                ],
                "acl_policies": data.acl_policies.get(ns, []),
                "egp_policies": sorted(data.egp.get(ns, {})),
                "rgp_policies": sorted(data.rgp.get(ns, {})),
            }
        )
    auth_types = Counter(m.get("type") for mounts in data.auth.values() for m in mounts.values())
    secret_types = Counter(m.get("type") for mounts in data.secrets.values() for m in mounts.values() if m.get("type") not in BUILTIN_ENGINE_TYPES)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "run": run,
        "coverage": coverage.to_dict(),
        "summary": {
            "namespaces": len(namespaces),
            "auth_mounts_by_type": dict(sorted(auth_types.items())),
            "secrets_mounts_by_type": dict(sorted(secret_types.items())),
            "acl_policies": sum(len(v) for v in data.acl_policies.values()),
            "sentinel": data.sentinel,
        },
        "namespaces": rows,
    }


def build_usage_document(
    activity: dict[str, Any],
    top: int,
    run: dict[str, Any],
    coverage: Coverage,
    current: dict[str, Any] | None = None,
) -> dict[str, Any]:
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
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(document, handle, indent=2, sort_keys=False)
        handle.write("\n")
    os.chmod(path, 0o600)
    return path


def output_path(output_dir: str, cluster: str, kind: str, ts: datetime) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "-", cluster) or "vault"
    return Path(output_dir).resolve() / f"{safe}-{kind}-{ts.strftime('%Y%m%d-%H%M%S')}.json"


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


def cmd_audit(args: argparse.Namespace) -> int:
    config = Config.from_env(args.namespace)
    reader = VaultReader(config)
    reader.validate()
    started = utc_now()
    coverage = Coverage()
    health = collect_health(reader, coverage)
    data = Walker(reader, coverage, workers=args.workers, sentinel=not args.no_sentinel).walk(config.namespace)
    max_ttl = (health.get("lease_ttls") or {}).get("max_lease_ttl_seconds")
    findings = mount_findings(data, max_ttl) + namespace_findings(data) + sentinel_findings(data) + health_findings(health)
    run = run_block(health["cluster_name"], _addr(config, args.redact_addr), config.namespace, started, args.workers)
    document = build_findings_document(findings, coverage, health, data.sentinel, run)
    path = write_json(output_path(args.output_dir, health["cluster_name"], "findings", started), document)
    print(path)
    return exit_code_for(document, args.fail_on, args.fail_on_gaps)


def cmd_health(args: argparse.Namespace) -> int:
    config = Config.from_env(args.namespace)
    reader = VaultReader(config)
    reader.validate()
    started = utc_now()
    coverage = Coverage()
    health = collect_health(reader, coverage)
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
    config = Config.from_env(args.namespace)
    reader = VaultReader(config)
    reader.validate()
    started = utc_now()
    coverage = Coverage()
    health = collect_health(reader, coverage)
    data = Walker(reader, coverage, workers=args.workers, sentinel=not args.no_sentinel).walk(config.namespace)
    run = run_block(health["cluster_name"], _addr(config, args.redact_addr), config.namespace, started, args.workers)
    document = build_inventory_document(data, coverage, run)
    print(write_json(output_path(args.output_dir, health["cluster_name"], "inventory", started), document))
    return EXIT_OK


def cmd_usage(args: argparse.Namespace) -> int:
    config = Config.from_env("")  # activity is queried at root; it already reports every namespace
    reader = VaultReader(config)
    reader.validate()
    started = utc_now()
    coverage = Coverage()
    health = collect_health(reader, coverage)
    params = {k: v for k, v in (("start_time", args.start), ("end_time", args.end)) if v}

    def read_activity(path: str, query: dict[str, Any] | None) -> dict[str, Any] | None:
        try:
            return reader.data(path, params=query)
        except hvac_exc.Forbidden:
            coverage.deny("", path)
        except hvac_exc.InvalidPath:
            return {}  # no activity recorded yet
        except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
            coverage.error("", exc)
        return None

    activity = read_activity("sys/internal/counters/activity", params or None) or {}
    current = read_activity("sys/internal/counters/activity/monthly", None) if not args.end else None
    run = run_block(health["cluster_name"], _addr(config, args.redact_addr), "", started, None)
    document = build_usage_document(activity, args.top, run, coverage, current)
    print(write_json(output_path(args.output_dir, health["cluster_name"], "usage", started), document))
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
        epilog="Env: VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE, VAULT_SKIP_VERIFY, VAULT_CACERT, VAULT_OPS_OUTPUT_DIR",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--output-dir", default=os.getenv("VAULT_OPS_OUTPUT_DIR", "outputs"))
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
