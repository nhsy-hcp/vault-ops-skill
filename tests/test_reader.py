"""VaultReader: the GET-only requests client that replaced hvac."""

import ast
import json
from pathlib import Path

import pytest
import requests
import vault_ops as vo
from conftest import FAKE_TOKEN
from test_walker_cli import ROUTES

SCRIPT = Path(vo.__file__)
ADDR = "https://vault.example:8200"


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=None):
        self.status_code = status_code
        self.ok = 200 <= status_code < 400
        self._payload = payload
        self._text = text

    @property
    def text(self):
        return self._text if self._text is not None else json.dumps(self._payload)

    def json(self):
        if self._text is not None:
            return json.loads(self._text)
        return self._payload


class FakeSession:
    """Records every call; only get() answers, any other verb fails the test."""

    def __init__(self, respond=None):
        self.headers = {}
        self.verify = True
        self.cert = None
        self.calls = []
        self.respond = respond or (lambda path, namespace, params: FakeResponse(200, {"data": {}}))

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        assert url.startswith(f"{ADDR}/v1/")
        namespace = (kwargs.get("headers") or {}).get("X-Vault-Namespace", "")
        return self.respond(url.removeprefix(f"{ADDR}/v1/"), namespace, kwargs.get("params"))

    def __getattr__(self, name):
        if name in ("post", "put", "patch", "delete", "head", "options", "request"):

            def refuse(*args, **kwargs):
                self.calls.append((name.upper(), args, kwargs))
                raise AssertionError(f"VaultReader issued {name.upper()}")

            return refuse
        raise AttributeError(name)


def reader(monkeypatch, session=None, verify=True):
    session = session or FakeSession()
    monkeypatch.setattr(vo.requests, "Session", lambda: session)
    return vo.VaultReader(vo.Config(addr=ADDR, token=FAKE_TOKEN, verify=verify)), session


@pytest.mark.parametrize("verify", [False, "/ca.pem", True])
def test_session_carries_tls_setting(monkeypatch, verify):
    monkeypatch.delenv("VAULT_CLIENT_CERT", raising=False)
    r, session = reader(monkeypatch, verify=verify)
    assert r.session is session and session.verify == verify and session.cert is None


def test_session_client_cert_from_env(monkeypatch):
    monkeypatch.setenv("VAULT_CLIENT_CERT", "/client.pem")
    monkeypatch.setenv("VAULT_CLIENT_KEY", "/client.key")
    _, session = reader(monkeypatch)
    assert session.cert == ("/client.pem", "/client.key")


def test_real_session_settings(monkeypatch):
    monkeypatch.delenv("VAULT_CLIENT_CERT", raising=False)
    r = vo.VaultReader(vo.Config(addr=ADDR, token=FAKE_TOKEN, verify="/ca.pem"))
    assert isinstance(r.session, requests.Session) and r.session.verify == "/ca.pem"
    assert r.session.headers["X-Vault-Token"] == FAKE_TOKEN and r.session.headers["X-Vault-Request"] == "true"
    assert "X-Vault-Namespace" not in r.session.headers


def test_headers_url_and_params(monkeypatch):
    r, session = reader(monkeypatch)
    assert session.headers == {"X-Vault-Token": FAKE_TOKEN, "X-Vault-Request": "true"}
    r.get("sys/health", params={"standbyok": "true"})
    r.list("sys/policies/acl/", namespace="tn001/app")
    r.get("//sys//mounts/")
    (_, url1, kw1), (_, url2, kw2), (_, url3, _) = session.calls
    assert url1 == f"{ADDR}/v1/sys/health" and kw1["params"] == {"standbyok": "true"} and kw1["headers"] is None
    assert url2 == f"{ADDR}/v1/sys/policies/acl" and kw2["params"] == {"list": "true"}
    assert kw2["headers"] == {"X-Vault-Namespace": "tn001/app"}
    assert url3 == f"{ADDR}/v1/sys/mounts"
    assert all(kw["timeout"] == vo.DEFAULT_TIMEOUT and kw["allow_redirects"] is True for _, _, kw in session.calls)


@pytest.mark.parametrize(
    ("status", "name"),
    [
        (400, "InvalidRequest"),
        (401, "Unauthorized"),
        (403, "Forbidden"),
        (404, "InvalidPath"),
        (429, "RateLimitExceeded"),
        (500, "InternalServerError"),
        (501, "VaultNotInitialized"),
        (502, "BadGateway"),
        (503, "VaultDown"),
        (418, "UnexpectedError"),
    ],
)
def test_status_maps_to_exception(monkeypatch, status, name):
    r, _ = reader(monkeypatch, FakeSession(lambda *_: FakeResponse(status, {"errors": [f"secret {FAKE_TOKEN}"]})))
    with pytest.raises(vo.VaultError) as info:
        r.get("secret/data/x")
    assert type(info.value).__name__ == name and info.value.status_code == status
    assert str(info.value) == f"secret {FAKE_TOKEN}" and "vault.example" not in str(info.value)
    assert vo.sanitise_error(info.value) == name


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (FakeResponse(404, {"errors": ["1 error occurred:", "unsupported path"]}), "1 error occurred:, unsupported path"),
        (FakeResponse(500, text="upstream timeout"), "upstream timeout"),
        (FakeResponse(502, {"errors": []}), "HTTP 502"),
    ],
)
def test_error_message_is_vault_text(monkeypatch, response, message):
    """Checks match on Vault's error text (CE Sentinel "unsupported path", "raft storage is not in use"), as with hvac."""
    r, _ = reader(monkeypatch, FakeSession(lambda *_: response))
    with pytest.raises(vo.VaultError, match="^" + message.replace("(", r"\(")):
        r.get("sys/policies/egp")


@pytest.mark.parametrize("response", [FakeResponse(204), FakeResponse(200, text="not json"), FakeResponse(200, ["a"]), FakeResponse(301)])
def test_non_dict_success_is_empty(monkeypatch, response):
    r, _ = reader(monkeypatch, FakeSession(lambda *_: response))
    assert r.get("sys/health") == {}


def test_sanitise_error_keeps_class_name_only(monkeypatch):
    r, _ = reader(monkeypatch, FakeSession(lambda *_: FakeResponse(403, {"errors": ["permission denied"]})))
    with pytest.raises(vo.Forbidden) as info:
        r.get(f"auth/token/lookup?token={FAKE_TOKEN}")
    assert vo.sanitise_error(info.value) == "Forbidden"


def test_validate_and_probe_errors(monkeypatch):
    r, _ = reader(monkeypatch, FakeSession(lambda *_: FakeResponse(403)))
    with pytest.raises(SystemExit, match="token rejected"):
        r.validate()
    r, _ = reader(monkeypatch, FakeSession(lambda *_: FakeResponse(503)))
    with pytest.raises(SystemExit, match="cannot reach Vault.*VaultDown"):
        r.probe()


def test_full_audit_issues_only_gets(monkeypatch, tmp_path, capsys):
    """Runtime guard: a whole audit through the real VaultReader records nothing but GET."""
    routes = {**ROUTES, ("", "auth/token/lookup-self"): {"data": {}}, ("", "sys/health"): {"cluster_name": "c1", "version": "2.1.1+ent", "sealed": False}}

    def respond(path, namespace, params):
        value = routes.get((namespace, path.rstrip("/")))
        if value is None or isinstance(value, vo.InvalidPath):
            return FakeResponse(404)
        if isinstance(value, vo.VaultError):
            return FakeResponse(value.status_code or 500)
        return FakeResponse(200, value)

    session = FakeSession(respond)
    monkeypatch.setattr(vo.requests, "Session", lambda: session)
    monkeypatch.setenv("VAULT_ADDR", ADDR)
    monkeypatch.setenv("VAULT_TOKEN", FAKE_TOKEN)
    monkeypatch.setenv("VAULT_SKIP_VERIFY", "true")
    monkeypatch.delenv("VAULT_NAMESPACE", raising=False)
    monkeypatch.setenv("VAULT_OPS_OUTPUT_DIR", str(tmp_path))
    assert vo.main(["audit", "--redact-addr"]) == vo.EXIT_OK
    assert len(capsys.readouterr().out.split()) == 2
    assert len(session.calls) > 10 and {method for method, *_ in session.calls} == {"GET"}


def test_source_issues_only_gets():
    """Static guard: no HTTP verb other than GET appears on a session or the requests module."""
    verbs = {"post", "put", "patch", "delete", "head", "options", "request"}
    offenders = []
    for node in ast.walk(ast.parse(SCRIPT.read_text())):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in verbs:
            owner = node.func.value
            name = owner.attr if isinstance(owner, ast.Attribute) else getattr(owner, "id", "")
            if name in ("session", "requests"):
                offenders.append(f"line {node.lineno}: {name}.{node.func.attr}")
    assert not offenders
    assert "import hvac" not in SCRIPT.read_text()
