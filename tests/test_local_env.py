"""Regression tests for scripts/local_env.sh, local_claude.sh and token_lib.sh (task env / task claude).

A fake `vault` on PATH stands in for the cluster: FAKE_VAULT_MODE picks the answer and every call's
VAULT_* environment is logged, so the tests see which address, namespace and TLS settings were used.
"""

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
FAKE_TOKEN = "hvs.fake-audit-token"  # not a real token

pytestmark = pytest.mark.skipif(shutil.which("jq") is None or not Path("/bin/bash").exists(), reason="needs bash and jq")

FAKE_VAULT = """#!/bin/bash
env | grep '^VAULT_' | sort > "$FAKE_VAULT_LOG.$1.$RANDOM$RANDOM"
mode="${FAKE_VAULT_MODE:-ok}"
case "$1" in
  status)
    case "$mode" in sealed) exit 2 ;; down) exit 1 ;; *) exit 0 ;; esac ;;
  token)
    case "$mode" in
      ok) echo '{"data":{"ttl":7260,"expire_time":"2099-01-01T00:00:00Z","id":"x"}}' ;;
      never) echo '{"data":{"ttl":0,"expire_time":null,"id":"x"}}' ;;
      expired) echo '{"data":{"ttl":0,"expire_time":"2000-01-01T00:00:00Z","id":"x"}}' ;;
      *) echo "Error looking up token: permission denied" >&2; exit 2 ;;
    esac ;;
esac
"""

FAKE_CLAUDE = """#!/bin/bash
env | sort > "$FAKE_CLAUDE_ENV"
"""

DOTENV = """# test .env
export VAULT_ADDR=https://primary.example:8210
export VAULT_PR_ADDR=https://pr.example:8240
export VAULT_DR_ADDR=https://dr.example:8220
export VAULT_SKIP_VERIFY=true
export VAULT_TOKEN=root
export VAULT_LICENSE=fake-licence
export HCP_PROJECT_ID=fake-project
"""


@pytest.fixture
def repo(tmp_path):
    """A working directory with .env, token files and fake vault/claude binaries first on PATH."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in {"vault": FAKE_VAULT, "claude": FAKE_CLAUDE}.items():
        path = bindir / name
        path.write_text(body)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    work = tmp_path / "work"
    (work / ".tmp").mkdir(parents=True)
    (work / ".env").write_text(DOTENV)
    (work / ".tmp" / "audit-token").write_text(FAKE_TOKEN)
    (work / ".tmp" / "audit-token-pr").write_text(FAKE_TOKEN)
    (work / ".tmp" / "audit-token-ns").write_text(FAKE_TOKEN)
    (work / ".tmp" / "audit-token-ns.namespace").write_text("admin/team-x")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("VAULT_", "HCP_", "TOKEN"))}
    env.update(PATH=f"{bindir}:{env['PATH']}", FAKE_VAULT_LOG=str(tmp_path / "vault-call"), FAKE_CLAUDE_ENV=str(tmp_path / "claude-env"))
    return work, env, tmp_path


def run(repo, *args, script="local_env.sh", **extra_env):
    work, env, _ = repo
    return subprocess.run(["/bin/bash", str(SCRIPTS / script), *args], cwd=work, env={**env, **extra_env}, capture_output=True, text=True, timeout=30)


def vault_calls(repo, command):
    """VAULT_* settings of each fake `vault <command>` call, as dicts."""
    _, _, tmp = repo
    calls = []
    for path in sorted(tmp.glob(f"vault-call.{command}.*")):
        calls.append(dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line))
    return calls


def evaluated(repo, stdout, **shell_env):
    """Run stdout through bash eval, as eval "$(task env)" would, and return the resulting VAULT_* env and status."""
    work, env, _ = repo
    script = f"{stdout}\nstatus=$?\nenv | grep '^VAULT_' | sort\necho status=$status"
    out = subprocess.run(["/bin/bash", "-c", script], cwd=work, env={**env, **shell_env}, capture_output=True, text=True, timeout=30).stdout
    values = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return values, values.pop("status")


def test_primary_address_comes_from_dotenv_not_the_shell(repo):
    """Finding 1: an inherited VAULT_ADDR (e.g. from task env -- pr) must not redirect the primary's token."""
    result = run(repo, VAULT_ADDR="https://127.0.0.1:1")
    assert result.returncode == 0, result.stderr
    assert {c["VAULT_ADDR"] for c in vault_calls(repo, "token")} == {"https://primary.example:8210"}
    values, status = evaluated(repo, result.stdout)
    assert status == "0"
    assert values["VAULT_ADDR"] == "https://primary.example:8210"
    assert values["VAULT_TOKEN"] == FAKE_TOKEN
    assert values["VAULT_OPS_ENV"] == "audit"
    assert FAKE_TOKEN not in result.stdout + result.stderr


def test_pr_and_ns_targets(repo):
    pr = run(repo, "pr", VAULT_PR_ADDR="https://elsewhere:1")
    assert evaluated(repo, pr.stdout)[0]["VAULT_ADDR"] == "https://pr.example:8240"
    ns = run(repo, "ns", VAULT_NAMESPACE="admin")
    values, _ = evaluated(repo, ns.stdout)
    assert values["VAULT_NAMESPACE"] == "admin/team-x"
    assert [c.get("VAULT_NAMESPACE") for c in vault_calls(repo, "token")].count("admin/team-x") == 1  # pr lookup had none


def test_reset_unsets_every_export(repo):
    """Finding 2: task env -- reset gives .env's root token and address back to later tasks."""
    result = run(repo, "reset")
    assert result.returncode == 0
    values, status = evaluated(repo, result.stdout, VAULT_ADDR="x", VAULT_TOKEN="y", VAULT_NAMESPACE="z", VAULT_OPS_ENV="audit", VAULT_CACERT="c")
    assert values == {}
    assert status == "0"


@pytest.mark.parametrize(
    ("mode", "message"),
    [("invalid", "token expired or invalid"), ("expired", "token expired"), ("sealed", "sealed"), ("down", "unreachable")],
)
def test_failure_drops_credentials_and_fails_the_eval(repo, mode, message):
    """Findings 3 and 8: a failed check unsets a root/HCP-admin token in the shell, returns non-zero and says why."""
    result = run(repo, FAKE_VAULT_MODE=mode)
    assert result.returncode == 1
    assert message in result.stderr
    assert "permission denied" not in result.stderr  # Vault's error text is never shown
    values, status = evaluated(repo, result.stdout, VAULT_TOKEN="root", VAULT_ADDR="https://hcp.example", VAULT_NAMESPACE="admin")
    assert status != "0"
    assert values == {}


def test_missing_token_file_also_drops_credentials(repo):
    work, _, _ = repo
    (work / ".tmp" / "audit-token").unlink()
    result = run(repo)
    assert result.returncode == 1
    assert "run: task token:audit" in result.stderr
    assert evaluated(repo, result.stdout, VAULT_TOKEN="root") == ({}, "1")


def test_token_without_expiry_is_accepted(repo):
    """Finding 8: ttl 0 with no expire_time is a never-expiring token, not an expired one."""
    result = run(repo, FAKE_VAULT_MODE="never")
    assert result.returncode == 0, result.stderr
    assert "no expiry" in result.stderr


def test_generic_token_variable_is_ignored(repo):
    """Finding 4: an unrelated TOKEN in the environment neither picks the target nor gets printed."""
    secret = "s3cr3t-unrelated-value"
    result = run(repo, TOKEN=secret)
    assert result.returncode == 0, result.stderr
    assert secret not in result.stdout + result.stderr
    assert evaluated(repo, result.stdout)[0]["VAULT_OPS_ENV"] == "audit"


def test_unknown_target_does_not_echo_it(repo):
    result = run(repo, "s3cr3t")
    assert result.returncode == 1
    assert "s3cr3t" not in result.stdout + result.stderr


def test_dr_needs_no_token_file_and_exports_a_placeholder(repo):
    """Finding 6: dr never reads or exports the primary's audit token, so it works after task clean."""
    work, _, _ = repo
    (work / ".tmp" / "audit-token").unlink()
    result = run(repo, "dr")
    assert result.returncode == 0, result.stderr
    values, _ = evaluated(repo, result.stdout)
    assert values["VAULT_ADDR"] == "https://dr.example:8220"
    assert values["VAULT_TOKEN"] == "dr-health-only"
    assert "audit-token" not in result.stdout
    assert vault_calls(repo, "token") == []


def test_tls_client_settings_are_checked_and_exported(repo):
    """Finding 7: TLS settings used by the pre-flight lookup reach the exported environment too."""
    work, _, _ = repo
    tls = {"VAULT_CLIENT_CERT": "/certs/client.pem", "VAULT_CLIENT_KEY": "/certs/client.key", "VAULT_CAPATH": "/certs/ca", "VAULT_TLS_SERVER_NAME": "vault.internal"}
    result = run(repo, **tls)
    assert result.returncode == 0, result.stderr
    values, _ = evaluated(repo, result.stdout)
    lookup = vault_calls(repo, "token")[-1]
    for name, value in tls.items():
        assert values[name] == value
        assert lookup[name] == value
    assert values["VAULT_SKIP_VERIFY"] == "true"
    with (work / ".env").open("a") as fh:
        fh.write("export VAULT_CACERT=.tmp/ca.pem\n")
    values, _ = evaluated(repo, run(repo).stdout)
    assert values["VAULT_CACERT"] == f"{work}/.tmp/ca.pem"


def test_claude_gets_only_the_local_env(repo):
    """Finding 5: HCP_* and VAULT_* from the shell are dropped even when .env doesn't name them."""
    _, _, tmp = repo
    result = run(repo, script="local_claude.sh", HCP_CLIENT_ID="fake-id", HCP_CLIENT_SECRET="fake-secret", VAULT_LICENSE="lic", VAULT_SOMETHING="x", VAULT_TOKEN="root")
    assert result.returncode == 0, result.stderr
    claude_env = dict(line.split("=", 1) for line in (tmp / "claude-env").read_text().splitlines() if "=" in line)
    assert not {k for k in claude_env if k.startswith("HCP_")}
    assert "VAULT_LICENSE" not in claude_env and "VAULT_SOMETHING" not in claude_env
    assert claude_env["VAULT_TOKEN"] == FAKE_TOKEN
    assert claude_env["VAULT_ADDR"] == "https://primary.example:8210"
    assert claude_env["VAULT_OPS_ENV"] == "audit"


def test_claude_missing_binary_and_override(repo):
    """Finding 9: a clear error when claude isn't an executable on PATH; CLAUDE_BIN points at it."""
    _, env, tmp = repo
    missing = run(repo, script="local_claude.sh", CLAUDE_BIN="no-such-claude")
    assert missing.returncode == 1
    assert "CLAUDE_BIN" in missing.stderr
    custom = tmp / "my-claude"
    shutil.copy(tmp / "bin" / "claude", custom)
    assert run(repo, script="local_claude.sh", CLAUDE_BIN=str(custom)).returncode == 0
    assert (tmp / "claude-env").exists()


def test_claude_does_not_start_when_the_token_check_fails(repo):
    _, _, tmp = repo
    result = run(repo, script="local_claude.sh", FAKE_VAULT_MODE="invalid")
    assert result.returncode == 1
    assert not (tmp / "claude-env").exists()


def test_hcp_token_check_uses_the_shared_check(repo, tmp_path):
    """Finding 10: hcp_token_check.sh reuses token_lib.sh, so it also accepts a token without expiry."""
    work, _, _ = repo
    tf = tmp_path / "bin" / "terraform"
    tf.write_text("#!/bin/bash\necho https://hcp.example:8200\n")
    tf.chmod(0o755)
    (work / ".tmp" / "admin-token-hcp").write_text(FAKE_TOKEN)
    result = run(repo, script="hcp_token_check.sh", FAKE_VAULT_MODE="never", VAULT_SKIP_VERIFY="true")
    assert result.returncode == 0, result.stderr
    lookup = vault_calls(repo, "token")[-1]
    assert lookup["VAULT_ADDR"] == "https://hcp.example:8200"
    assert lookup["VAULT_NAMESPACE"] == "admin"
    assert "VAULT_SKIP_VERIFY" not in lookup
    assert json.dumps(lookup).count(FAKE_TOKEN) == 1  # only VAULT_TOKEN, nothing printed
    assert FAKE_TOKEN not in result.stdout + result.stderr
