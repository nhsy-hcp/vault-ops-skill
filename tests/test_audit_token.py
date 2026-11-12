"""Regression tests for scripts/audit_token.sh, including IF_MISSING=1 (run by task up).

A fake `vault` on PATH logs each subcommand; FAKE_VAULT_MODE picks the token lookup answer.
"""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
OLD_TOKEN = "hvs.fake-existing-token"  # not a real token
NEW_TOKEN = "hvs.fake-minted-token"  # not a real token

pytestmark = pytest.mark.skipif(shutil.which("jq") is None or not Path("/bin/bash").exists(), reason="needs bash and jq")

FAKE_VAULT = f"""#!/bin/bash
echo "$1 $2" >> "$FAKE_VAULT_LOG"
mode="${{FAKE_VAULT_MODE:-ok}}"
case "$1 $2" in
  "token lookup")
    case "$mode" in
      ok) echo '{{"data":{{"ttl":7260,"expire_time":"2099-01-01T00:00:00Z"}}}}' ;;
      expired) echo '{{"data":{{"ttl":0,"expire_time":"2000-01-01T00:00:00Z"}}}}' ;;
      *) echo "Error looking up token: permission denied" >&2; exit 2 ;;
    esac ;;
  "token create") echo "{NEW_TOKEN}" ;;
esac
exit 0
"""


@pytest.fixture
def repo(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    vault = bindir / "vault"
    vault.write_text(FAKE_VAULT)
    vault.chmod(vault.stat().st_mode | stat.S_IXUSR)
    work = tmp_path / "work"
    (work / ".tmp").mkdir(parents=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("VAULT_")}
    env.update(PATH=f"{bindir}:{env['PATH']}", FAKE_VAULT_LOG=str(tmp_path / "vault.log"), VAULT_ADDR="https://primary.example:8210", VAULT_TOKEN="root")
    return work, env, tmp_path / "vault.log"


def run(repo, **extra_env):
    work, env, _ = repo
    return subprocess.run(["/bin/bash", str(SCRIPTS / "audit_token.sh")], cwd=work, env={**env, **extra_env}, capture_output=True, text=True, timeout=30)


def calls(repo):
    log = repo[2]
    return log.read_text().splitlines() if log.exists() else []


def token_file(repo):
    return repo[0] / ".tmp" / "audit-token"


def assert_minted(repo, result):
    assert result.returncode == 0, result.stderr
    assert "policy write" in calls(repo)
    assert "token create" in calls(repo)
    assert token_file(repo).read_text().strip() == NEW_TOKEN
    assert stat.S_IMODE(token_file(repo).stat().st_mode) == 0o600


def test_if_missing_keeps_a_valid_token(repo):
    token_file(repo).write_text(OLD_TOKEN)
    result = run(repo, IF_MISSING="1")
    assert result.returncode == 0, result.stderr
    assert calls(repo) == ["token lookup"]
    assert token_file(repo).read_text() == OLD_TOKEN
    assert "token ok" in result.stderr
    assert OLD_TOKEN not in result.stdout + result.stderr


def test_if_missing_mints_when_file_is_absent(repo):
    assert_minted(repo, run(repo, IF_MISSING="1"))


@pytest.mark.parametrize("mode", ["expired", "invalid"])
def test_if_missing_replaces_an_unusable_token(repo, mode):
    token_file(repo).write_text(OLD_TOKEN)
    result = run(repo, IF_MISSING="1", FAKE_VAULT_MODE=mode)
    assert_minted(repo, result)
    assert "permission denied" not in result.stderr  # Vault's error text is never shown


def test_task_up_mints_the_policies_token(repo):
    """task up runs IF_MISSING=1 POLICY_READER=1: all three read-only policies are written."""
    assert_minted(repo, run(repo, IF_MISSING="1", POLICY_READER="1"))
    assert calls(repo).count("policy write") == 3


def test_if_missing_skips_in_a_task_env_shell(repo):
    result = run(repo, IF_MISSING="1", VAULT_OPS_ENV="audit")
    assert result.returncode == 0
    assert "skipped" in result.stderr
    assert calls(repo) == []
    assert not token_file(repo).exists()


def test_default_mode_always_mints(repo):
    """task token:audit still replaces a valid token."""
    token_file(repo).write_text(OLD_TOKEN)
    assert_minted(repo, run(repo))
    assert "token lookup" not in calls(repo)
