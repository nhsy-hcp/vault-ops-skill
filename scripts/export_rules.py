#!/usr/bin/env python3
"""Write skills/vault-ops/references/rules.json from vault_ops.RULES (run via `task rules:export`)."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/vault-ops/scripts"))

import vault_ops  # noqa: E402

RULES_JSON = ROOT / "skills/vault-ops/references/rules.json"


def render() -> str:
    return json.dumps(vault_ops.rules_catalogue(), indent=2) + "\n"


if __name__ == "__main__":
    RULES_JSON.write_text(render())
    print(RULES_JSON.relative_to(ROOT))
